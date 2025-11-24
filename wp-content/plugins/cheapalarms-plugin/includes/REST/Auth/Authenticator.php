<?php

namespace CheapAlarms\Plugin\REST\Auth;

use CheapAlarms\Plugin\Config\Config;
use WP_Error;
use WP_REST_Request;
use WP_User;

use function add_filter;
use function array_filter;
use function array_keys;
use function array_values;
use function current_user_can;
use function defined;
use function get_transient;
use function get_user_by;
use function hash_equals;
use function json_decode;
use function set_transient;
use function site_url;
use function str_starts_with;
use function time;
use function wp_die;
use function wp_json_encode;
use function wp_set_current_user;
use function wp_verify_nonce;

class Authenticator
{
    private ?WP_Error $lastAuthError = null;

    public function __construct(private Config $config)
    {
    }

    public function boot(): void
    {
        add_filter('determine_current_user', [$this, 'determineCurrentUser'], 15);
        add_filter('rest_authentication_errors', [$this, 'restAuthenticationErrors']);
    }

    public function ensureConfigured(): void
    {
        if (!$this->config->isConfigured()) {
            wp_die(__('CheapAlarms plugin is not configured. Please set CA_GHL_TOKEN and CA_LOCATION_ID.', 'cheapalarms'), '', 500);
        }
    }

    public function requireCapability(string $capability): bool|WP_Error
    {
        if (current_user_can($capability) || current_user_can('manage_options')) {
            return true;
        }

        return new WP_Error('forbidden', __('Insufficient privileges.', 'cheapalarms'), ['status' => 403]);
    }

    public function requireAdmin(): bool|WP_Error
    {
        return $this->requireCapability('ca_manage_portal');
    }

    public function publicAllowed(): bool
    {
        return true;
    }

    public function validateNonce(WP_REST_Request $request, string $action = 'ca_portal'): bool|WP_Error
    {
        $nonce = $request->get_header('X-WP-Nonce') ?: $request->get_param('_wpnonce');
        if ($nonce && wp_verify_nonce($nonce, $action)) {
            return true;
        }
        return new WP_Error('invalid_nonce', __('Invalid security token.', 'cheapalarms'), ['status' => 403]);
    }

    /**
     * @param array<mixed> $payload
     */
    public function issueToken(WP_User $user): array
    {
        $issuedAt = time();
        $ttl      = $this->config->getJwtTtlSeconds();
        $expires  = $issuedAt + $ttl;
        $caps = array_values(array_filter(array_keys($user->allcaps ?? []), static fn ($cap) => str_starts_with($cap, 'ca_')));

        $payload  = [
            'iss'        => site_url(),
            'sub'        => (string) $user->ID,
            'iat'        => $issuedAt,
            'exp'        => $expires,
            'email'      => $user->user_email,
            'display'    => $user->display_name,
            'roles'      => array_values($user->roles ?? []),
            'capabilities' => $caps,
        ];

        return [
            'token'       => $this->encodeJwt($payload),
            'expires_at'  => $expires,
            'expires_in'  => $ttl,
            'user'        => [
                'id'          => (int) $user->ID,
                'email'       => $user->user_email,
                'displayName' => $user->display_name,
                'roles'       => array_values($user->roles ?? []),
                'capabilities'=> $caps,
            ],
        ];
    }

    public function enforceRateLimit(string $key, int $limit = 5, int $windowSeconds = 300): bool|WP_Error
    {
        $origin = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $bucket = 'ca_rate_' . md5($key . $origin);
        $record = get_transient($bucket);
        $now    = time();

        if (!is_array($record) || ($record['reset'] ?? 0) < $now) {
            $record = [
                'count' => 0,
                'reset' => $now + $windowSeconds,
            ];
        }

        if ($record['count'] >= $limit) {
            return new WP_Error('rate_limited', __('Too many attempts. Please slow down.', 'cheapalarms'), [
                'status'     => 429,
                'retry_after'=> $record['reset'] - $now,
            ]);
        }

        $record['count']++;
        set_transient($bucket, $record, $windowSeconds);

        return true;
    }

    public function determineCurrentUser($userId)
    {
        if ($userId || !defined('REST_REQUEST') || !REST_REQUEST) {
            return $userId;
        }

        $token = $this->getBearerToken();
        if (!$token) {
            return $userId;
        }

        $decoded = $this->decodeJwt($token);
        if (is_wp_error($decoded)) {
            $this->lastAuthError = $decoded;
            return 0;
        }

        $user = get_user_by('id', (int) ($decoded['sub'] ?? 0));
        if (!$user instanceof WP_User) {
            $this->lastAuthError = new WP_Error('invalid_token', __('User no longer exists.', 'cheapalarms'), ['status' => 401]);
            return 0;
        }

        wp_set_current_user($user->ID);
        return $user->ID;
    }

    public function restAuthenticationErrors($result)
    {
        if (!empty($result)) {
            return $result;
        }

        if ($this->lastAuthError instanceof WP_Error) {
            $error = $this->lastAuthError;
            $this->lastAuthError = null;
            return $error;
        }

        return $result;
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function encodeJwt(array $payload): string
    {
        $header  = ['alg' => 'HS256', 'typ' => 'JWT'];
        $segments = [
            $this->base64UrlEncode(wp_json_encode($header)),
            $this->base64UrlEncode(wp_json_encode($payload)),
        ];
        $signature = hash_hmac('sha256', implode('.', $segments), $this->config->getJwtSecret(), true);
        $segments[] = $this->base64UrlEncode($signature);
        return implode('.', $segments);
    }

    /**
     * @return array<string, mixed>|WP_Error
     */
    private function decodeJwt(string $token)
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return new WP_Error('invalid_token', __('Malformed token.', 'cheapalarms'), ['status' => 401]);
        }

        [$headerB64, $payloadB64, $sigB64] = $parts;
        $signature   = $this->base64UrlDecode($sigB64);
        $expected    = hash_hmac('sha256', $headerB64 . '.' . $payloadB64, $this->config->getJwtSecret(), true);

        if (!hash_equals($expected, $signature)) {
            return new WP_Error('invalid_token', __('Token signature mismatch.', 'cheapalarms'), ['status' => 401]);
        }

        $payloadJson = $this->base64UrlDecode($payloadB64);
        $payload     = json_decode($payloadJson, true);
        if (!is_array($payload)) {
            return new WP_Error('invalid_token', __('Unable to parse token payload.', 'cheapalarms'), ['status' => 401]);
        }

        $now = time();
        if (!empty($payload['exp']) && $now > (int) $payload['exp']) {
            return new WP_Error('token_expired', __('Token expired.', 'cheapalarms'), ['status' => 401]);
        }

        if (!empty($payload['nbf']) && $now < (int) $payload['nbf']) {
            return new WP_Error('invalid_token', __('Token not yet valid.', 'cheapalarms'), ['status' => 401]);
        }

        return $payload;
    }

    private function getBearerToken(): ?string
    {
        // First, check Authorization header
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['Authorization'] ?? null;
        if (!$authHeader && function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? null;
        }

        if ($authHeader && stripos($authHeader, 'Bearer ') === 0) {
            return trim(substr($authHeader, 7));
        }

        // Fallback: check cookies for JWT token (for httpOnly cookies)
        $cookieName = 'ca_jwt';
        if (isset($_COOKIE[$cookieName]) && !empty($_COOKIE[$cookieName])) {
            return $_COOKIE[$cookieName];
        }

        return null;
    }

    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $value): string
    {
        $remainder = strlen($value) % 4;
        if ($remainder) {
            $value .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($value, '-_', '+/')) ?: '';
    }
}

