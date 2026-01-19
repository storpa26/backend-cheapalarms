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
use function wp_get_current_user;
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
        // FIX: Priority 1 ensures JWT auth runs BEFORE WordPress core cookie auth (priority 10)
        // This prevents cookie auth from overriding JWT tokens and causing intermittent 401 errors
        add_filter('determine_current_user', [$this, 'determineCurrentUser'], 1);
        add_filter('rest_authentication_errors', [$this, 'restAuthenticationErrors']);
    }

    public function ensureConfigured(): void
    {
        if (!$this->config->isConfigured()) {
            wp_die(__('CheapAlarms plugin is not configured. Please set CA_GHL_TOKEN and CA_LOCATION_ID.', 'cheapalarms'), '', 500);
        }
    }

    /**
     * Ensure user is loaded before capability checks.
     * This fixes JWT authentication timing issues.
     */
    public function ensureUserLoaded(): void
    {
        global $current_user;
        $current_user = null;
        wp_get_current_user();
    }

    /**
     * Directly authenticate via JWT token and return user ID
     * This bypasses the filter system to ensure the user is authenticated
     */
    public function authenticateViaJwt(): ?int
    {
        $token = $this->getBearerToken();
        if (!$token) {
            return null;
        }

        $decoded = $this->decodeJwt($token);
        if (is_wp_error($decoded)) {
            return null;
        }

        $userIdFromToken = (int) ($decoded['sub'] ?? 0);
        $user = get_user_by('id', $userIdFromToken);
        if (!$user instanceof WP_User) {
            return null;
        }

        return $user->ID;
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

    /**
     * Enforce rate limiting with user-based and IP-based tracking
     * SECURITY: Uses both user ID (if authenticated) and IP address to prevent bypass
     * 
     * @param string $key Rate limit key (e.g., 'auth_token', 'password_reset')
     * @param int $limit Maximum requests per window
     * @param int $windowSeconds Time window in seconds
     * @return bool|WP_Error
     */
    public function enforceRateLimit(string $key, int $limit = 5, int $windowSeconds = 300): bool|WP_Error
    {
        // Get real IP address with proxy support (Cloudflare, etc.)
        $ip = $this->getRealIpAddress();
        
        // SECURITY: Use user ID if authenticated, otherwise IP address
        // This prevents IP rotation attacks and reduces false positives from shared IPs
        $userId = get_current_user_id();
        $identifier = $userId > 0 ? "user_{$userId}" : "ip_{$ip}";
        
        $bucket = 'ca_rate_' . md5($key . $identifier);
        $record = get_transient($bucket);
        $now    = time();

        if (!is_array($record) || ($record['reset'] ?? 0) < $now) {
            $record = [
                'count' => 0,
                'reset' => $now + $windowSeconds,
                'ip_source' => $this->getIpSource(), // For debugging
            ];
        }

        if ($record['count'] >= $limit) {
            // Log rate limit violation for debugging
            if (function_exists('error_log')) {
                error_log(sprintf(
                    '[CheapAlarms] Rate limit exceeded: key=%s, identifier=%s, ip=%s, ip_source=%s',
                    $key,
                    $identifier,
                    $ip,
                    $record['ip_source'] ?? 'unknown'
                ));
            }

            $error = new WP_Error('rate_limited', __('Too many attempts. Please slow down.', 'cheapalarms'), [
                'status'     => 429,
                'retry_after'=> $record['reset'] - $now,
                'rate_limit' => [
                    'limit' => $limit,
                    'remaining' => 0,
                    'reset' => $record['reset'],
                ],
            ]);
            
            return $error;
        }

        $remaining = max(0, $limit - $record['count'] - 1);
        
        // Store rate limit info for header injection (via filter)
        $record['rate_limit_info'] = [
            'limit' => $limit,
            'remaining' => $remaining,
            'reset' => $record['reset'],
        ];
        
        $record['count']++;
        set_transient($bucket, $record, $windowSeconds);

        // Store rate limit info in error data for header injection
        return true;
    }

    /**
     * Get real IP address with proxy/Cloudflare support
     * 
     * @return string
     */
    private function getRealIpAddress(): string
    {
        // Check Cloudflare headers first (most reliable)
        $cfIp = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['CF-Connecting-IP'] ?? null;
        if ($cfIp && $this->isValidIp($cfIp)) {
            return $cfIp;
        }

        // Check standard proxy headers
        $forwardedFor = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['X-Forwarded-For'] ?? null;
        if ($forwardedFor) {
            // X-Forwarded-For can contain multiple IPs (comma-separated)
            // Use the first one (original client IP)
            $ips = array_map('trim', explode(',', $forwardedFor));
            foreach ($ips as $ip) {
                if ($this->isValidIp($ip)) {
                    return $ip;
                }
            }
        }

        // Check X-Real-IP header
        $realIp = $_SERVER['HTTP_X_REAL_IP'] ?? $_SERVER['X-Real-IP'] ?? null;
        if ($realIp && $this->isValidIp($realIp)) {
            return $realIp;
        }

        // Fallback to REMOTE_ADDR
        $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        return $this->isValidIp($remoteAddr) ? $remoteAddr : 'unknown';
    }

    /**
     * Validate IP address format
     * 
     * @param string $ip
     * @return bool
     */
    private function isValidIp(string $ip): bool
    {
        // Filter out invalid IPs
        $ip = trim($ip);
        if (empty($ip) || $ip === 'unknown') {
            return false;
        }

        // In development, allow private ranges (localhost, 127.0.0.1, etc.)
        $isDevelopment = defined('WP_DEBUG') && WP_DEBUG;
        $flags = FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6;
        
        if (!$isDevelopment) {
            // In production, reject private and reserved ranges
            $flags |= FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
        }

        // Validate IP format (IPv4 or IPv6)
        return filter_var($ip, FILTER_VALIDATE_IP, $flags) !== false;
    }

    /**
     * Get IP source for debugging
     * 
     * @return string
     */
    private function getIpSource(): string
    {
        if (isset($_SERVER['HTTP_CF_CONNECTING_IP']) || isset($_SERVER['CF-Connecting-IP'])) {
            return 'cloudflare';
        }
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) || isset($_SERVER['X-Forwarded-For'])) {
            return 'x-forwarded-for';
        }
        if (isset($_SERVER['HTTP_X_REAL_IP']) || isset($_SERVER['X-Real-IP'])) {
            return 'x-real-ip';
        }
        return 'remote-addr';
    }

    public function determineCurrentUser($userId)
    {
        // Check if this is a REST API request (either by constant or by request URI)
        $isRestRequest = (defined('REST_REQUEST') && REST_REQUEST) 
            || (isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], '/wp-json/') !== false);
        
        // For non-REST requests, return early (normal WordPress behavior)
        if (!$isRestRequest) {
            return $userId;
        }

        // Always check for JWT token in REST requests, even if $userId is already set
        // This ensures server-to-server requests from Next.js get authenticated correctly
        $token = $this->getBearerToken();
        if (!$token) {
            return $userId; // No JWT token, return existing userId (might be from cookie auth)
        }

        // JWT token exists - verify it and use it (overrides any existing userId)
        $decoded = $this->decodeJwt($token);
        if (is_wp_error($decoded)) {
            $this->lastAuthError = $decoded;
            return 0; // JWT invalid, return 0 to force re-authentication
        }

        $userIdFromToken = (int) ($decoded['sub'] ?? 0);
        $user = get_user_by('id', $userIdFromToken);
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

        // FIX: Check if JWT authentication succeeded
        // If a JWT token exists and user is logged in, return true to signal success
        // This prevents WordPress core's rest_cookie_check_errors from running
        // (which requires nonces for cookie-based auth)
        $token = $this->getBearerToken();
        if ($token) {
            // JWT token exists - check if authentication succeeded
            $this->ensureUserLoaded(); // Trigger determineCurrentUser if needed
            $user = wp_get_current_user();
            if ($user && $user->ID > 0) {
                // JWT authentication succeeded - return true to skip cookie auth
                return true;
            }
        }

        return $result;
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function encodeJwt(array $payload): string
    {
        $header  = ['alg' => 'HS256', 'typ' => 'JWT'];
        
        // Encode header and validate
        $jsonHeader = wp_json_encode($header);
        if ($jsonHeader === false) {
            if (function_exists('error_log')) {
                error_log('[CheapAlarms] Failed to encode JWT header JSON: ' . json_last_error_msg());
            }
            throw new \RuntimeException('Failed to encode JWT header: ' . json_last_error_msg());
        }
        
        // Encode payload and validate
        $jsonPayload = wp_json_encode($payload);
        if ($jsonPayload === false) {
            if (function_exists('error_log')) {
                error_log('[CheapAlarms] Failed to encode JWT payload JSON: ' . json_last_error_msg());
            }
            throw new \RuntimeException('Failed to encode JWT payload: ' . json_last_error_msg());
        }
        
        $segments = [
            $this->base64UrlEncode($jsonHeader),
            $this->base64UrlEncode($jsonPayload),
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
        
        // Check $_COOKIE first (normal browser requests)
        if (isset($_COOKIE[$cookieName]) && !empty($_COOKIE[$cookieName])) {
            return $_COOKIE[$cookieName];
        }
        
        // FIX: Also check Cookie header for server-to-server requests (e.g., from getAuthContext)
        // When Next.js makes server-side fetch, cookies are in HTTP_COOKIE header, not $_COOKIE
        $cookieHeader = $_SERVER['HTTP_COOKIE'] ?? null;
        if ($cookieHeader) {
            // Parse cookies from header (format: "name1=value1; name2=value2")
            $cookies = [];
            $pairs = explode(';', $cookieHeader);
            foreach ($pairs as $pair) {
                $pair = trim($pair);
                if (empty($pair)) {
                    continue;
                }
                $parts = explode('=', $pair, 2);
                if (count($parts) === 2) {
                    // FIX: URL decode cookie value (cookies in headers may be URL-encoded)
                    // Use different variable name to avoid overwriting $cookieName ('ca_jwt')
                    $parsedCookieName = trim($parts[0]);
                    $cookieValue = urldecode(trim($parts[1]));
                    $cookies[$parsedCookieName] = $cookieValue;
                }
            }
            // Check for 'ca_jwt' cookie (using original $cookieName variable)
            if (isset($cookies[$cookieName]) && !empty($cookies[$cookieName])) {
                return $cookies[$cookieName];
            }
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

