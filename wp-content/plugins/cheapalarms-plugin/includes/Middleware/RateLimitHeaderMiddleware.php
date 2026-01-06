<?php

namespace CheapAlarms\Plugin\Middleware;

use WP_REST_Request;
use WP_REST_Response;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Rate Limit Header Middleware
 * 
 * Adds standard rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset)
 * to all REST API responses for endpoints that use rate limiting
 */
class RateLimitHeaderMiddleware
{
    public function __construct()
    {
        // No dependencies needed - reads directly from transients
    }

    /**
     * Add rate limit headers to REST API responses
     * 
     * This should be called as a filter on rest_pre_serve_request
     * 
     * @param bool $served
     * @param WP_REST_Response|mixed $result
     * @param WP_REST_Request $request
     * @param mixed $server
     * @return bool
     */
    public function addRateLimitHeaders($served, $result, $request, $server)
    {
        // Only add headers for successful responses (not errors)
        if (!($result instanceof WP_REST_Response) || $result->get_status() >= 400) {
            return $served;
        }

        // Determine rate limit based on endpoint type
        $route = $request->get_route();
        $method = $request->get_method();
        
        // Skip if already has rate limit headers (from error response)
        $headers = $result->get_headers();
        if (isset($headers['X-RateLimit-Limit'])) {
            return $served;
        }

        // Get rate limit configuration for this route
        $config = $this->getRateLimitConfigForRoute($route, $method);
        if (!$config) {
            return $served; // No rate limiting for this endpoint
        }

        // Get current rate limit status using the correct key
        $rateLimitInfo = $this->getCurrentRateLimitInfo($request, $config);
        if ($rateLimitInfo) {
            $result->header('X-RateLimit-Limit', (string) $rateLimitInfo['limit']);
            $result->header('X-RateLimit-Remaining', (string) $rateLimitInfo['remaining']);
            $result->header('X-RateLimit-Reset', (string) $rateLimitInfo['reset']);
        }

        return $served;
    }

    /**
     * Get rate limit key for a specific route
     * 
     * Maps routes to the rate limit keys used by Authenticator::enforceRateLimit()
     * 
     * @param string $route
     * @param string $method
     * @return array{key: string, limit: int, window: int}|null
     */
    private function getRateLimitConfigForRoute(string $route, string $method): ?array
    {
        // Map routes to rate limit keys and configs used by Authenticator
        $routeMap = [
            '/ca/v1/quote-request' => [
                'key' => 'quote_request_public',
                'limit' => 100,
                'window' => 900, // 15 minutes
            ],
            '/ca/v1/auth/token' => [
                'key' => 'auth_token',
                'limit' => 5,
                'window' => 300, // 5 minutes
            ],
            '/ca/v1/auth/password-reset' => [
                'key' => 'password_reset',
                'limit' => 5,
                'window' => 300, // 5 minutes (matches controller)
            ],
            '/ca/v1/auth/validate-reset-key' => [
                'key' => 'validate_reset_key',
                'limit' => 10,
                'window' => 300, // 5 minutes
            ],
            '/ca/v1/auth/check-account' => [
                'key' => 'check_account',
                'limit' => 10,
                'window' => 300, // 5 minutes
            ],
            '/ca/v1/auth/reset-password' => [
                'key' => 'reset_password',
                'limit' => 5,
                'window' => 300, // 5 minutes
            ],
            // Public endpoints - generic API rate limit
            '/ca/v1/estimate' => [
                'key' => 'api_request',
                'limit' => 100,
                'window' => 900,
            ],
            '/ca/v1/upload' => [
                'key' => 'api_request',
                'limit' => 50,
                'window' => 900,
            ],
            // Authenticated endpoints - per-user limits
            '/ca/v1/admin' => [
                'key' => 'api_request',
                'limit' => 1000,
                'window' => 900,
            ],
            '/ca/v1/portal' => [
                'key' => 'api_request',
                'limit' => 1000,
                'window' => 900,
            ],
        ];
        
        foreach ($routeMap as $routePrefix => $config) {
            if (str_starts_with($route, $routePrefix)) {
                return $config;
            }
        }

        // No rate limiting for other endpoints
        return null;
    }

    /**
     * Get current rate limit information for the request
     * 
     * Reads from the same transient bucket used by Authenticator::enforceRateLimit()
     * 
     * @param \WP_REST_Request $request
     * @param array{key: string, limit: int, window: int} $config
     * @return array{limit: int, remaining: int, reset: int}|null
     */
    private function getCurrentRateLimitInfo(\WP_REST_Request $request, array $config): ?array
    {
        $key = $config['key'];
        $limit = $config['limit'];
        $window = $config['window'];
        
        // Get rate limit bucket using same logic as Authenticator
        $ip = $this->getRealIpAddress();
        $userId = get_current_user_id();
        $identifier = $userId > 0 ? "user_{$userId}" : "ip_{$ip}";
        
        // Use same bucket naming as Authenticator::enforceRateLimit()
        $bucket = 'ca_rate_' . md5($key . $identifier);
        $record = get_transient($bucket);
        
        $now = time();
        
        if (!is_array($record) || ($record['reset'] ?? 0) < $now) {
            // No rate limit record yet or expired - assume full limit available
            return [
                'limit' => $limit,
                'remaining' => $limit,
                'reset' => $now + $window,
            ];
        }

        // Use rate_limit_info if available (set by Authenticator), otherwise calculate
        if (isset($record['rate_limit_info']) && is_array($record['rate_limit_info'])) {
            return $record['rate_limit_info'];
        }

        // Fallback: calculate from record
        $reset = $record['reset'] ?? ($now + $window);
        $count = $record['count'] ?? 0;
        // Account for current request (if Authenticator hasn't updated yet)
        $remaining = max(0, $limit - $count - 1);

        return [
            'limit' => $limit,
            'remaining' => $remaining,
            'reset' => $reset,
        ];
    }

    /**
     * Get real IP address (same logic as Authenticator)
     * 
     * @return string
     */
    private function getRealIpAddress(): string
    {
        // Check Cloudflare headers first
        $cfIp = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['CF-Connecting-IP'] ?? null;
        if ($cfIp && $this->isValidIp($cfIp)) {
            return $cfIp;
        }

        // Check standard proxy headers
        $forwardedFor = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['X-Forwarded-For'] ?? null;
        if ($forwardedFor) {
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
        $ip = trim($ip);
        if (empty($ip) || $ip === 'unknown') {
            return false;
        }

        $isDevelopment = defined('WP_DEBUG') && WP_DEBUG;
        $flags = FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6;
        
        if (!$isDevelopment) {
            $flags |= FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
        }

        return filter_var($ip, FILTER_VALIDATE_IP, $flags) !== false;
    }
}

