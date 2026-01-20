<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\GhlClient;
use CheapAlarms\Plugin\Config\Config;
use WP_REST_Request;
use WP_REST_Response;
use WP_Error;

use function get_transient;
use function set_transient;
use function wp_get_current_user;
use function wp_set_current_user;
use function current_user_can;
use function defined;
use function constant;

if (!defined('ABSPATH')) {
    exit;
}

class HealthController implements ControllerInterface
{
    private Authenticator $auth;
    private GhlClient $ghlClient;
    private Config $config;
    private const GHL_CHECK_CACHE_KEY = 'ca_health_ghl_check';
    private const GHL_CHECK_CACHE_TTL = 60; // 60 seconds cache

    public function __construct(private Container $container)
    {
        $this->auth = $this->container->get(Authenticator::class);
        $this->ghlClient = $this->container->get(GhlClient::class);
        $this->config = $this->container->get(Config::class);
    }

    public function register(): void
    {
        // Public shallow health check (minimal info)
        register_rest_route('ca/v1', '/health', [
            'methods'             => 'GET',
            'permission_callback' => '__return_true', // Public endpoint
            'callback'            => [$this, 'shallowCheck'],
        ]);

        // Detailed health check (requires auth or secret header)
        register_rest_route('ca/v1', '/health/detailed', [
            'methods'             => 'GET',
            'permission_callback' => '__return_true', // Check auth in callback
            'callback'            => [$this, 'deepCheck'],
        ]);
    }

    /**
     * Shallow health check - public endpoint with minimal info
     * No external API calls to prevent monitoring load
     */
    public function shallowCheck(WP_REST_Request $request): WP_REST_Response
    {
        $status = 'ok';
        
        // Check database connectivity
        global $wpdb;
        $dbCheck = $wpdb->get_var("SELECT 1");
        if ($dbCheck !== '1') {
            $status = 'degraded';
        }
        
        // Check critical WordPress functions
        $wpCheck = function_exists('wp_get_current_user') && function_exists('get_option');
        if (!$wpCheck) {
            $status = 'degraded';
        }

        // Return minimal response - just status code and minimal body
        $httpStatus = $status === 'ok' ? 200 : 503;
        $response = new WP_REST_Response(['status' => $status], $httpStatus);
        
        // Add cache control to prevent excessive checks
        $response->header('Cache-Control', 'public, max-age=30');
        
        $this->addSecurityHeaders($response);
        return $response;
    }

    /**
     * Deep health check - requires authentication or secret header
     * Includes GHL API check with caching
     */
    public function deepCheck(WP_REST_Request $request): WP_REST_Response
    {
        // Check authentication: secret header OR admin user
        $hasSecret = $this->checkSecretHeader($request);
        $hasAuth = $this->checkAdminAuth();

        if (!$hasSecret && !$hasAuth) {
            return new WP_REST_Response([
                'ok' => false,
                'error' => 'Unauthorized. Requires secret header or admin authentication.',
                'code' => 'unauthorized',
            ], 401);
        }

        $status = 'healthy';
        $checks = [];
        $cached = false;

        // Check database connectivity
        global $wpdb;
        $dbCheck = $wpdb->get_var("SELECT 1");
        $checks['database'] = [
            'status' => $dbCheck === '1' ? 'ok' : 'error',
            'message' => $dbCheck === '1' ? 'Database connection successful' : 'Database connection failed',
        ];
        if ($checks['database']['status'] !== 'ok') {
            $status = 'unhealthy';
        }

        // Check critical WordPress functions
        $wpCheck = function_exists('wp_get_current_user') && function_exists('get_option');
        $checks['wordpress'] = [
            'status' => $wpCheck ? 'ok' : 'error',
            'message' => $wpCheck ? 'WordPress functions available' : 'WordPress functions unavailable',
        ];
        if ($checks['wordpress']['status'] !== 'ok') {
            $status = 'unhealthy';
        }

        // Check GHL API connectivity (with caching)
        $ghlCheck = $this->checkGhlApi($cached);
        $checks['ghl_api'] = $ghlCheck;
        if ($ghlCheck['status'] === 'error') {
            $status = $status === 'healthy' ? 'degraded' : 'unhealthy';
        } elseif ($ghlCheck['status'] === 'degraded') {
            $status = $status === 'healthy' ? 'degraded' : $status;
        }

        $response = new WP_REST_Response([
            'status' => $status,
            'checks' => $checks,
            'timestamp' => gmdate('c'),
            'cached' => $cached,
        ], 200);

        $this->addSecurityHeaders($response);
        return $response;
    }

    /**
     * Check GHL API connectivity with caching
     * 
     * @param bool $cached Output parameter indicating if cached result was used
     * @return array<string, mixed>
     */
    private function checkGhlApi(bool &$cached): array
    {
        // Check cache first
        $cachedResult = get_transient(self::GHL_CHECK_CACHE_KEY);
        if ($cachedResult !== false && is_array($cachedResult)) {
            $cached = true;
            return $cachedResult;
        }

        $cached = false;

        // Perform actual GHL API check
        $token = $this->config->getGhlToken();
        $locationId = $this->config->getLocationId();

        if (empty($token) || empty($locationId)) {
            $result = [
                'status' => 'error',
                'message' => 'GHL credentials not configured',
            ];
            // Cache error result for shorter time (30 seconds)
            set_transient(self::GHL_CHECK_CACHE_KEY, $result, 30);
            return $result;
        }

        // Make a lightweight API call (check specific location endpoint)
        // Use a short timeout to avoid blocking
        $response = $this->ghlClient->get('/locations/' . rawurlencode($locationId), [], 5, $locationId, 0);

        if (is_wp_error($response)) {
            $result = [
                'status' => 'degraded',
                'message' => 'GHL API check failed: ' . $response->get_error_message(),
            ];
        } else {
            $result = [
                'status' => 'ok',
                'message' => 'GHL API connection successful',
            ];
        }

        // Cache result for 60 seconds
        set_transient(self::GHL_CHECK_CACHE_KEY, $result, self::GHL_CHECK_CACHE_TTL);

        return $result;
    }

    /**
     * Check if request has valid secret header
     */
    private function checkSecretHeader(WP_REST_Request $request): bool
    {
        $secret = $request->get_header('X-Health-Check-Secret');
        if (empty($secret)) {
            return false;
        }

        // Get secret from wp-config.php or environment
        $expectedSecret = defined('CA_HEALTH_CHECK_SECRET') 
            ? constant('CA_HEALTH_CHECK_SECRET') 
            : getenv('CA_HEALTH_CHECK_SECRET');

        if (empty($expectedSecret)) {
            return false;
        }

        return hash_equals($expectedSecret, $secret);
    }

    /**
     * Check if current user is authenticated admin
     * Includes JWT authentication workaround for timing issues
     */
    private function checkAdminAuth(): bool
    {
        // FIX: Use direct JWT authentication instead of manual token checking
        $userId = $this->auth->authenticateViaJwt();
        if ($userId && $userId > 0) {
            wp_set_current_user($userId);
            $user = wp_get_current_user();
        } else {
            $user = wp_get_current_user();
        }
        
        if (!$user || !$user->ID) {
            return false;
        }

        return current_user_can('ca_manage_portal');
    }

    /**
     * Add security headers to response
     */
    private function addSecurityHeaders(WP_REST_Response $response): void
    {
        $response->header('X-Content-Type-Options', 'nosniff');
        $response->header('X-XSS-Protection', '1; mode=block');
        $response->header('X-Frame-Options', 'DENY');
        $response->header('Referrer-Policy', 'strict-origin-when-cross-origin');
    }
}

