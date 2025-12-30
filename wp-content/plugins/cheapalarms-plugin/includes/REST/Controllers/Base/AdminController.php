<?php

namespace CheapAlarms\Plugin\REST\Controllers\Base;

use CheapAlarms\Plugin\REST\Controllers\ControllerInterface;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\Shared\LocationResolver;
use CheapAlarms\Plugin\Services\Shared\PortalMetaRepository;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

use function sanitize_text_field;
use function wp_get_current_user;

/**
 * Base controller for admin endpoints with shared functionality.
 */
abstract class AdminController implements ControllerInterface
{
    protected Container $container;
    protected PortalMetaRepository $portalMeta;
    protected LocationResolver $locationResolver;

    public function __construct(Container $container)
    {
        $this->container = $container;
        $this->portalMeta = $this->container->get(PortalMetaRepository::class);
        $this->locationResolver = $this->container->get(LocationResolver::class);
    }

    /**
     * Resolve locationId from request parameter or config default.
     *
     * @return string|WP_Error
     */
    protected function resolveLocationId(WP_REST_Request $request)
    {
        $locationId = sanitize_text_field($request->get_param('locationId') ?? '');
        return $this->locationResolver->resolveOrError(!empty($locationId) ? $locationId : null);
    }

    /**
     * Resolve locationId from request, returning null if not provided (for optional cases).
     *
     * @return string|null
     */
    protected function resolveLocationIdOptional(WP_REST_Request $request): ?string
    {
        $locationId = sanitize_text_field($request->get_param('locationId') ?? '');
        return $this->locationResolver->resolve(!empty($locationId) ? $locationId : null);
    }

    /**
     * Ensure user is loaded before capability checks.
     * This fixes JWT authentication timing issues.
     */
    protected function ensureUserLoaded(): void
    {
        global $current_user;
        $current_user = null;
        wp_get_current_user();
    }

    /**
     * Get portal meta for an estimate.
     *
     * @return array<string, mixed>
     */
    protected function getPortalMeta(string $estimateId): array
    {
        return $this->portalMeta->get($estimateId);
    }

    /**
     * Update portal meta for an estimate.
     *
     * @param array<string, mixed> $data
     */
    protected function updatePortalMeta(string $estimateId, array $data): bool
    {
        return $this->portalMeta->merge($estimateId, $data);
    }

    /**
     * Find estimate ID that has this invoice ID in its portal meta.
     * This is a reverse lookup - searches all portal meta options.
     *
     * @return string|null
     */
    protected function findEstimateIdByInvoiceId(string $invoiceId): ?string
    {
        return $this->portalMeta->findEstimateIdByInvoiceId($invoiceId);
    }

    /**
     * Format and return a REST response.
     *
     * @param array|WP_Error $result
     */
    protected function respond($result, ?WP_REST_Request $request = null): WP_REST_Response
    {
        if (is_wp_error($result)) {
            return $this->errorResponse($result);
        }

        if (!isset($result['ok'])) {
            $result['ok'] = true;
        }

        $response = new WP_REST_Response($result, 200);

        // Add cache headers for GET requests
        if ($request && $request->get_method() === 'GET') {
            $response->header('Cache-Control', 'private, max-age=60, stale-while-revalidate=120');
            $response->header('Vary', 'Authorization, Cookie');
        }

        $this->addSecurityHeaders($response);
        return $response;
    }

    /**
     * Create standardized error response with sanitization
     *
     * @param WP_Error $error
     * @return WP_REST_Response
     */
    protected function errorResponse(WP_Error $error): WP_REST_Response
    {
        $status = $error->get_error_data()['status'] ?? 500;
        $code = $error->get_error_code();
        $message = $error->get_error_message();
        $errorData = $error->get_error_data();
        
        // SECURITY: Sanitize error messages in production
        $isDebug = defined('WP_DEBUG') && WP_DEBUG;
        
        if (!$isDebug) {
            // Generic messages for production to prevent information disclosure
            $genericMessages = [
                'rest_forbidden' => 'Access denied.',
                'unauthorized' => 'Authentication required.',
                'invalid_token' => 'Invalid authentication token.',
                'rate_limited' => 'Too many requests. Please try again later.',
                'bad_request' => 'Invalid request.',
                'not_found' => 'Resource not found.',
                'server_error' => 'An error occurred. Please try again.',
                'xero_api_error' => 'Payment processing error. Please try again.',
                'ghl_api_error' => 'Service temporarily unavailable. Please try again.',
                'forbidden' => 'Insufficient privileges.',
                'invalid_nonce' => 'Invalid security token.',
            ];
            
            $message = $genericMessages[$code] ?? 'An error occurred. Please try again.';
        }
        
        $response = [
            'ok'   => false,
            'error' => $message,
            'code' => $code,
            // Include 'err' for backward compatibility
            'err'  => $message,
        ];
        
        // Only include detailed error information in debug mode
        if ($isDebug && !empty($errorData) && is_array($errorData)) {
            $sanitized = $this->sanitizeErrorData($errorData);
            if (!empty($sanitized)) {
                $response['details'] = $sanitized;
            }
        }
        
        $restResponse = new WP_REST_Response($response, $status);
        $this->addSecurityHeaders($restResponse);
        return $restResponse;
    }

    /**
     * Remove sensitive data from error details
     *
     * @param array<string, mixed> $data
     * @return array<string, mixed>
     */
    private function sanitizeErrorData(array $data): array
    {
        $sensitive = ['password', 'token', 'secret', 'key', 'authorization', 'cookie', 'api_key'];
        $sanitized = [];
        
        foreach ($data as $key => $value) {
            $keyLower = strtolower($key);
            $isSensitive = false;
            
            foreach ($sensitive as $sensitiveKey) {
                if (str_contains($keyLower, $sensitiveKey)) {
                    $isSensitive = true;
                    break;
                }
            }
            
            if ($isSensitive) {
                $sanitized[$key] = '[REDACTED]';
            } elseif (is_array($value)) {
                $sanitized[$key] = $this->sanitizeErrorData($value);
            } else {
                $sanitized[$key] = $value;
            }
        }
        
        return $sanitized;
    }

    /**
     * Add security headers to response
     *
     * @param WP_REST_Response $response
     * @return void
     */
    protected function addSecurityHeaders(WP_REST_Response $response): void
    {
        // Prevent MIME type sniffing
        $response->header('X-Content-Type-Options', 'nosniff');
        
        // XSS protection (legacy but still useful)
        $response->header('X-XSS-Protection', '1; mode=block');
        
        // Prevent clickjacking
        $response->header('X-Frame-Options', 'DENY');
        
        // Referrer policy
        $response->header('Referrer-Policy', 'strict-origin-when-cross-origin');
    }
}

