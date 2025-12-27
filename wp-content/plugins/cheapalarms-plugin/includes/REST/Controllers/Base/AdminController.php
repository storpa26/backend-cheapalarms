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
            $status = $result->get_error_data()['status'] ?? 500;
            $errorData = $result->get_error_data();
            $response = [
                'ok'   => false,
                'error' => $result->get_error_message(), // Standardized to 'error' instead of 'err'
                'code' => $result->get_error_code(),
                // Include 'err' for backward compatibility
                'err'  => $result->get_error_message(),
            ];
            
            // SECURITY: Only include detailed error information in debug mode
            // In production, avoid leaking internal system details
            if (defined('WP_DEBUG') && WP_DEBUG) {
                $response['details'] = $errorData['details'] ?? null;
            }
            
            return new WP_REST_Response($response, $status);
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

        return $response;
    }
}

