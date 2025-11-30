<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\REST\Controllers\Base\AdminController;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\EstimateService;
use CheapAlarms\Plugin\Services\InvoiceService;
use CheapAlarms\Plugin\Services\PortalService;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

use function sanitize_text_field;

class AdminEstimateController extends AdminController
{
    private EstimateService $estimateService;
    private PortalService $portalService;
    private InvoiceService $invoiceService;
    private Authenticator $auth;

    public function __construct(Container $container)
    {
        parent::__construct($container);
        $this->estimateService = $this->container->get(EstimateService::class);
        $this->portalService   = $this->container->get(PortalService::class);
        $this->invoiceService  = $this->container->get(InvoiceService::class);
        $this->auth            = $this->container->get(Authenticator::class);
    }

    public function register(): void
    {
        register_rest_route('ca/v1', '/admin/estimates', [
            'methods'             => 'GET',
            'permission_callback' => fn () => true, // Let request through, check auth in callback
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->listEstimates($request);
            },
        ]);

        register_rest_route('ca/v1', '/admin/estimates/(?P<estimateId>[a-zA-Z0-9]+)', [
            'methods'             => 'GET',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->getEstimate($request);
            },
            'args'                => [
                'estimateId' => [
                    'required' => true,
                    'type'     => 'string',
                ],
            ],
        ]);

        register_rest_route('ca/v1', '/admin/estimates/(?P<estimateId>[a-zA-Z0-9]+)/sync', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->syncEstimate($request);
            },
            'args'                => [
                'estimateId' => [
                    'required' => true,
                    'type'     => 'string',
                ],
            ],
        ]);

        register_rest_route('ca/v1', '/admin/estimates/(?P<estimateId>[a-zA-Z0-9]+)/create-invoice', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->createInvoice($request);
            },
            'args'                => [
                'estimateId' => [
                    'required' => true,
                    'type'     => 'string',
                ],
            ],
        ]);
    }

    /**
     * List estimates with filters and pagination.
     */
    public function listEstimates(WP_REST_Request $request): WP_REST_Response
    {
        $locationIdResult = $this->resolveLocationId($request);
        if (is_wp_error($locationIdResult)) {
            return $this->respond($locationIdResult);
        }
        $locationId = $locationIdResult;

        $search      = sanitize_text_field($request->get_param('search') ?? '');
        $status      = sanitize_text_field($request->get_param('status') ?? '');
        $portalStatus = sanitize_text_field($request->get_param('portalStatus') ?? '');
        $page        = max(1, (int)($request->get_param('page') ?? 1));
        $pageSize    = max(1, min(100, (int)($request->get_param('pageSize') ?? 20)));

        // Fetch estimates from GHL
        $result = $this->estimateService->listEstimates($locationId, $pageSize * 2); // Fetch more for filtering
        if (is_wp_error($result)) {
            return $this->respond($result);
        }

        $items = $result['items'] ?? [];
        $out   = [];

        // Merge portal meta and apply filters
        foreach ($items as $item) {
            $estimateId = $item['id'] ?? null;
            if (!$estimateId) {
                continue;
            }

            // Get portal meta
            $meta = $this->getPortalMeta($estimateId);
            $portalStatusValue = $meta['quote']['status'] ?? 'pending';

            // Apply filters
            if ($status && ($item['status'] ?? '') !== $status) {
                continue;
            }
            if ($portalStatus && $portalStatusValue !== $portalStatus) {
                continue;
            }
            if ($search) {
                $searchLower = strtolower($search);
                $matches = false;
                $matches = $matches || (isset($item['estimateNumber']) && stripos((string)$item['estimateNumber'], $search) !== false);
                $matches = $matches || (isset($item['email']) && stripos($item['email'], $search) !== false);
                // We'd need to fetch full estimate for name search - skip for now or do it
                if (!$matches) {
                    continue;
                }
            }

            // Get linked invoice from meta
            $linkedInvoice = $meta['invoice'] ?? null;

            $out[] = [
                'id'             => $estimateId,
                'estimateNumber' => $item['estimateNumber'] ?? null,
                'title'          => 'ESTIMATE', // Would need full estimate for title
                'contactName'    => '', // Would need full estimate for name
                'contactEmail'   => $item['email'] ?? '',
                'total'          => 0, // Would need full estimate for total
                'currency'       => 'AUD',
                'ghlStatus'      => $item['status'] ?? 'draft',
                'portalStatus'   => $portalStatusValue,
                'linkedInvoiceId' => $linkedInvoice['id'] ?? null,
                'createdAt'      => $item['createdAt'] ?? '',
                'updatedAt'      => $item['updatedAt'] ?? '',
            ];
        }

        // Apply pagination
        $total = count($out);
        $offset = ($page - 1) * $pageSize;
        $paginated = array_slice($out, $offset, $pageSize);

        return $this->respond([
            'ok'       => true,
            'items'    => $paginated,
            'total'    => $total,
            'page'     => $page,
            'pageSize' => $pageSize,
        ]);
    }

    /**
     * Get single estimate detail with portal meta.
     */
    public function getEstimate(WP_REST_Request $request): WP_REST_Response
    {
        $estimateId = sanitize_text_field($request->get_param('estimateId'));
        $locationId = $this->resolveLocationIdOptional($request);

        // Only pass locationId if it's provided, otherwise let EstimateService use default
        $args = [
            'estimateId' => $estimateId,
        ];
        if ($locationId) {
            $args['locationId'] = $locationId;
        }

        // Fetch full estimate from GHL
        $estimate = $this->estimateService->getEstimate($args);
        if (is_wp_error($estimate)) {
            return $this->respond($estimate);
        }

        // Get portal meta
        $meta = $this->getPortalMeta($estimateId);

        // Get linked invoice if exists
        $linkedInvoice = null;
        if (!empty($meta['invoice']['id'])) {
            // Use locationId from request or fallback to config default
            $effectiveLocationId = $locationId ?: $this->locationResolver->resolve(null);
            if ($effectiveLocationId) {
                $invoiceResult = $this->invoiceService->getInvoice($meta['invoice']['id'], $effectiveLocationId);
                if (!is_wp_error($invoiceResult)) {
                    $linkedInvoice = $invoiceResult;
                }
            }
        }

        // Build normalized response
        $contact = $estimate['contact'] ?? $estimate['contactDetails'] ?? [];

        return $this->respond([
            'ok'            => true,
            'id'            => $estimateId,
            'estimateNumber' => $estimate['estimateNumber'] ?? $estimateId,
            'title'         => $estimate['title'] ?? $estimate['name'] ?? 'ESTIMATE',
            'ghlStatus'     => $estimate['status'] ?? 'draft',
            'portalStatus'  => $meta['quote']['status'] ?? 'pending',
            'contact'       => [
                'id'    => $contact['id'] ?? $contact['contactId'] ?? null,
                'name'  => $contact['name'] ?? (($contact['firstName'] ?? '') . ' ' . ($contact['lastName'] ?? '')),
                'email' => $contact['email'] ?? '',
                'phone' => $contact['phone'] ?? '',
            ],
            'items'         => $estimate['items'] ?? [],
            'subtotal'      => $estimate['subtotal'] ?? null,
            'tax'           => $estimate['tax'] ?? null,
            'discount'      => $estimate['discount'] ?? null,
            'total'         => $estimate['total'] ?? 0,
            'currency'      => $estimate['currency'] ?? 'AUD',
            'createdAt'     => $estimate['createdAt'] ?? '',
            'updatedAt'     => $estimate['updatedAt'] ?? '',
            'portalMeta'    => [
                'acceptedAt' => $meta['quote']['acceptedAt'] ?? null,
                'photos'     => $meta['photos'] ?? null,
                'invoice'    => $meta['invoice'] ?? null,
            ],
            'linkedInvoice' => $linkedInvoice,
        ]);
    }

    /**
     * Sync estimate by re-fetching from GHL.
     */
    public function syncEstimate(WP_REST_Request $request): WP_REST_Response
    {
        $estimateId = sanitize_text_field($request->get_param('estimateId'));
        $locationId = $this->resolveLocationIdOptional($request);

        // Only pass locationId if it's provided, otherwise let EstimateService use default
        $args = [
            'estimateId' => $estimateId,
        ];
        if ($locationId) {
            $args['locationId'] = $locationId;
        }

        // Re-fetch from GHL
        $estimate = $this->estimateService->getEstimate($args);
        if (is_wp_error($estimate)) {
            return $this->respond($estimate);
        }

        // Get updated portal meta
        $meta = $this->getPortalMeta($estimateId);

        // Optionally reconcile portal meta if GHL status changed
        // (For now, just return updated data)

        return $this->getEstimate($request); // Reuse getEstimate logic
    }

    /**
     * Create invoice from estimate.
     */
    public function createInvoice(WP_REST_Request $request): WP_REST_Response
    {
        $estimateId = sanitize_text_field($request->get_param('estimateId'));
        $locationId = $this->resolveLocationIdOptional($request);

        // Use PortalService method (which calls createInvoiceFromDraftEstimate internally)
        // If locationId is empty, pass null to let PortalService use config default
        $result = $this->portalService->createInvoiceForEstimate($estimateId, $locationId);
        if (is_wp_error($result)) {
            return $this->respond($result);
        }

        return $this->respond([
            'ok'     => true,
            'invoice' => $result['invoice'] ?? null,
            'exists'  => $result['exists'] ?? false,
        ]);
    }

}

