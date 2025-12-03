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

        register_rest_route('ca/v1', '/admin/estimates/(?P<estimateId>[a-zA-Z0-9]+)/send', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->sendEstimate($request);
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

        // Extract all estimate IDs for batch fetching
        $estimateIds = array_filter(array_map(fn($item) => $item['id'] ?? null, $items));
        
        // Batch fetch all portal meta in ONE query (prevents N+1 problem)
        $allMeta = $this->portalMeta->batchGet($estimateIds);

        // Merge portal meta and apply filters
        // NOTE: We DON'T fetch full estimates here to keep it fast
        // Full data is available on the detail page
        foreach ($items as $item) {
            $estimateId = $item['id'] ?? null;
            if (!$estimateId) {
                continue;
            }

            // Get portal meta from batch result (already fetched)
            $meta = $allMeta[$estimateId] ?? [];
            $portalStatusValue = $meta['quote']['status'] ?? 'sent';

            // Apply filters
            if ($status && ($item['status'] ?? '') !== $status) {
                continue;
            }
            if ($portalStatus && $portalStatusValue !== $portalStatus) {
                continue;
            }
            if ($search) {
                $matches = false;
                $matches = $matches || (isset($item['estimateNumber']) && stripos((string)$item['estimateNumber'], $search) !== false);
                $matches = $matches || (isset($item['email']) && stripos($item['email'], $search) !== false);
                if (!$matches) {
                    continue;
                }
            }

            // Get data from portal meta cache (fast) - no API calls
            $contactName = $meta['quote']['contactName'] ?? '';
            $contactEmail = $item['email'] ?? '';
            
            // Get total: prefer portal meta, fallback to GHL estimate data
            $total = (float)($meta['quote']['total'] ?? $item['total'] ?? 0);
            $currency = $meta['quote']['currency'] ?? $item['currency'] ?? 'AUD';
            $title = $meta['quote']['title'] ?? 'ESTIMATE';
            
            // Fallback: use email as name if name is empty
            if (empty($contactName) && !empty($contactEmail)) {
                $contactName = $contactEmail;
            }

            // Get linked invoice from meta
            $linkedInvoice = $meta['invoice'] ?? null;

            $out[] = [
                'id'             => $estimateId,
                'estimateNumber' => $item['estimateNumber'] ?? null,
                'title'          => $title,
                'contactName'    => $contactName ?: ($contactEmail ?: 'N/A'),
                'contactEmail'   => $contactEmail,
                'total'          => $total,
                'currency'       => $currency,
                'ghlStatus'      => $item['status'] ?? 'draft',
                'portalStatus'   => $portalStatusValue,
                'linkedInvoiceId' => $linkedInvoice['id'] ?? null,
                'createdAt'      => $item['createdAt'] ?? '',
                'updatedAt'      => $item['updatedAt'] ?? '',
            ];
        }

        // Calculate summary totals from ALL estimates (before pagination)
        $summary = [
            'sent' => ['count' => 0, 'total' => 0.0],
            'accepted' => ['count' => 0, 'total' => 0.0],
            'rejected' => ['count' => 0, 'total' => 0.0],
            'invoiced' => ['count' => 0, 'total' => 0.0],
        ];

        foreach ($out as $item) {
            $status = $item['portalStatus'] ?? 'sent';
            $total = (float)($item['total'] ?? 0);
            
            // Count by status
            if ($status === 'accepted') {
                $summary['accepted']['count']++;
                $summary['accepted']['total'] += $total;
            } elseif ($status === 'rejected') {
                $summary['rejected']['count']++;
                $summary['rejected']['total'] += $total;
            } else {
                // Default to 'sent' for any other status
                $summary['sent']['count']++;
                $summary['sent']['total'] += $total;
            }
            
            // Count invoiced (can overlap with other statuses)
            if (!empty($item['linkedInvoiceId'])) {
                $summary['invoiced']['count']++;
                $summary['invoiced']['total'] += $total;
            }
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
            'summary'  => $summary,
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

        // Return linked invoice ID only (lazy loading - fetch details on demand)
        // This avoids blocking the estimate load with another slow GHL API call
        $linkedInvoiceId = $meta['invoice']['id'] ?? null;
        $linkedInvoice = null;
        if ($linkedInvoiceId) {
            // Return minimal invoice info - full details can be fetched separately if needed
            $linkedInvoice = [
                'id' => $linkedInvoiceId,
                'invoiceNumber' => $meta['invoice']['number'] ?? null,
            ];
        }

        // Build normalized response
        $contact = $estimate['contact'] ?? $estimate['contactDetails'] ?? [];

        return $this->respond([
            'ok'            => true,
            'id'            => $estimateId,
            'estimateNumber' => $estimate['estimateNumber'] ?? $estimateId,
            'title'         => $estimate['title'] ?? $estimate['name'] ?? 'ESTIMATE',
            'ghlStatus'     => $estimate['status'] ?? 'draft',
            'portalStatus'  => $meta['quote']['status'] ?? 'sent',
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

    /**
     * Send estimate via GHL.
     */
    public function sendEstimate(WP_REST_Request $request): WP_REST_Response
    {
        $estimateId = sanitize_text_field($request->get_param('estimateId'));
        $locationId = $this->resolveLocationIdOptional($request);

        if (!$locationId) {
            $locationId = $this->locationResolver->resolve(null);
        }

        if (!$locationId) {
            return $this->respond(new WP_Error('missing_location', __('Location ID is required.', 'cheapalarms'), ['status' => 400]));
        }

        // Get optional send method from request body
        $body = $request->get_json_params();
        $options = $body ?? [];

        $result = $this->estimateService->sendEstimate($estimateId, $locationId, $options);
        if (is_wp_error($result)) {
            return $this->respond($result);
        }

        return $this->respond([
            'ok' => true,
            'message' => 'Estimate sent successfully',
        ]);
    }

}

