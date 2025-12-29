<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\REST\Controllers\Base\AdminController;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\Estimate\EstimateSnapshotRepository;
use CheapAlarms\Plugin\Services\Estimate\EstimateSnapshotSyncService;
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
    private EstimateSnapshotRepository $snapshotRepo;
    private EstimateSnapshotSyncService $snapshotSync;

    public function __construct(Container $container)
    {
        parent::__construct($container);
        $this->estimateService = $this->container->get(EstimateService::class);
        $this->portalService   = $this->container->get(PortalService::class);
        $this->invoiceService  = $this->container->get(InvoiceService::class);
        $this->auth            = $this->container->get(Authenticator::class);
        $this->snapshotRepo    = $this->container->get(EstimateSnapshotRepository::class);
        $this->snapshotSync    = $this->container->get(EstimateSnapshotSyncService::class);
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

        register_rest_route('ca/v1', '/admin/estimates/(?P<estimateId>[a-zA-Z0-9]+)/complete-review', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->completeReview($request);
            },
            'args'                => [
                'estimateId' => [
                    'required' => true,
                    'type'     => 'string',
                ],
            ],
        ]);

        register_rest_route('ca/v1', '/admin/estimates/(?P<estimateId>[a-zA-Z0-9]+)/request-changes', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->requestChanges($request);
            },
            'args'                => [
                'estimateId' => [
                    'required' => true,
                    'type'     => 'string',
                ],
            ],
        ]);

        // Non-blocking snapshot refresh for admin lists (WP-Cron).
        register_rest_route('ca/v1', '/admin/estimates/sync-snapshots', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }

                $locationIdResult = $this->resolveLocationId($request);
                if (is_wp_error($locationIdResult)) {
                    return $this->respond($locationIdResult);
                }
                $locationId = $locationIdResult;

                $already = wp_next_scheduled('ca_sync_estimate_snapshots', [$locationId]);
                if (!$already) {
                    wp_schedule_single_event(time() + 1, 'ca_sync_estimate_snapshots', [$locationId]);
                }

                return $this->respond([
                    'ok'              => true,
                    'scheduled'       => $already ? false : true,
                    'alreadyScheduled'=> $already ? true : false,
                    'locationId'      => $locationId,
                ]);
            },
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
        
        // Validate workflow status filter against whitelist
        $validWorkflowStatuses = ['requested', 'sent', 'under_review', 'ready_to_accept', 'accepted', 'rejected', 'booked', 'paid', 'completed'];
        $workflowStatusRaw = sanitize_text_field($request->get_param('workflowStatus') ?? '');
        $workflowStatus = in_array($workflowStatusRaw, $validWorkflowStatuses, true) ? $workflowStatusRaw : '';
        $page        = max(1, (int)($request->get_param('page') ?? 1));
        $pageSize    = max(1, min(100, (int)($request->get_param('pageSize') ?? 20)));

        // Prefer snapshot table (fast + scalable). Fall back to transient-cached GHL list if snapshots are empty/unavailable.
        $items = null;
        $snapshotItems = $this->snapshotRepo->listByLocation($locationId);

        if (!is_wp_error($snapshotItems) && is_array($snapshotItems) && count($snapshotItems) > 0) {
            $items = $snapshotItems;

            // Best-effort background refresh if snapshots are stale.
            $lastSyncedAt = $this->snapshotRepo->lastSyncedAt($locationId);
            $stale = false;
            if (!is_wp_error($lastSyncedAt) && is_string($lastSyncedAt) && $lastSyncedAt) {
                $stale = (time() - (int)strtotime($lastSyncedAt)) > (3 * MINUTE_IN_SECONDS);
            }
            if ($stale && !wp_next_scheduled('ca_sync_estimate_snapshots', [$locationId])) {
                wp_schedule_single_event(time() + 1, 'ca_sync_estimate_snapshots', [$locationId]);
            }
        } else {
            // If snapshots are missing/empty, schedule a background sync and fall back to the current transient cache path.
            if (!wp_next_scheduled('ca_sync_estimate_snapshots', [$locationId])) {
                wp_schedule_single_event(time() + 1, 'ca_sync_estimate_snapshots', [$locationId]);
            }

            // Build cache key for the full (up to 100) GHL list for this location
            $cacheKey = "ca_admin_estimates_ghl_full_{$locationId}";

            $result   = get_transient($cacheKey);
            $cacheHit = ($result !== false);

            if (!$cacheHit) {
                $result = $this->estimateService->listEstimates($locationId, 100); // legacy ceiling
                if (is_wp_error($result)) {
                    return $this->respond($result);
                }
                set_transient($cacheKey, $result, 3 * MINUTE_IN_SECONDS);
            }

            $items = $result['items'] ?? [];
        }

        if (!is_array($items)) {
            $items = [];
        }

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
            
            // Get workflow status safely (check if workflow is an array)
            // Calculate once and reuse for both filtering and response
            $workflow = $meta['workflow'] ?? [];
            
            // Derive workflow status for old estimates that don't have workflow block
            if (empty($workflow) || !isset($workflow['status']) || !is_array($workflow)) {
                $quoteStatus = $meta['quote']['status'] ?? 'sent';
                $hasPhotos = !empty($meta['photos']['submission_status']) && $meta['photos']['submission_status'] === 'submitted';
                
                // Derive from existing data (NEW: Updated workflow states)
                if ($quoteStatus === 'accepted') {
                    $workflowStatusValue = 'accepted';
                } elseif ($quoteStatus === 'rejected') {
                    $workflowStatusValue = 'rejected';
                } elseif ($quoteStatus === 'sent' && !empty($meta['quote']['acceptance_enabled'])) {
                    // Check if acceptance is enabled (ready to accept)
                    $workflowStatusValue = 'ready_to_accept';
                } elseif ($hasPhotos && $quoteStatus === 'sent') {
                    // Check if review was requested
                    $approvalRequested = $meta['quote']['approval_requested'] ?? false;
                    $workflowStatusValue = $approvalRequested ? 'under_review' : 'sent';
                } else {
                    $workflowStatusValue = 'requested';
                }
            } else {
                $workflowStatusValue = $workflow['status'];
            }

            // Apply filters
            if ($status && ($item['status'] ?? '') !== $status) {
                continue;
            }
            if ($portalStatus && $portalStatusValue !== $portalStatus) {
                continue;
            }
            // NEW: Filter by workflow status
            if ($workflowStatus && $workflowStatusValue !== $workflowStatus) {
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

            // Get linked invoice from meta (support both old and new structure)
            $invoice = $meta['invoice'] ?? null;
            $linkedInvoice = null;
            $linkedInvoiceId = null;
            
            if ($invoice) {
                // Check for new structure first (ghl.xero), then fall back to old flat structure
                if (isset($invoice['ghl']) && is_array($invoice['ghl'])) {
                    $linkedInvoiceId = $invoice['ghl']['id'] ?? null;
                } else {
                    // Old flat structure
                    $linkedInvoiceId = $invoice['id'] ?? null;
                }
                
                if ($linkedInvoiceId) {
                    $linkedInvoice = ['id' => $linkedInvoiceId];
                }
            }

            // Reuse workflowStatusValue calculated above (no need to recalculate)
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
                'workflowStatus' => $workflowStatusValue, // Reuse value calculated above
                'linkedInvoiceId' => ($linkedInvoice && isset($linkedInvoice['id'])) ? $linkedInvoice['id'] : null,
                'createdAt'      => $item['createdAt'] ?? '',
                'updatedAt'      => $item['updatedAt'] ?? '',
            ];
        }

        // Calculate summary totals from ALL filtered estimates (before pagination)
        // This is now correct because we have the full dataset (or at least the first 100)
        $summary = [
            'sent' => ['count' => 0, 'total' => 0.0],
            'accepted' => ['count' => 0, 'total' => 0.0],
            'rejected' => ['count' => 0, 'total' => 0.0],
            'invoiced' => ['count' => 0, 'total' => 0.0],
        ];

        foreach ($out as $item) {
            $status = $item['portalStatus'] ?? 'sent';
            $total = (float)($item['total'] ?? 0);
            
            // Validate and sanitize total (prevent overflow, negative, or NaN values)
            if (!is_finite($total) || $total < 0) {
                $total = 0.0; // Sanitize invalid values
            }
            
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

        // Apply pagination to filtered results
        // Now $total is correct because it's from the full filtered dataset
        $total = count($out);
        $offset = max(0, ($page - 1) * $pageSize); // Ensure offset is non-negative
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
        // Support both new structure (ghl.xero) and old flat structure for backward compatibility
        $invoice = $meta['invoice'] ?? null;
        $linkedInvoiceId = null;
        $invoiceNumber = null;
        
        if ($invoice) {
            // Check for new structure first (ghl.xero), then fall back to old flat structure
            if (isset($invoice['ghl']) && is_array($invoice['ghl'])) {
                $linkedInvoiceId = $invoice['ghl']['id'] ?? null;
                $invoiceNumber = $invoice['ghl']['number'] ?? null;
            } else {
                // Old flat structure
                $linkedInvoiceId = $invoice['id'] ?? null;
                $invoiceNumber = $invoice['number'] ?? null;
            }
        }
        
        $linkedInvoice = null;
        if ($linkedInvoiceId) {
            // Return minimal invoice info - full details can be fetched separately if needed
            $linkedInvoice = [
                'id' => $linkedInvoiceId,
                'invoiceNumber' => $invoiceNumber,
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
                // NEW: Include workflow, booking, and payment data for admin visibility
                'workflow'   => $meta['workflow'] ?? null,
                'booking'    => $meta['booking'] ?? null,
                'payment'    => $meta['payment'] ?? null,
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

        // Get optional send method and revision data from request body
        $body = $request->get_json_params();
        $options = $body ?? [];
        $revisionData = $options['revisionData'] ?? null;
        $revisionNote = $options['revisionNote'] ?? null;

        // If revision data provided, send custom revision email instead of standard estimate
        if ($revisionData && is_array($revisionData)) {
            // Merge revisionNote into revisionData if provided (for admin note in email)
            if ($revisionNote && !isset($revisionData['adminNote'])) {
                $revisionData['adminNote'] = sanitize_text_field($revisionNote);
            }
            
            // Fetch estimate once and pass to sendRevisionNotification to avoid re-fetching
            $estimate = $this->estimateService->getEstimate([
                'estimateId' => $estimateId,
                'locationId' => $locationId,
            ]);
            
            // Pass estimate data if available, otherwise let sendRevisionNotification fetch it
            $estimateData = !is_wp_error($estimate) ? $estimate : null;
            
            // Send notification (non-blocking - errors are logged but don't fail the request)
            try {
                $this->portalService->sendRevisionNotification($estimateId, $locationId, $revisionData, $estimateData);
            } catch (\Exception $e) {
                // Log error but don't fail the request (email is non-critical)
                error_log('Failed to send revision notification: ' . $e->getMessage());
            }
            
            return $this->respond([
                'ok' => true,
                'message' => 'Revision notification sent successfully',
            ]);
        }

        // Standard estimate send (via GHL)
        $result = $this->estimateService->sendEstimate($estimateId, $locationId, $options);
        if (is_wp_error($result)) {
            return $this->respond($result);
        }

        return $this->respond([
            'ok' => true,
            'message' => 'Estimate sent successfully',
        ]);
    }

    /**
     * Complete review for an estimate (Approve & Enable Acceptance)
     * Transitions workflow from "under_review" to "ready_to_accept"
     */
    public function completeReview(WP_REST_Request $request): WP_REST_Response
    {
        $estimateId = sanitize_text_field($request->get_param('estimateId'));
        $locationId = sanitize_text_field($request->get_param('locationId') ?? '');

        if (empty($estimateId)) {
            return $this->respond(new WP_Error('missing_estimate_id', __('Estimate ID is required.', 'cheapalarms'), ['status' => 400]));
        }

        $options = [];
        $body = $request->get_json_params();
        if (is_array($body)) {
            $options = $body;
            if (isset($body['locationId']) && empty($locationId)) {
                $locationId = sanitize_text_field($body['locationId']);
            }
        }

        $result = $this->portalService->completeReview($estimateId, $locationId, $options);

        return $this->respond($result);
    }

    /**
     * Request changes to photos (admin action)
     */
    public function requestChanges(WP_REST_Request $request): WP_REST_Response
    {
        $estimateId = sanitize_text_field($request->get_param('estimateId'));
        $locationId = sanitize_text_field($request->get_param('locationId') ?? '');

        if (empty($estimateId)) {
            return $this->respond(new WP_Error('missing_estimate_id', __('Estimate ID is required.', 'cheapalarms'), ['status' => 400]));
        }

        $options = [];
        $body = $request->get_json_params();
        if (is_array($body)) {
            $options = $body;
            if (isset($body['locationId']) && empty($locationId)) {
                $locationId = sanitize_text_field($body['locationId']);
            }
        }

        $note = sanitize_text_field($body['note'] ?? '');

        $result = $this->portalService->requestChanges($estimateId, $locationId, $note);

        return $this->respond($result);
    }

}

