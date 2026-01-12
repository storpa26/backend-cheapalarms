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
use function sanitize_email;
use function email_exists;
use function wp_delete_user;
use function get_user_by;
use function delete_user_meta;
use function delete_option;
use function wp_json_encode;

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

        // List trash (soft-deleted estimates) - MUST be registered BEFORE the parameterized route
        register_rest_route('ca/v1', '/admin/estimates/trash', [
            'methods'             => 'GET',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->listTrash($request);
            },
        ]);

        // Bulk restore estimates - MUST be registered BEFORE the parameterized route
        register_rest_route('ca/v1', '/admin/estimates/bulk-restore', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->bulkRestore($request);
            },
        ]);

        // Bulk delete estimates - MUST be registered BEFORE the parameterized route
        register_rest_route('ca/v1', '/admin/estimates/bulk-delete', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->bulkDelete($request);
            },
        ]);

        // Empty trash (permanently delete all soft-deleted estimates) - MUST be registered BEFORE the parameterized route
        register_rest_route('ca/v1', '/admin/estimates/trash/empty', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->emptyTrash($request);
            },
        ]);

        // Non-blocking snapshot refresh for admin lists (WP-Cron) - MUST be registered BEFORE the parameterized route
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

        // Complete delete by email - deletes contact, estimates, invoices, metadata, and WordPress user
        register_rest_route('ca/v1', '/admin/data/delete-by-email', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->deleteByEmail($request);
            },
        ]);

        // Now register the parameterized route (matches any estimateId) - MUST be after specific routes
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

        register_rest_route('ca/v1', '/admin/estimates/(?P<estimateId>[a-zA-Z0-9]+)/delete', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->deleteEstimate($request);
            },
            'args'                => [
                'estimateId' => [
                    'required' => true,
                    'type'     => 'string',
                ],
            ],
        ]);

        // Restore soft-deleted estimate
        register_rest_route('ca/v1', '/admin/estimates/(?P<estimateId>[a-zA-Z0-9]+)/restore', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->restoreEstimate($request);
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

            // Normalize to string to match batchGet() keys (which are normalized)
            $estimateId = (string)$estimateId;

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
                // CRITICAL: Include quote data (contains revisionNumber, acceptance_enabled, status, etc.)
                'quote'      => $meta['quote'] ?? null,
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

    /**
     * Delete estimate with scope support (local, ghl, both).
     * Fail-closed: if scope=both and GHL delete fails, local delete is skipped.
     */
    public function deleteEstimate(WP_REST_Request $request): WP_REST_Response
    {
        // Safety gate
        $gateCheck = $this->checkDestructiveActionsEnabled();
        if ($gateCheck) {
            return $this->respond($gateCheck);
        }

        $estimateId = sanitize_text_field($request->get_param('estimateId'));
        $body = $request->get_json_params() ?? [];
        $scope = sanitize_text_field($body['scope'] ?? 'both');
        $confirm = sanitize_text_field($body['confirm'] ?? '');
        $locationId = $this->resolveLocationIdOptional($request) ?: sanitize_text_field($body['locationId'] ?? '');

        // Validation
        if (empty($estimateId)) {
            return $this->respond(new WP_Error('bad_request', __('Estimate ID is required.', 'cheapalarms'), ['status' => 400]));
        }

        if (!in_array($scope, ['local', 'ghl', 'both'], true)) {
            return $this->respond(new WP_Error('bad_request', __('Invalid scope. Must be: local, ghl, or both.', 'cheapalarms'), ['status' => 400]));
        }

        if ($confirm !== 'DELETE') {
            return $this->respond(new WP_Error('bad_request', __('Confirmation required. Set confirm="DELETE" in request body.', 'cheapalarms'), ['status' => 400]));
        }

        $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
        $user = wp_get_current_user();
        $correlationId = wp_generate_password(12, false);

        $logger->info('Estimate delete initiated', [
            'correlationId' => $correlationId,
            'estimateId' => $estimateId,
            'scope' => $scope,
            'userId' => $user->ID ?? null,
            'userEmail' => $user->user_email ?? null,
        ]);

        $result = [
            'ok' => true,
            'scope' => $scope,
            'correlationId' => $correlationId,
            'local' => ['ok' => false, 'skipped' => true],
            'ghl' => ['ok' => false, 'skipped' => true],
        ];

        // Determine execution order: for "both", do GHL first (fail-closed)
        $doGhl = ($scope === 'ghl' || $scope === 'both');
        $doLocal = ($scope === 'local' || ($scope === 'both'));

        // Step 1: GHL delete (if needed, and first for fail-closed)
        if ($doGhl) {
            if (empty($locationId)) {
                return $this->respond(new WP_Error('missing_location', __('locationId is required for GHL delete.', 'cheapalarms'), ['status' => 400]));
            }
            $ghlClient = $this->container->get(\CheapAlarms\Plugin\Services\GhlClient::class);
            $ghlResult = $ghlClient->delete(
                '/invoices/estimate/' . rawurlencode($estimateId),
                ['altId' => $locationId, 'altType' => 'location'],
                $locationId,
                10,
                0
            );

            if (is_wp_error($ghlResult)) {
                $errorData = $ghlResult->get_error_data();
                $result['ghl'] = [
                    'ok' => false,
                    'error' => $ghlResult->get_error_message(),
                    'code' => $ghlResult->get_error_code(),
                    'httpCode' => $errorData['code'] ?? null,
                ];
                $result['ok'] = false;

                // Fail-closed: if GHL fails and scope=both, skip local delete
                if ($scope === 'both') {
                    $result['local']['skipped'] = true;
                    $logger->warning('Estimate delete failed (fail-closed)', [
                        'correlationId' => $correlationId,
                        'estimateId' => $estimateId,
                        'ghlError' => $ghlResult->get_error_message(),
                    ]);
                    return $this->respond(new WP_Error(
                        'delete_partial_failure',
                        'Delete operation completed with errors.',
                        ['status' => 500, 'details' => $result]
                    ));
                }
            } else {
                $result['ghl'] = [
                    'ok' => true,
                    'alreadyDeleted' => $ghlResult['alreadyDeleted'] ?? false,
                ];
                $logger->info('Estimate deleted from GHL', [
                    'correlationId' => $correlationId,
                    'estimateId' => $estimateId,
                    'alreadyDeleted' => $result['ghl']['alreadyDeleted'],
                ]);
            }
        }

        // Step 2: Local delete (if needed, and GHL succeeded or scope=local)
        if ($doLocal && !($scope === 'both' && !$result['ghl']['ok'])) {
            // For local delete, locationId is required for location-scoped soft delete
            if (empty($locationId)) {
                // Try to get locationId from the estimate snapshot
                global $wpdb;
                $tableName = $wpdb->prefix . 'ca_estimate_snapshots';
                $locationId = $wpdb->get_var($wpdb->prepare(
                    "SELECT location_id FROM {$tableName} WHERE estimate_id = %s LIMIT 1",
                    $estimateId
                ));
                
                if (empty($locationId)) {
                    $result['local'] = [
                        'ok' => false,
                        'error' => 'locationId is required for soft delete',
                    ];
                    $result['ok'] = false;
                }
            }
            
            if (!empty($locationId)) {
                $localResult = $this->deleteEstimateLocal($estimateId, $scope, $locationId);
                if (is_wp_error($localResult)) {
                    $result['local'] = [
                        'ok' => false,
                        'error' => $localResult->get_error_message(),
                    ];
                    $result['ok'] = false;
                } else {
                    $result['local'] = [
                        'ok' => true,
                        'alreadyDeleted' => $localResult['alreadyDeleted'] ?? false,
                    ];
                    $logger->info('Estimate soft deleted from WordPress', [
                        'correlationId' => $correlationId,
                        'estimateId' => $estimateId,
                        'locationId' => $locationId,
                        'alreadyDeleted' => $result['local']['alreadyDeleted'],
                    ]);
                }
            }
        }

        if (!$result['ok']) {
            return $this->respond(new WP_Error(
                'delete_partial_failure',
                'Delete operation completed with errors.',
                ['status' => 500, 'details' => $result]
            ));
        }

        return $this->respond($result);
    }

    /**
     * Restore soft-deleted estimate
     * 
     * POST /ca/v1/admin/estimates/{estimateId}/restore
     */
    public function restoreEstimate(WP_REST_Request $request): WP_REST_Response
    {
        $gateCheck = $this->checkDestructiveActionsEnabled();
        if ($gateCheck) {
            return $this->respond($gateCheck);
        }

        $estimateId = sanitize_text_field($request->get_param('estimateId'));
        if (empty($estimateId)) {
            return $this->respond(new WP_Error('bad_request', __('Estimate ID is required.', 'cheapalarms'), ['status' => 400]));
        }

        $locationIdResult = $this->resolveLocationId($request);
        if (is_wp_error($locationIdResult)) {
            return $this->respond($locationIdResult);
        }
        $locationId = $locationIdResult;

        $user = wp_get_current_user();
        $result = $this->snapshotRepo->restore($estimateId, $locationId, $user->ID ?? 0);

        if (is_wp_error($result)) {
            return $this->respond($result);
        }

        // Note: Portal meta was hard deleted during soft delete.
        // If portal meta is needed, it must be recreated by syncing from GHL.
        // This is intentional - snapshot table is source of truth, not portal meta.

        return $this->respond([
            'ok' => true,
            'estimateId' => $estimateId,
            'locationId' => $locationId,
            'restored_at' => current_time('mysql'),
            'note' => 'Estimate restored. Portal meta will regenerate on next sync or when estimate is accessed.',
            'warning' => 'Portal meta and user links were deleted and will need to be recreated from GHL if needed.',
        ]);
    }

    /**
     * Empty trash (permanently delete all soft-deleted estimates)
     * 
     * POST /ca/v1/admin/estimates/trash/empty
     */
    public function emptyTrash(WP_REST_Request $request): WP_REST_Response
    {
        $gateCheck = $this->checkDestructiveActionsEnabled();
        if ($gateCheck) {
            return $this->respond($gateCheck);
        }

        // Increase time limit for large batch operations (matches LogController pattern)
        $originalTimeLimit = ini_get('max_execution_time');
        @set_time_limit(300); // 5 minutes for large batches

        try {
            $body = $request->get_json_params() ?? [];
            $confirm = sanitize_text_field($body['confirm'] ?? '');

            if ($confirm !== 'EMPTY_TRASH') {
                return $this->respond(new WP_Error('bad_request', __('Confirmation required. Set confirm="EMPTY_TRASH"', 'cheapalarms'), ['status' => 400]));
            }

            $locationIdResult = $this->resolveLocationId($request);
            if (is_wp_error($locationIdResult)) {
                return $this->respond($locationIdResult);
            }
            $locationId = $locationIdResult;

            // Get all soft-deleted estimates for this location
            $trashItems = $this->snapshotRepo->findAllInTrash($locationId);
            
            if (is_wp_error($trashItems)) {
                return $this->respond($trashItems);
            }

            if (empty($trashItems)) {
                return $this->respond([
                    'ok' => true,
                    'deleted' => 0,
                    'message' => 'Trash is already empty',
                ]);
            }

            $deleted = 0;
            $errors = [];
            $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);

            // Process in batches for better performance
            $batchSize = 100;
            $batches = array_chunk($trashItems, $batchSize);

            foreach ($batches as $batch) {
                foreach ($batch as $row) {
                    $estimateId = $row['estimate_id'] ?? null;
                    
                    if (!$estimateId) {
                        continue;
                    }

                    // Hard delete from snapshot table (location-scoped)
                    $result = $this->snapshotRepo->hardDelete($estimateId, $locationId);
                    
                    if (is_wp_error($result)) {
                        $errors[] = ['estimateId' => $estimateId, 'error' => $result->get_error_message()];
                    } else {
                        $deleted++;
                        
                        // Also hard delete related options (if still exist)
                        delete_option('ca_portal_meta_' . $estimateId);
                        delete_option('ca_estimate_uploads_' . $estimateId);
                        delete_option('ca_estimate_job_link_' . $estimateId);
                    }
                }
            }

            $logger->info('Trash emptied', [
                'locationId' => $locationId,
                'deleted' => $deleted,
                'errors' => count($errors),
            ]);

            return $this->respond([
                'ok' => true,
                'deleted' => $deleted,
                'errors' => $errors,
                'message' => sprintf(__('%d estimate(s) permanently deleted', 'cheapalarms'), $deleted),
            ]);
        } finally {
            // Always restore original time limit if it wasn't unlimited (even if exception occurs)
            if ($originalTimeLimit !== false && $originalTimeLimit !== '0') {
                @set_time_limit((int)$originalTimeLimit);
            }
        }
    }

    /**
     * List trash (soft-deleted estimates)
     * 
     * GET /ca/v1/admin/estimates/trash
     */
    public function listTrash(WP_REST_Request $request): WP_REST_Response
    {
        $locationIdResult = $this->resolveLocationId($request);
        if (is_wp_error($locationIdResult)) {
            return $this->respond($locationIdResult);
        }
        $locationId = $locationIdResult;

        $limit = max(1, min(100, (int)($request->get_param('limit') ?? 100)));
        $items = $this->snapshotRepo->findInTrash($locationId, $limit);

        if (is_wp_error($items)) {
            return $this->respond($items);
        }

        // Normalize for frontend
        $normalized = [];
        foreach ($items as $row) {
            $normalized[] = [
                'id' => $row['estimate_id'] ?? null,
                'estimateNumber' => $row['estimate_number'] ?? null,
                'email' => $row['email'] ?? '',
                'status' => $row['ghl_status'] ?? '',
                'total' => (float)($row['total'] ?? 0),
                'currency' => $row['currency'] ?? 'AUD',
                'createdAt' => $row['created_at'] ?? '',
                'updatedAt' => $row['updated_at'] ?? '',
                'deletedAt' => $row['deleted_at'] ?? '',
                'deletedBy' => $row['deleted_by'] ?? null,
                'deletionScope' => $row['deletion_scope'] ?? null,
                'deletionReason' => $row['deletion_reason'] ?? null,
            ];
        }

        return $this->respond([
            'ok' => true,
            'items' => $normalized,
            'count' => count($normalized),
        ]);
    }

    /**
     * Bulk restore estimates
     * 
     * POST /ca/v1/admin/estimates/bulk-restore
     */
    public function bulkRestore(WP_REST_Request $request): WP_REST_Response
    {
        $gateCheck = $this->checkDestructiveActionsEnabled();
        if ($gateCheck) {
            return $this->respond($gateCheck);
        }

        $body = $request->get_json_params() ?? [];
        $confirm = sanitize_text_field($body['confirm'] ?? '');
        $estimateIds = $body['estimateIds'] ?? [];

        if ($confirm !== 'BULK_RESTORE') {
            return $this->respond(new WP_Error('bad_request', __('Confirmation required. Set confirm="BULK_RESTORE"', 'cheapalarms'), ['status' => 400]));
        }

        if (!is_array($estimateIds) || empty($estimateIds)) {
            return $this->respond(new WP_Error('bad_request', __('estimateIds array is required', 'cheapalarms'), ['status' => 400]));
        }

        // Validate each ID is a valid string/numeric
        foreach ($estimateIds as $id) {
            if (!is_string($id) && !is_numeric($id)) {
                return $this->respond(new WP_Error('bad_request', __('Invalid estimate ID format. All IDs must be strings or numbers.', 'cheapalarms'), ['status' => 400]));
            }
        }

        // Limit batch size for performance
        $maxBatchSize = 1000;
        if (count($estimateIds) > $maxBatchSize) {
            return $this->respond(new WP_Error('bad_request', sprintf(__('Maximum %d estimates per batch', 'cheapalarms'), $maxBatchSize), ['status' => 400]));
        }

        $user = wp_get_current_user();
        $restored = 0;
        $errors = [];

        // PHASE 1: Batch fetch all locationIds in ONE query (prevents N+1)
        $requestLocationId = !empty($body['locationId']) ? sanitize_text_field($body['locationId']) : null;
        $locationIdMap = [];
        
        if (!$requestLocationId) {
            // Only batch fetch if locationId not provided in request
            $sanitizedEstimateIds = array_map('sanitize_text_field', array_filter($estimateIds, fn($id) => !empty($id)));
            if (!empty($sanitizedEstimateIds)) {
                global $wpdb;
                $placeholders = implode(',', array_fill(0, count($sanitizedEstimateIds), '%s'));
                $query = $wpdb->prepare(
                    "SELECT estimate_id, location_id FROM {$wpdb->prefix}ca_estimate_snapshots WHERE estimate_id IN ($placeholders)",
                    ...$sanitizedEstimateIds
                );
                $results = $wpdb->get_results($query, ARRAY_A);
                
                // Check for database errors
                if ($wpdb->last_error) {
                    if (function_exists('error_log')) {
                        error_log(sprintf(
                            '[CheapAlarms] Database error in bulkRestore: %s',
                            $wpdb->last_error
                        ));
                    }
                    // Continue with empty map - will result in errors for affected estimates
                } elseif (is_array($results)) {
                    foreach ($results as $row) {
                        if (!empty($row['estimate_id']) && !empty($row['location_id'])) {
                            $locationIdMap[$row['estimate_id']] = $row['location_id'];
                        }
                    }
                }
            }
        }

        // PHASE 2: Process in batches of 100 for better performance
        $batchSize = 100;
        $batches = array_chunk($estimateIds, $batchSize);

        foreach ($batches as $batch) {
            foreach ($batch as $estimateId) {
                $estimateId = sanitize_text_field($estimateId);
                if (empty($estimateId)) {
                    continue;
                }

                // Get locationId from request, batch map, or skip if not found
                $locationId = $requestLocationId ?? ($locationIdMap[$estimateId] ?? null);
                
                if (!$locationId) {
                    $errors[] = ['estimateId' => $estimateId, 'error' => 'Location ID not found'];
                    continue;
                }
                
                $result = $this->snapshotRepo->restore($estimateId, $locationId, $user->ID ?? 0);
                if (is_wp_error($result)) {
                    $errors[] = ['estimateId' => $estimateId, 'error' => $result->get_error_message()];
                } else {
                    $restored++;
                }
            }
        }

        return $this->respond([
            'ok' => true,
            'restored' => $restored,
            'total' => count($estimateIds),
            'errors' => $errors,
        ]);
    }

    /**
     * POST /ca/v1/admin/estimates/bulk-delete
     * Permanently delete multiple estimates (moves to trash for local scope)
     */
    public function bulkDelete(WP_REST_Request $request): WP_REST_Response
    {
        $gateCheck = $this->checkDestructiveActionsEnabled();
        if ($gateCheck) {
            return $this->respond($gateCheck);
        }

        $body = $request->get_json_params() ?? [];
        $confirm = sanitize_text_field($body['confirm'] ?? '');
        $estimateIds = $body['estimateIds'] ?? [];
        $scope = sanitize_text_field($body['scope'] ?? 'both');
        $requestLocationId = !empty($body['locationId']) ? sanitize_text_field($body['locationId']) : null;

        if ($confirm !== 'BULK_DELETE') {
            return $this->respond(new WP_Error('bad_request', __('Confirmation required. Set confirm="BULK_DELETE"', 'cheapalarms'), ['status' => 400]));
        }

        if (!is_array($estimateIds) || empty($estimateIds)) {
            return $this->respond(new WP_Error('bad_request', __('estimateIds array is required', 'cheapalarms'), ['status' => 400]));
        }

        if (!in_array($scope, ['local', 'ghl', 'both'], true)) {
            return $this->respond(new WP_Error('bad_request', __('Invalid scope. Must be: local, ghl, or both.', 'cheapalarms'), ['status' => 400]));
        }

        // Validate each ID is a valid string/numeric
        foreach ($estimateIds as $id) {
            if (!is_string($id) && !is_numeric($id)) {
                return $this->respond(new WP_Error('bad_request', __('Invalid estimate ID format. All IDs must be strings or numbers.', 'cheapalarms'), ['status' => 400]));
            }
        }

        // Limit batch size for performance
        $maxBatchSize = 1000;
        if (count($estimateIds) > $maxBatchSize) {
            return $this->respond(new WP_Error('bad_request', sprintf(__('Maximum %d estimates per batch', 'cheapalarms'), $maxBatchSize), ['status' => 400]));
        }

        $originalTimeLimit = ini_get('max_execution_time');
        @set_time_limit(300); // 5 minutes for large batches

        try {
            $user = wp_get_current_user();
            $deleted = 0;
            $errors = [];

            // PHASE 1: Batch fetch all locationIds in ONE query (prevents N+1)
            $locationIdMap = [];
            
            if (!$requestLocationId) {
                // Only batch fetch if locationId not provided in request
                $sanitizedEstimateIds = array_map('sanitize_text_field', array_filter($estimateIds, fn($id) => !empty($id)));
                if (!empty($sanitizedEstimateIds)) {
                    global $wpdb;
                    $placeholders = implode(',', array_fill(0, count($sanitizedEstimateIds), '%s'));
                    $query = $wpdb->prepare(
                        "SELECT estimate_id, location_id FROM {$wpdb->prefix}ca_estimate_snapshots WHERE estimate_id IN ($placeholders)",
                        ...$sanitizedEstimateIds
                    );
                    $results = $wpdb->get_results($query, ARRAY_A);
                    
                    // Check for database errors
                    if ($wpdb->last_error) {
                        if (function_exists('error_log')) {
                            error_log(sprintf(
                                '[CheapAlarms] Database error in bulkDelete: %s',
                                $wpdb->last_error
                            ));
                        }
                        // Continue with empty map - will result in errors for affected estimates
                    } elseif (is_array($results)) {
                        foreach ($results as $row) {
                            if (!empty($row['estimate_id']) && !empty($row['location_id'])) {
                                $locationIdMap[$row['estimate_id']] = $row['location_id'];
                            }
                        }
                    }
                }
            }

            // PHASE 2: Process in batches of 100 for better performance
            $batchSize = 100;
            $batches = array_chunk($estimateIds, $batchSize);

            foreach ($batches as $batch) {
                foreach ($batch as $estimateId) {
                    $estimateId = sanitize_text_field($estimateId);
                    if (empty($estimateId)) {
                        continue;
                    }

                    // Get locationId from request, batch map, or skip if not found
                    $locationId = $requestLocationId ?? ($locationIdMap[$estimateId] ?? null);
                    
                    if (!$locationId && ($scope === 'ghl' || $scope === 'both')) {
                        $errors[] = ['estimateId' => $estimateId, 'error' => 'Location ID not found'];
                        continue;
                    }

                    // Create a mock request for deleteEstimate logic
                    $deleteRequest = new WP_REST_Request('POST', '/ca/v1/admin/estimates/' . $estimateId . '/delete');
                    $deleteRequest->set_param('estimateId', $estimateId);
                    // Set body as JSON string so get_json_params() can parse it
                    $deleteRequest->set_body(wp_json_encode([
                        'confirm' => 'DELETE',
                        'scope' => $scope,
                        'locationId' => $locationId,
                    ]));
                    $deleteRequest->set_header('Content-Type', 'application/json');

                    // Call the existing deleteEstimate method
                    $result = $this->deleteEstimate($deleteRequest);
                    
                    // deleteEstimate always returns WP_REST_Response (never raw WP_Error)
                    $responseData = $result->get_data();
                    if (isset($responseData['ok']) && $responseData['ok'] === true) {
                        $deleted++;
                    } else {
                        $errors[] = ['estimateId' => $estimateId, 'error' => $responseData['error'] ?? 'Delete failed'];
                    }
                }
            }

            return $this->respond([
                'ok' => true,
                'deleted' => $deleted,
                'errors' => $errors,
                'scope' => $scope,
            ]);
        } finally {
            // Always restore original time limit
            if ($originalTimeLimit !== false && $originalTimeLimit !== '0') {
                @set_time_limit((int)$originalTimeLimit);
            }
        }
    }

    /**
     * Delete estimate from WordPress (local delete - now soft delete).
     * 
     * IMPORTANT: For MVP, only allows scope='local' in this method.
     * GHL deletion is handled separately in parent deleteEstimate() method.
     *
     * @param string $estimateId
     * @param string $scope 'local', 'ghl', 'both', or 'orphan_cleanup' (for MVP, only 'local' is used here)
     * @param string $locationId Location ID (required for location-scoped soft delete)
     * @return array|WP_Error
     */
    private function deleteEstimateLocal(string $estimateId, string $scope = 'local', string $locationId = '')
    {
        global $wpdb;

        // For MVP: Only allow scope='local' in this method (GHL deletion handled separately)
        if ($scope !== 'local' && $scope !== 'orphan_cleanup') {
            $scope = 'local'; // Override to 'local' for clarity
        }

        if (empty($locationId)) {
            return new WP_Error('bad_request', 'locationId is required for soft delete', ['status' => 400]);
        }

        $alreadyDeleted = true;
        $deleted = [];

        // 1. Soft delete snapshot rows (instead of hard delete)
        $user = wp_get_current_user();
        $snapshotResult = $this->snapshotRepo->softDelete(
            $estimateId,
            $locationId,
            $user->ID ?? 0,
            $scope,
            null
        );
        
        if (is_wp_error($snapshotResult)) {
            // Check if it's already deleted (409) - that's okay
            if ($snapshotResult->get_error_code() === 'already_deleted') {
                // Already soft-deleted, that's fine
            } else {
                // Log but don't fail if snapshot soft delete fails (might not exist)
                error_log('Failed to soft delete snapshot for estimate ' . $estimateId . ': ' . $snapshotResult->get_error_message());
            }
        } else {
            $alreadyDeleted = false;
            $deleted[] = 'snapshots';
        }

        // 2. Delete portal meta option (hard delete - not source of truth)
        $optionName = 'ca_portal_meta_' . $estimateId;
        $metaDeleted = delete_option($optionName);
        if ($metaDeleted) {
            $alreadyDeleted = false;
            $deleted[] = 'portal_meta';
        }

        // 3. Clean up user meta linkage (find users with this estimateId)
        $userIds = $wpdb->get_col($wpdb->prepare(
            "SELECT user_id FROM {$wpdb->usermeta} 
             WHERE meta_key = 'ca_estimate_ids' 
             AND meta_value LIKE %s",
            '%' . $wpdb->esc_like($estimateId) . '%'
        ));

        // PHASE 1: Batch fetch all user meta in ONE query (prevents N+1)
        $userMetaMap = [];
        if (!empty($userIds)) {
            $placeholders = implode(',', array_fill(0, count($userIds), '%d'));
            $query = $wpdb->prepare(
                "SELECT user_id, meta_key, meta_value FROM {$wpdb->usermeta} 
                 WHERE user_id IN ($placeholders) 
                 AND meta_key IN ('ca_estimate_ids', 'ca_estimate_locations')",
                ...$userIds
            );
            $results = $wpdb->get_results($query, ARRAY_A);
            
            // Check for database errors
            if ($wpdb->last_error) {
                if (function_exists('error_log')) {
                    error_log(sprintf(
                        '[CheapAlarms] Database error in deleteEstimateLocal: %s',
                        $wpdb->last_error
                    ));
                }
                // Continue with empty map - user meta cleanup will be skipped
            } elseif (is_array($results)) {
                foreach ($results as $row) {
                    $userId = (int)$row['user_id'];
                    $metaKey = $row['meta_key'];
                    $metaValue = $row['meta_value'];
                    
                    if (!isset($userMetaMap[$userId])) {
                        $userMetaMap[$userId] = [];
                    }
                    
                    if ($metaKey === 'ca_estimate_ids') {
                        $decoded = maybe_unserialize($metaValue);
                        $userMetaMap[$userId]['estimate_ids'] = is_array($decoded) ? $decoded : [];
                    } elseif ($metaKey === 'ca_estimate_locations') {
                        $decoded = maybe_unserialize($metaValue);
                        $userMetaMap[$userId]['locations'] = is_array($decoded) ? $decoded : [];
                    }
                }
            }
        }

        // PHASE 2: Process users with pre-fetched meta
        foreach ($userIds as $userId) {
            $userId = (int)$userId;
            
            // Skip invalid user IDs
            if ($userId <= 0) {
                continue;
            }
            
            $estimateIds = $userMetaMap[$userId]['estimate_ids'] ?? [];
            $locations = $userMetaMap[$userId]['locations'] ?? [];
            
            // Clean up ca_estimate_ids
            if (is_array($estimateIds)) {
                $estimateIds = array_filter($estimateIds, fn($id) => $id !== $estimateId);
                update_user_meta($userId, 'ca_estimate_ids', array_values($estimateIds));
            }

            // Also clean up ca_estimate_locations
            if (is_array($locations) && isset($locations[$estimateId])) {
                unset($locations[$estimateId]);
                update_user_meta($userId, 'ca_estimate_locations', $locations);
            }
        }

        return [
            'ok' => true,
            'alreadyDeleted' => $alreadyDeleted && empty($deleted),
            'deleted' => $deleted,
        ];
    }

    /**
     * Complete deletion by email - deletes contact, estimates, invoices, metadata, and WordPress user
     * Hard delete - no trash, everything is permanently removed
     * 
     * @param WP_REST_Request $request
     * @return WP_REST_Response
     */
    public function deleteByEmail(WP_REST_Request $request): WP_REST_Response
    {
        // Safety gate
        $gateCheck = $this->checkDestructiveActionsEnabled();
        if ($gateCheck) {
            return $this->respond($gateCheck);
        }

        // SECURITY: Rate limit destructive operations to prevent abuse
        $rateCheck = $this->auth->enforceRateLimit('delete_by_email', 5, 300); // 5 requests per 5 minutes
        if (is_wp_error($rateCheck)) {
            return $this->respond($rateCheck);
        }

        // Increase execution time limit for large deletions
        $originalTimeLimit = ini_get('max_execution_time');
        @set_time_limit(300); // 5 minutes for large deletions

        try {
            $body = $request->get_json_params() ?? [];
            // Trim email before sanitization (best practice)
            $email = trim(sanitize_email($body['email'] ?? ''));
            $confirm = sanitize_text_field($body['confirm'] ?? '');
            $locationId = $this->resolveLocationIdOptional($request) ?: sanitize_text_field($body['locationId'] ?? '');

            // Validation - use filter_var for additional security (best practice)
            if (empty($email)) {
                return $this->respond(new WP_Error('bad_request', __('Email is required.', 'cheapalarms'), ['status' => 400]));
            }
            
            // Double-validate email format (sanitize_email + filter_var for extra security)
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                return $this->respond(new WP_Error('bad_request', __('Invalid email format.', 'cheapalarms'), ['status' => 400]));
            }

            if ($confirm !== 'DELETE_ALL') {
                return $this->respond(new WP_Error('bad_request', __('Confirmation required. Set confirm="DELETE_ALL" in request body.', 'cheapalarms'), ['status' => 400]));
            }

            if (empty($locationId)) {
                $locationId = $this->container->get(\CheapAlarms\Plugin\Config\Config::class)->getLocationId();
                if (empty($locationId)) {
                    return $this->respond(new WP_Error('missing_location', __('locationId is required.', 'cheapalarms'), ['status' => 400]));
                }
            }

            $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
            $currentUser = wp_get_current_user();
            $correlationId = wp_generate_password(12, false);

            $logger->info('Complete delete by email initiated', [
                'correlationId' => $correlationId,
                'email' => $email,
                'locationId' => $locationId,
                'deletedByUserId' => $currentUser->ID ?? null,
                'deletedByUserEmail' => $currentUser->user_email ?? null,
            ]);

            $result = [
                'ok' => true,
                'correlationId' => $correlationId,
                'email' => $email,
                'contact' => ['ok' => false, 'found' => false, 'deleted' => false],
                'estimates' => ['ok' => false, 'found' => 0, 'deleted' => 0, 'errors' => []],
                'invoices' => ['ok' => false, 'found' => 0, 'deleted' => 0, 'errors' => []],
                'metadata' => ['ok' => false, 'cleaned' => 0],
                'wordpressUser' => ['ok' => false, 'found' => false, 'deleted' => false],
            ];

            $ghlClient = $this->container->get(\CheapAlarms\Plugin\Services\GhlClient::class);

            // Step 1: Find contact by email
            // Note: Continue even if contact search fails - estimates/invoices may still exist
            $contactId = $this->findContactIdByEmail($email, $locationId, $ghlClient);
            if (is_wp_error($contactId)) {
                $result['contact']['error'] = $contactId->get_error_message();
                $logger->warning('Contact search failed, continuing with estimates/invoices deletion', [
                    'correlationId' => $correlationId,
                    'email' => $email,
                    'error' => $contactId->get_error_message(),
                ]);
                // Don't return early - continue to delete estimates/invoices that may exist
                $contactId = null;
            } else if ($contactId) {
                $result['contact']['found'] = true;
                $result['contact']['contactId'] = $contactId;
            }

            // Step 2 & 3: Find all estimates and invoices for this contact (using helper)
            $estimateResult = $this->findItemIdsByContact($contactId, $locationId, '/invoices/estimate/list', $ghlClient);
            $estimateIds = $estimateResult['ids'];
            $result['estimates']['found'] = count($estimateIds);
            $result['estimates']['estimateIds'] = $estimateIds;
            $result['estimates']['errors'] = $estimateResult['errors'];

            $invoiceResult = $this->findItemIdsByContact($contactId, $locationId, '/invoices/', $ghlClient);
            $invoiceIds = $invoiceResult['ids'];
            $result['invoices']['found'] = count($invoiceIds);
            $result['invoices']['invoiceIds'] = $invoiceIds;
            $result['invoices']['errors'] = $invoiceResult['errors'];

            // Check batch size limits to prevent timeouts
            $maxBatchSize = 1000; // Reasonable limit to prevent timeouts
            if (count($estimateIds) > $maxBatchSize || count($invoiceIds) > $maxBatchSize) {
                return $this->respond(new WP_Error(
                    'too_many_items',
                    sprintf(
                        __('Too many items to delete (max %d). Found %d estimates and %d invoices. Please contact support or delete in smaller batches.', 'cheapalarms'),
                        $maxBatchSize,
                        count($estimateIds),
                        count($invoiceIds)
                    ),
                    [
                        'status' => 400,
                        'estimatesFound' => count($estimateIds),
                        'invoicesFound' => count($invoiceIds),
                        'maxBatchSize' => $maxBatchSize,
                    ]
                ));
            }

            // Step 4 & 5: Delete all estimates and invoices (using helper)
            $this->deleteItemsByIds($estimateIds, 'estimate', $locationId, $result);
            $this->deleteItemsByIds($invoiceIds, 'invoice', $locationId, $result);

            // Step 6: Delete contact from GHL
            if ($contactId) {
                $ghlResult = $ghlClient->delete(
                    '/contacts/' . rawurlencode($contactId),
                    [],
                    $locationId,
                    10,
                    0
                );

                if (is_wp_error($ghlResult)) {
                    $result['contact']['error'] = $ghlResult->get_error_message();
                } else {
                    $result['contact']['deleted'] = true;
                    $result['contact']['ok'] = true;
                }
            }

            // Step 7: Clean up ALL metadata (using helper)
            $metadataCleaned = $this->cleanupEstimateMetadata($estimateIds);
            $result['metadata']['cleaned'] = $metadataCleaned;
            $result['metadata']['ok'] = true;

            // Step 8: Delete WordPress user (using helper)
            $this->deleteWordPressUserByEmail($email, $result);

            // Mark overall success - allow partial success if contact/user doesn't exist
            // This handles cases where contact/user was already deleted but estimates/invoices remain
            $result['ok'] = (
                // Contact: ok if deleted OR not found (already deleted or never existed)
                ($result['contact']['ok'] || !$result['contact']['found']) &&
                // Estimates: all found must be deleted (or none found)
                $result['estimates']['deleted'] === $result['estimates']['found'] &&
                // Invoices: all found must be deleted (or none found)
                $result['invoices']['deleted'] === $result['invoices']['found'] &&
                // Metadata: always ok (just cleanup operation)
                $result['metadata']['ok'] &&
                // WordPress user: ok if deleted OR not found (no account exists)
                ($result['wordpressUser']['ok'] || !$result['wordpressUser']['found'])
            );

            // Add descriptive error message for partial failures
            if (!$result['ok']) {
                $errors = [];
                if ($result['contact']['found'] && !$result['contact']['ok']) {
                    $errors[] = 'Contact deletion failed' . ($result['contact']['error'] ? ': ' . $result['contact']['error'] : '');
                }
                if ($result['estimates']['deleted'] !== $result['estimates']['found']) {
                    $failed = $result['estimates']['found'] - $result['estimates']['deleted'];
                    $errors[] = sprintf('%d of %d estimate(s) failed to delete', $failed, $result['estimates']['found']);
                }
                if ($result['invoices']['deleted'] !== $result['invoices']['found']) {
                    $failed = $result['invoices']['found'] - $result['invoices']['deleted'];
                    $errors[] = sprintf('%d of %d invoice(s) failed to delete', $failed, $result['invoices']['found']);
                }
                if ($result['wordpressUser']['found'] && !$result['wordpressUser']['ok']) {
                    $errors[] = 'WordPress user deletion failed';
                }
                
                $result['error'] = !empty($errors) ? implode(', ', $errors) : 'Partial deletion completed with errors';
                $result['err'] = $result['error']; // Backward compatibility
            }

            $logger->info('Complete delete by email finished', [
                'correlationId' => $correlationId,
                'email' => $email,
                'result' => $result,
            ]);

            return $this->respond($result);
        } finally {
            // Always restore original time limit
            if ($originalTimeLimit !== false && $originalTimeLimit !== '0') {
                @set_time_limit((int)$originalTimeLimit);
            }
        }
    }

    /**
     * Find all item IDs (estimates or invoices) for a contact by paginating through GHL API
     * 
     * @param string|null $contactId Contact ID (null if not found)
     * @param string $locationId Location ID
     * @param string $endpoint GHL endpoint ('/invoices/estimate/list' or '/invoices/')
     * @param \CheapAlarms\Plugin\Services\GhlClient $ghlClient
     * @return array{ids: array, errors: array}
     */
    private function findItemIdsByContact(?string $contactId, string $locationId, string $endpoint, \CheapAlarms\Plugin\Services\GhlClient $ghlClient): array
    {
        $ids = [];
        $errors = [];
        
        if (!$contactId) {
            return ['ids' => [], 'errors' => []];
        }
        
        $offset = '0';
        $loops = 0;
        $maxLoops = 100;
        
        do {
            $loops++;
            if ($loops > $maxLoops) {
                break;
            }
            
            $query = ['altId' => $locationId, 'altType' => 'location', 'limit' => 50, 'offset' => $offset];
            $response = $ghlClient->get($endpoint, $query, 25, $locationId);
            
            if (is_wp_error($response)) {
                $errors[] = $response->get_error_message();
                break;
            }
            
            $records = $response['estimates'] ?? $response['invoices'] ?? $response['items'] ?? [];
            foreach ($records as $record) {
                $cid = $record['contact']['id'] ?? ($record['contactId'] ?? '');
                if ($cid && $cid === $contactId) {
                    $itemId = $record['id'] ?? $record['_id'] ?? $record['estimateId'] ?? $record['invoiceId'] ?? null;
                    if ($itemId) {
                        $ids[] = $itemId;
                    }
                }
            }
            
            $next = $response['nextOffset'] ?? ($response['meta']['nextOffset'] ?? null);
            $offset = $next ? (string)$next : null;
        } while ($offset !== null);
        
        return ['ids' => $ids, 'errors' => $errors];
    }

    /**
     * Delete multiple items (estimates or invoices) by ID
     * 
     * @param array $itemIds Array of item IDs to delete
     * @param string $type 'estimate' or 'invoice'
     * @param string $locationId Location ID
     * @param array &$result Result array to update (passed by reference)
     * @return void
     */
    private function deleteItemsByIds(array $itemIds, string $type, string $locationId, array &$result): void
    {
        $key = $type === 'estimate' ? 'estimates' : 'invoices';
        $idKey = $type === 'estimate' ? 'estimateId' : 'invoiceId';
        $routePrefix = $type === 'estimate' ? '/ca/v1/admin/estimates/' : '/ca/v1/admin/invoices/';
        
        if ($type === 'estimate') {
            foreach ($itemIds as $itemId) {
                $deleteRequest = new WP_REST_Request('POST', $routePrefix . $itemId . '/delete');
                $deleteRequest->set_param($idKey, $itemId);
                $deleteRequest->set_body(wp_json_encode([
                    'confirm' => 'DELETE',
                    'scope' => 'both', // Delete from both GHL and local
                    'locationId' => $locationId,
                ]));
                $deleteRequest->set_header('Content-Type', 'application/json');
                
                $deleteResult = $this->deleteEstimate($deleteRequest);
                $responseData = $deleteResult->get_data();
                
                if (isset($responseData['ok']) && $responseData['ok'] === true) {
                    $result[$key]['deleted']++;
                } else {
                    $result[$key]['errors'][] = [
                        $idKey => $itemId,
                        'error' => $responseData['error'] ?? 'Delete failed',
                        'code' => $responseData['code'] ?? null,
                        'details' => $responseData['details'] ?? null,
                    ];
                }
            }
        } else {
            // Instantiate AdminInvoiceController directly (controllers are not registered in container)
            $invoiceController = new AdminInvoiceController($this->container);
            foreach ($itemIds as $itemId) {
                $deleteRequest = new WP_REST_Request('POST', $routePrefix . $itemId . '/delete');
                $deleteRequest->set_param($idKey, $itemId);
                $deleteRequest->set_body(wp_json_encode([
                    'confirm' => 'DELETE',
                    'scope' => 'both', // Delete from both GHL and local
                    'locationId' => $locationId,
                ]));
                $deleteRequest->set_header('Content-Type', 'application/json');
                
                $deleteResult = $invoiceController->deleteInvoice($deleteRequest);
                $responseData = $deleteResult->get_data();
                
                if (isset($responseData['ok']) && $responseData['ok'] === true) {
                    $result[$key]['deleted']++;
                } else {
                    $result[$key]['errors'][] = [
                        $idKey => $itemId,
                        'error' => $responseData['error'] ?? 'Delete failed',
                        'code' => $responseData['code'] ?? null,
                        'details' => $responseData['details'] ?? null,
                    ];
                }
            }
        }
        
        // Set ok flag based on deletion results (all found items must be deleted successfully)
        // Compare against 'found' (set earlier) for clarity and consistency
        if ($result[$key]['found'] > 0) {
            $result[$key]['ok'] = $result[$key]['deleted'] === $result[$key]['found'] && empty($result[$key]['errors']);
        } else {
            // No items to delete = success (nothing to do)
            $result[$key]['ok'] = true;
        }
    }

    /**
     * Clean up all metadata for estimates (portal meta, uploads metadata, snapshots)
     * 
     * @param array $estimateIds Array of estimate IDs
     * @return int Number of metadata items cleaned
     */
    private function cleanupEstimateMetadata(array $estimateIds): int
    {
        global $wpdb;
        $metadataCleaned = 0;

        // Delete portal meta and uploads metadata in a single loop
        foreach ($estimateIds as $estimateId) {
            if (delete_option('ca_portal_meta_' . $estimateId)) {
                $metadataCleaned++;
            }
            if (delete_option('ca_estimate_uploads_' . $estimateId)) {
                $metadataCleaned++;
            }
        }

        // Hard delete snapshots (bypass soft delete)
        // Batch delete for very large sets to prevent SQL query size issues
        if (!empty($estimateIds)) {
            $tableName = $wpdb->prefix . 'ca_estimate_snapshots';
            $sqlBatchSize = 1000; // MySQL has limits on query size
            
            if (count($estimateIds) <= $sqlBatchSize) {
                // Single query for small sets
                $placeholders = implode(',', array_fill(0, count($estimateIds), '%s'));
                $deleted = $wpdb->query($wpdb->prepare(
                    "DELETE FROM {$tableName} WHERE estimate_id IN ($placeholders)",
                    ...$estimateIds
                ));
                if ($deleted !== false) {
                    $metadataCleaned += $deleted;
                }
            } else {
                // Batch delete for very large sets
                $batches = array_chunk($estimateIds, $sqlBatchSize);
                foreach ($batches as $batch) {
                    $placeholders = implode(',', array_fill(0, count($batch), '%s'));
                    $deleted = $wpdb->query($wpdb->prepare(
                        "DELETE FROM {$tableName} WHERE estimate_id IN ($placeholders)",
                        ...$batch
                    ));
                    if ($deleted !== false) {
                        $metadataCleaned += $deleted;
                    }
                }
            }
        }

        return $metadataCleaned;
    }

    /**
     * Delete WordPress user by email
     * 
     * @param string $email Email address
     * @param array &$result Result array to update (passed by reference)
     * @return void
     */
    private function deleteWordPressUserByEmail(string $email, array &$result): void
    {
        $userId = email_exists($email);
        if ($userId) {
            $user = get_user_by('id', $userId);
            
            // Safety: Never delete admin users
            if ($user && !user_can($user, 'manage_options')) {
                // Delete all user meta first
                delete_user_meta($userId, 'ca_estimate_ids');
                delete_user_meta($userId, 'ca_estimate_locations');
                delete_user_meta($userId, 'ghl_contact_id');
                delete_user_meta($userId, 'ca_password_set_at');
                delete_user_meta($userId, 'ca_last_login');
                
                // Hard delete user (no trash)
                if (!function_exists('wp_delete_user')) {
                    require_once ABSPATH . 'wp-admin/includes/user.php';
                }
                $deleted = wp_delete_user($userId, true); // true = reassign to admin (or delete if no reassign)
                
                if ($deleted) {
                    $result['wordpressUser']['deleted'] = true;
                    $result['wordpressUser']['ok'] = true;
                }
            }
            $result['wordpressUser']['found'] = true;
        }
    }

    /**
     * Helper to find contact ID by email (replicates EstimateService logic)
     * 
     * @param string $email
     * @param string $locationId
     * @param \CheapAlarms\Plugin\Services\GhlClient $ghlClient
     * @return string|WP_Error|null
     */
    private function findContactIdByEmail(string $email, string $locationId, \CheapAlarms\Plugin\Services\GhlClient $ghlClient)
    {
        $response = $ghlClient->get('/contacts/search', [
            'locationId' => $locationId,
            'query'      => $email,
        ], 20, $locationId);

        if (is_wp_error($response)) {
            return $response;
        }

        $contacts = $response['contacts'] ?? $response['items'] ?? [];
        foreach ($contacts as $contact) {
            $contactEmail = $contact['email'] ?? '';
            if ($contactEmail && strcasecmp($contactEmail, $email) === 0) {
                return $contact['id'] ?? null;
            }
        }

        return null;
    }

}

