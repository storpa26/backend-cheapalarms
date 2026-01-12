<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\REST\Controllers\Base\AdminController;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\InvoiceService;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

use function sanitize_text_field;

class AdminInvoiceController extends AdminController
{
    private InvoiceService $invoiceService;
    private Authenticator $auth;

    public function __construct(Container $container)
    {
        parent::__construct($container);
        $this->invoiceService = $this->container->get(InvoiceService::class);
        $this->auth           = $this->container->get(Authenticator::class);
    }

    public function register(): void
    {
        register_rest_route('ca/v1', '/admin/invoices', [
            'methods'             => 'GET',
            'permission_callback' => fn () => true, // Let request through, check auth in callback
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->listInvoices($request);
            },
        ]);

        // Bulk delete invoices - MUST be registered BEFORE the parameterized route
        register_rest_route('ca/v1', '/admin/invoices/bulk-delete', [
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

        register_rest_route('ca/v1', '/admin/invoices/(?P<invoiceId>[\w-]+)', [
            'methods'             => 'GET',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->getInvoice($request);
            },
            'args'                => [
                'invoiceId' => [
                    'required' => true,
                    'type'     => 'string',
                ],
            ],
        ]);

        register_rest_route('ca/v1', '/admin/invoices/(?P<invoiceId>[\w-]+)/sync', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->syncInvoice($request);
            },
            'args'                => [
                'invoiceId' => [
                    'required' => true,
                    'type'     => 'string',
                ],
            ],
        ]);

        register_rest_route('ca/v1', '/admin/invoices/(?P<invoiceId>[\w-]+)/delete', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->deleteInvoice($request);
            },
            'args'                => [
                'invoiceId' => [
                    'required' => true,
                    'type'     => 'string',
                ],
            ],
        ]);

        register_rest_route('ca/v1', '/admin/invoices/(?P<invoiceId>[\w-]+)/send', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->sendInvoice($request);
            },
            'args'                => [
                'invoiceId' => [
                    'required' => true,
                    'type'     => 'string',
                ],
            ],
        ]);

        // Configure deposit requirement for invoice
        register_rest_route('ca/v1', '/admin/invoices/(?P<invoiceId>[\w-]+)/configure-deposit', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->respond($authCheck);
                }
                return $this->configureDeposit($request);
            },
            'args'                => [
                'invoiceId' => [
                    'required' => true,
                    'type'     => 'string',
                    'validate_callback' => fn ($param) => !empty($param) && preg_match('/^[\w-]+$/', $param),
                ],
            ],
        ]);
    }

    /**
     * List invoices with filters and pagination.
     */
    public function listInvoices(WP_REST_Request $request): WP_REST_Response
    {
        $locationIdResult = $this->resolveLocationId($request);
        if (is_wp_error($locationIdResult)) {
            return $this->respond($locationIdResult);
        }
        $locationId = $locationIdResult;

        $search    = sanitize_text_field($request->get_param('search') ?? '');
        $status    = sanitize_text_field($request->get_param('status') ?? '');
        $page      = max(1, (int)($request->get_param('page') ?? 1));
        $pageSize  = max(1, min(100, (int)($request->get_param('pageSize') ?? 20)));

        $filters = [
            'limit'  => $pageSize,
            'offset' => ($page - 1) * $pageSize,
        ];
        if ($status) {
            $filters['status'] = $status;
        }

        $result = $this->invoiceService->listInvoices($locationId, $filters);
        if (is_wp_error($result)) {
            return $this->respond($result);
        }

        $items = $result['items'] ?? [];
        
        // PHASE 1: Collect all invoice IDs
        $invoiceIds = array_filter(array_map(fn($item) => $item['id'] ?? null, $items), fn($id) => !empty($id));
        
        // PHASE 2: Batch reverse lookup - find all estimate IDs for these invoices (ONE query)
        $invoiceToEstimateMap = [];
        if (!empty($invoiceIds)) {
            $invoiceToEstimateMap = $this->portalMeta->batchFindEstimateIdsByInvoiceIds($invoiceIds);
        }
        
        // PHASE 3: Collect all linked estimate IDs, normalize to strings, and batch fetch their portal meta
        $linkedEstimateIds = array_filter(
            array_map('strval', array_values($invoiceToEstimateMap)),
            fn($id) => !empty($id)
        );
        $allMeta = [];
        if (!empty($linkedEstimateIds)) {
            $allMeta = $this->portalMeta->batchGet($linkedEstimateIds);
        }

        // PHASE 4: Process invoices with pre-fetched data
        $out = [];
        foreach ($items as $item) {
            $invoiceId = $item['id'] ?? null;
            if (!$invoiceId) {
                continue;
            }

            // Apply search filter
            if ($search) {
                $matches = false;
                $matches = $matches || (isset($item['invoiceNumber']) && stripos((string)$item['invoiceNumber'], $search) !== false);
                $matches = $matches || (isset($item['contactName']) && stripos($item['contactName'], $search) !== false);
                $matches = $matches || (isset($item['contactEmail']) && stripos($item['contactEmail'], $search) !== false);
                if (!$matches) {
                    continue;
                }
            }

            // Get linked estimate ID from batch result and normalize to string
            // Normalize invoiceId to string first (map keys are normalized strings)
            $invoiceIdNormalized = (string)$invoiceId;
            $linkedEstimateId = $invoiceToEstimateMap[$invoiceIdNormalized] ?? null;
            if ($linkedEstimateId) {
                $linkedEstimateId = (string)$linkedEstimateId;
            }
            
            // Get portal status and calculate amountDue from pre-fetched meta
            $portalStatus = 'sent';
            $calculatedAmountDue = $item['amountDue'] ?? $item['total'] ?? 0;
            
            if ($linkedEstimateId && isset($allMeta[$linkedEstimateId])) {
                $meta = $allMeta[$linkedEstimateId];
                if (!empty($meta)) {
                    $portalStatus = $meta['invoice']['status'] ?? $meta['quote']['status'] ?? 'sent';
                    
                    // Calculate amountDue from payment data (portal meta takes precedence over GHL)
                    if (isset($meta['invoice']['amountDue'])) {
                        $calculatedAmountDue = (float)$meta['invoice']['amountDue'];
                    } elseif (isset($meta['payment']['remainingBalance'])) {
                        // Fallback: use payment remainingBalance if invoice amountDue not set
                        $calculatedAmountDue = (float)$meta['payment']['remainingBalance'];
                    }
                }
            }

            $out[] = [
                'id'                => $invoiceId,
                'invoiceNumber'     => $item['invoiceNumber'] ?? null,
                'contactName'       => $item['contactName'] ?? '',
                'contactEmail'      => $item['contactEmail'] ?? '',
                'total'             => $item['total'] ?? 0,
                'amountDue'         => $calculatedAmountDue,
                'currency'          => $item['currency'] ?? 'AUD',
                'ghlStatus'         => $item['status'] ?? 'draft',
                'portalStatus'      => $portalStatus,
                'linkedEstimateId'  => $linkedEstimateId,
                'createdAt'         => $item['createdAt'] ?? '',
                'updatedAt'         => $item['updatedAt'] ?? '',
            ];
        }

        return $this->respond([
            'ok'       => true,
            'items'    => $out,
            'total'    => $result['total'] ?? count($out),
            'page'     => $page,
            'pageSize' => $pageSize,
        ]);
    }

    /**
     * Get single invoice detail with linked estimate info.
     */
    public function getInvoice(WP_REST_Request $request): WP_REST_Response
    {
        $invoiceId = sanitize_text_field($request->get_param('invoiceId'));
        $locationIdResult = $this->resolveLocationId($request);
        if (is_wp_error($locationIdResult)) {
            return $this->respond($locationIdResult);
        }
        $locationId = $locationIdResult;

        // Fetch invoice from GHL
        $invoice = $this->invoiceService->getInvoice($invoiceId, $locationId);
        if (is_wp_error($invoice)) {
            return $this->respond($invoice);
        }

        // Find linked estimate - improved lookup with better error handling
        $linkedEstimateId = $this->findEstimateIdByInvoiceId($invoiceId);
        $linkedEstimate = null;
        $portalStatus = 'sent';
        
        // Try to find estimate ID from portal meta (direct lookup)
        if (!$linkedEstimateId) {
            // Fallback: search all portal meta for this invoice ID
            // This handles cases where the reverse lookup might have failed
            global $wpdb;
            $optionNamePattern = 'ca_portal_meta_%';
            $results = $wpdb->get_results($wpdb->prepare(
                "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s",
                $optionNamePattern
            ));
            
            foreach ($results as $row) {
                $meta = json_decode($row->option_value, true);
                if (!is_array($meta)) {
                    continue;
                }
                
                $metaInvoiceId = $meta['invoice']['id'] ?? null;
                if ($metaInvoiceId === $invoiceId) {
                    $linkedEstimateId = str_replace('ca_portal_meta_', '', $row->option_name);
                    break;
                }
            }
        }
        
        // Final fallback: Try to match by contact ID and date (for manually created invoices)
        // Only attempt if invoice has contact info and issue date
        $invoiceContact = $invoice['contact'] ?? [];
        $invoiceContactId = $invoiceContact['id'] ?? null;
        $invoiceDate = $invoice['issueDate'] ?? null;
        
        if (!$linkedEstimateId && $invoiceContactId && $invoiceDate) {
            // Pass EstimateService and locationId to enable contact ID verification
            $estimateService = $this->container->get(\CheapAlarms\Plugin\Services\EstimateService::class);
            $matchedEstimateId = $this->portalMeta->findEstimateIdByContactAndDate($invoiceContactId, $invoiceDate, $estimateService, $locationId);
            if ($matchedEstimateId) {
                $linkedEstimateId = $matchedEstimateId;
                // Auto-link the invoice to the estimate for future lookups
                $meta = $this->getPortalMeta($linkedEstimateId);
                if (empty($meta['invoice']['id'])) {
                    $this->updatePortalMeta($linkedEstimateId, [
                        'invoice' => [
                            'id' => $invoiceId,
                            'number' => $invoice['invoiceNumber'] ?? null,
                            'status' => $invoice['status'] ?? 'draft',
                        ]
                    ]);
                }
            }
        }
        
        // Calculate amountDue from payment data in portal meta (if available)
        $calculatedAmountDue = $invoice['amountDue'] ?? $invoice['total'] ?? 0;
        $calculatedStatus = $invoice['status'] ?? 'draft';
        
        if ($linkedEstimateId) {
            // Get basic estimate info from portal meta
            $meta = $this->getPortalMeta($linkedEstimateId);
            if (!empty($meta)) {
                $linkedEstimate = [
                    'id'             => $linkedEstimateId,
                    'estimateNumber' => $meta['quote']['number'] ?? $linkedEstimateId,
                ];
                // Get portal status from invoice meta (if stored) or estimate status
                $portalStatus = $meta['invoice']['status'] ?? $meta['quote']['status'] ?? 'sent';
                
                // Calculate amountDue from payment data (portal meta takes precedence over GHL)
                if (isset($meta['invoice']['amountDue'])) {
                    $calculatedAmountDue = (float)$meta['invoice']['amountDue'];
                } elseif (isset($meta['payment']['remainingBalance'])) {
                    // Fallback: use payment remainingBalance if invoice amountDue not set
                    $calculatedAmountDue = (float)$meta['payment']['remainingBalance'];
                }
                
                // Use portal status if available
                if (isset($meta['invoice']['status'])) {
                    $calculatedStatus = $meta['invoice']['status'];
                }
            }
        }

        return $this->respond([
            'ok'            => true,
            'id'            => $invoice['id'] ?? $invoiceId,
            'invoiceNumber' => $invoice['invoiceNumber'] ?? null,
            'title'         => $invoice['title'] ?? 'INVOICE',
            'ghlStatus'    => $invoice['status'] ?? 'draft',
            'portalStatus' => $portalStatus,
            'contact'       => $invoice['contact'] ?? [],
            'items'         => $invoice['items'] ?? [],
            'subtotal'      => $invoice['subtotal'] ?? 0,
            'tax'           => $invoice['tax'] ?? 0,
            'discount'      => $invoice['discount'] ?? 0,
            'total'         => $invoice['total'] ?? 0,
            'amountDue'     => $calculatedAmountDue,
            'currency'      => $invoice['currency'] ?? 'AUD',
            'issueDate'     => $invoice['issueDate'] ?? null,
            'dueDate'       => $invoice['dueDate'] ?? null,
            'createdAt'     => $invoice['createdAt'] ?? '',
            'updatedAt'     => $invoice['updatedAt'] ?? '',
            'payments'      => $invoice['payments'] ?? [],
            'linkedEstimate' => $linkedEstimate,
            'linkedEstimateId' => $linkedEstimateId, // Also return ID directly for easier access
        ]);
    }

    /**
     * Sync invoice by re-fetching from GHL.
     */
    public function syncInvoice(WP_REST_Request $request): WP_REST_Response
    {
        $invoiceId = sanitize_text_field($request->get_param('invoiceId'));
        $locationIdResult = $this->resolveLocationId($request);
        if (is_wp_error($locationIdResult)) {
            return $this->respond($locationIdResult);
        }
        $locationId = $locationIdResult;

        // Re-fetch from GHL
        $invoice = $this->invoiceService->syncInvoice($invoiceId, $locationId);
        if (is_wp_error($invoice)) {
            return $this->respond($invoice);
        }

        return $this->getInvoice($request); // Reuse getInvoice logic
    }

    /**
     * Send invoice via GHL.
     */
    public function sendInvoice(WP_REST_Request $request): WP_REST_Response
    {
        $invoiceId = sanitize_text_field($request->get_param('invoiceId'));
        $locationIdResult = $this->resolveLocationId($request);
        if (is_wp_error($locationIdResult)) {
            return $this->respond($locationIdResult);
        }
        $locationId = $locationIdResult;

        // Get optional send method from request body
        $body = $request->get_json_params();
        $options = $body ?? [];

        $result = $this->invoiceService->sendInvoice($invoiceId, $locationId, $options);
        if (is_wp_error($result)) {
            return $this->respond($result);
        }

        return $this->respond([
            'ok' => true,
            'message' => 'Invoice sent successfully',
        ]);
    }

    /**
     * Delete invoice with scope support (local, ghl, both).
     * Fail-closed: if scope=both and GHL delete fails, local delete is skipped.
     */
    public function deleteInvoice(WP_REST_Request $request): WP_REST_Response
    {
        // Safety gate
        $gateCheck = $this->checkDestructiveActionsEnabled();
        if ($gateCheck) {
            return $this->respond($gateCheck);
        }

        $invoiceId = sanitize_text_field($request->get_param('invoiceId'));
        $body = $request->get_json_params() ?? [];
        $scope = sanitize_text_field($body['scope'] ?? 'both');
        $confirm = sanitize_text_field($body['confirm'] ?? '');
        $locationId = $this->resolveLocationIdOptional($request) ?: sanitize_text_field($body['locationId'] ?? '');

        // Validation
        if (empty($invoiceId)) {
            return $this->respond(new WP_Error('bad_request', __('Invoice ID is required.', 'cheapalarms'), ['status' => 400]));
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

        $logger->info('Invoice delete initiated', [
            'correlationId' => $correlationId,
            'invoiceId' => $invoiceId,
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
                '/invoices/' . rawurlencode($invoiceId),
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
                    $logger->warning('Invoice delete failed (fail-closed)', [
                        'correlationId' => $correlationId,
                        'invoiceId' => $invoiceId,
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
                $logger->info('Invoice deleted from GHL', [
                    'correlationId' => $correlationId,
                    'invoiceId' => $invoiceId,
                    'alreadyDeleted' => $result['ghl']['alreadyDeleted'],
                ]);
            }
        }

        // Step 2: Local delete (if needed, and GHL succeeded or scope=local)
        if ($doLocal && !($scope === 'both' && !$result['ghl']['ok'])) {
            $localResult = $this->deleteInvoiceLocal($invoiceId);
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
                $logger->info('Invoice deleted from WordPress', [
                    'correlationId' => $correlationId,
                    'invoiceId' => $invoiceId,
                    'linkedEstimateId' => $localResult['linkedEstimateId'] ?? null,
                    'alreadyDeleted' => $result['local']['alreadyDeleted'],
                ]);
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
     * POST /ca/v1/admin/invoices/bulk-delete
     * Permanently delete multiple invoices
     */
    public function bulkDelete(WP_REST_Request $request): WP_REST_Response
    {
        $gateCheck = $this->checkDestructiveActionsEnabled();
        if ($gateCheck) {
            return $this->respond($gateCheck);
        }

        $body = $request->get_json_params() ?? [];
        $confirm = sanitize_text_field($body['confirm'] ?? '');
        $invoiceIds = $body['invoiceIds'] ?? [];
        $scope = sanitize_text_field($body['scope'] ?? 'both');
        $requestLocationId = !empty($body['locationId']) ? sanitize_text_field($body['locationId']) : null;

        if ($confirm !== 'BULK_DELETE') {
            return $this->respond(new WP_Error('bad_request', __('Confirmation required. Set confirm="BULK_DELETE"', 'cheapalarms'), ['status' => 400]));
        }

        if (!is_array($invoiceIds) || empty($invoiceIds)) {
            return $this->respond(new WP_Error('bad_request', __('invoiceIds array is required', 'cheapalarms'), ['status' => 400]));
        }

        if (!in_array($scope, ['local', 'ghl', 'both'], true)) {
            return $this->respond(new WP_Error('bad_request', __('Invalid scope. Must be: local, ghl, or both.', 'cheapalarms'), ['status' => 400]));
        }

        // Validate each ID is a valid string/numeric
        foreach ($invoiceIds as $id) {
            if (!is_string($id) && !is_numeric($id)) {
                return $this->respond(new WP_Error('bad_request', __('Invalid invoice ID format. All IDs must be strings or numbers.', 'cheapalarms'), ['status' => 400]));
            }
        }

        // Limit batch size for performance
        $maxBatchSize = 1000;
        if (count($invoiceIds) > $maxBatchSize) {
            return $this->respond(new WP_Error('bad_request', sprintf(__('Maximum %d invoices per batch', 'cheapalarms'), $maxBatchSize), ['status' => 400]));
        }

        $originalTimeLimit = ini_get('max_execution_time');
        @set_time_limit(300); // 5 minutes for large batches

        try {
            $deleted = 0;
            $errors = [];

            // Process in batches of 100 for better performance
            $batchSize = 100;
            $batches = array_chunk($invoiceIds, $batchSize);

            foreach ($batches as $batch) {
                foreach ($batch as $invoiceId) {
                    $invoiceId = sanitize_text_field($invoiceId);
                    if (empty($invoiceId)) {
                        continue;
                    }

                    // Create a mock request for deleteInvoice logic
                    $deleteRequest = new WP_REST_Request('POST', '/ca/v1/admin/invoices/' . $invoiceId . '/delete');
                    $deleteRequest->set_param('invoiceId', $invoiceId);
                    // Set body as JSON string so get_json_params() can parse it
                    $deleteRequest->set_body(wp_json_encode([
                        'confirm' => 'DELETE',
                        'scope' => $scope,
                        'locationId' => $requestLocationId,
                    ]));
                    $deleteRequest->set_header('Content-Type', 'application/json');

                    // Call the existing deleteInvoice method
                    $result = $this->deleteInvoice($deleteRequest);
                    
                    // deleteInvoice always returns WP_REST_Response (never raw WP_Error)
                    $responseData = $result->get_data();
                    if (isset($responseData['ok']) && $responseData['ok'] === true) {
                        $deleted++;
                    } else {
                        $errors[] = ['invoiceId' => $invoiceId, 'error' => $responseData['error'] ?? 'Delete failed'];
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
     * Delete invoice from WordPress (local delete).
     * Removes invoice reference from linked estimate's portal meta.
     *
     * @param string $invoiceId
     * @return array|WP_Error
     */
    private function deleteInvoiceLocal(string $invoiceId)
    {
        // Find linked estimate
        $linkedEstimateId = $this->findEstimateIdByInvoiceId($invoiceId);

        if (!$linkedEstimateId) {
            // Invoice not linked to any estimate = already "deleted" (not present in WP)
            return [
                'ok' => true,
                'alreadyDeleted' => true,
                'linkedEstimateId' => null,
            ];
        }

        // Get portal meta and remove invoice section
        $meta = $this->getPortalMeta($linkedEstimateId);
        if (empty($meta['invoice']['id']) || $meta['invoice']['id'] !== $invoiceId) {
            // Invoice ID doesn't match or not present = already unlinked
            return [
                'ok' => true,
                'alreadyDeleted' => true,
                'linkedEstimateId' => $linkedEstimateId,
            ];
        }

        // Remove invoice from meta
        unset($meta['invoice']);
        $this->portalMeta->update($linkedEstimateId, $meta);

        return [
            'ok' => true,
            'alreadyDeleted' => false,
            'linkedEstimateId' => $linkedEstimateId,
        ];
    }

    /**
     * Configure deposit requirement for invoice
     * 
     * Route: POST /ca/v1/admin/invoices/{invoiceId}/configure-deposit
     */
    public function configureDeposit(WP_REST_Request $request): WP_REST_Response
    {
        $invoiceId = sanitize_text_field($request->get_param('invoiceId'));
        $body = $request->get_json_params() ?? [];
        
        // FIXED: Route regex allows hyphens (UUIDs)
        if (empty($invoiceId) || !preg_match('/^[\w-]+$/', $invoiceId)) {
            return $this->respond(new WP_Error('bad_request', __('Invalid invoice ID.', 'cheapalarms'), ['status' => 400]));
        }
        
        $depositRequired = isset($body['depositRequired']) ? (bool)$body['depositRequired'] : false;
        $depositAmount = isset($body['depositAmount']) ? (float)$body['depositAmount'] : null;
        $depositType = sanitize_text_field($body['depositType'] ?? 'fixed');
        
        // Validate deposit type
        if ($depositType !== 'fixed' && $depositType !== 'percentage') {
            return $this->respond(new WP_Error('bad_request', __('depositType must be "fixed" or "percentage".', 'cheapalarms'), ['status' => 400]));
        }
        
        // Find linked estimate
        $estimateId = $this->findEstimateIdByInvoiceId($invoiceId);
        
        if (empty($estimateId)) {
            return $this->respond(new WP_Error('not_found', __('Estimate not found for this invoice.', 'cheapalarms'), ['status' => 404]));
        }
        
        // Get portal meta
        $meta = $this->getPortalMeta($estimateId);
        $invoiceMeta = $meta['invoice'] ?? [];
        
        // Get invoice from service to get total if not in meta
        $invoice = $this->invoiceService->getInvoice($invoiceId, '');
        $invoiceTotal = 0;
        if (!is_wp_error($invoice)) {
            $invoiceTotal = $invoice['total'] ?? 0;
        }
        
        // Calculate deposit amount if percentage (store as fixed value)
        if ($depositRequired && $depositType === 'percentage' && $depositAmount !== null) {
            $invoiceTotal = $invoiceMeta['total'] ?? $invoiceMeta['ghl']['total'] ?? $invoiceTotal;
            if ($invoiceTotal <= 0) {
                return $this->respond(new WP_Error('bad_request', __('Invoice total must be greater than zero to calculate percentage deposit.', 'cheapalarms'), ['status' => 400]));
            }
            $depositAmount = ($invoiceTotal * $depositAmount) / 100;
        }
        
        // Validate deposit amount
        if ($depositRequired && ($depositAmount === null || $depositAmount <= 0)) {
            return $this->respond(new WP_Error('bad_request', __('Deposit amount must be greater than zero.', 'cheapalarms'), ['status' => 400]));
        }
        
        // Update invoice meta
        $invoiceUpdate = array_merge($invoiceMeta, [
            'depositRequired' => $depositRequired,
            'depositAmount' => $depositRequired ? $depositAmount : null,
            'depositType' => $depositRequired ? $depositType : null,
        ]);
        
        $this->updatePortalMeta($estimateId, [
            'invoice' => $invoiceUpdate,
        ]);
        
        return $this->respond([
            'ok' => true,
            'invoiceId' => $invoiceId,
            'estimateId' => $estimateId,
            'depositRequired' => $depositRequired,
            'depositAmount' => $depositAmount,
            'depositType' => $depositType,
        ]);
    }

}

