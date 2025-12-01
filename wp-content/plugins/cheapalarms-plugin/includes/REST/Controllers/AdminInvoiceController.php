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

        register_rest_route('ca/v1', '/admin/invoices/(?P<invoiceId>[a-zA-Z0-9]+)', [
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

        register_rest_route('ca/v1', '/admin/invoices/(?P<invoiceId>[a-zA-Z0-9]+)/sync', [
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

        register_rest_route('ca/v1', '/admin/invoices/(?P<invoiceId>[a-zA-Z0-9]+)/send', [
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
        $out   = [];

        // For each invoice, find linked estimate from portal meta
        foreach ($items as $item) {
            $invoiceId = $item['id'] ?? null;
            if (!$invoiceId) {
                continue;
            }

            // Apply search filter
            if ($search) {
                $searchLower = strtolower($search);
                $matches = false;
                $matches = $matches || (isset($item['invoiceNumber']) && stripos((string)$item['invoiceNumber'], $search) !== false);
                $matches = $matches || (isset($item['contactName']) && stripos($item['contactName'], $search) !== false);
                $matches = $matches || (isset($item['contactEmail']) && stripos($item['contactEmail'], $search) !== false);
                if (!$matches) {
                    continue;
                }
            }

            // Find linked estimate by searching portal meta
            $linkedEstimateId = $this->findEstimateIdByInvoiceId($invoiceId);
            
            // Get portal status from linked estimate meta
            $portalStatus = 'sent';
            if ($linkedEstimateId) {
                $meta = $this->getPortalMeta($linkedEstimateId);
                if (!empty($meta)) {
                    $portalStatus = $meta['invoice']['status'] ?? $meta['quote']['status'] ?? 'sent';
                }
            }

            $out[] = [
                'id'                => $invoiceId,
                'invoiceNumber'     => $item['invoiceNumber'] ?? null,
                'contactName'       => $item['contactName'] ?? '',
                'contactEmail'      => $item['contactEmail'] ?? '',
                'total'             => $item['total'] ?? 0,
                'amountDue'         => $item['amountDue'] ?? 0,
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
        
        // Try to find estimate ID from portal meta
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
            'amountDue'     => $invoice['amountDue'] ?? 0,
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

}

