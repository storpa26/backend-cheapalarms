<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\InvoiceService;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

use function get_option;
use function sanitize_text_field;

class AdminInvoiceController implements ControllerInterface
{
    private InvoiceService $invoiceService;
    private Authenticator $auth;

    public function __construct(private Container $container)
    {
        $this->invoiceService = $this->container->get(InvoiceService::class);
        $this->auth           = $this->container->get(Authenticator::class);
    }

    public function register(): void
    {
        register_rest_route('ca/v1', '/admin/invoices', [
            'methods'             => 'GET',
            'permission_callback' => fn () => true, // Let request through, check auth in callback
            'callback'            => function (WP_REST_Request $request) {
                // Ensure user is loaded (same as debug endpoint)
                global $current_user;
                $current_user = null;
                wp_get_current_user();
                
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
                // Ensure user is loaded (same as debug endpoint)
                global $current_user;
                $current_user = null;
                wp_get_current_user();
                
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
                // Ensure user is loaded (same as debug endpoint)
                global $current_user;
                $current_user = null;
                wp_get_current_user();
                
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
    }

    /**
     * List invoices with filters and pagination.
     */
    public function listInvoices(WP_REST_Request $request): WP_REST_Response
    {
        $locationId = sanitize_text_field($request->get_param('locationId') ?? '');
        $search    = sanitize_text_field($request->get_param('search') ?? '');
        $status    = sanitize_text_field($request->get_param('status') ?? '');
        $page      = max(1, (int)($request->get_param('page') ?? 1));
        $pageSize  = max(1, min(100, (int)($request->get_param('pageSize') ?? 20)));

        // Use config default if locationId not provided
        if (empty($locationId)) {
            $config = $this->container->get(\CheapAlarms\Plugin\Config\Config::class);
            $locationId = $config->getLocationId();
        }

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

            $out[] = [
                'id'                => $invoiceId,
                'invoiceNumber'     => $item['invoiceNumber'] ?? null,
                'contactName'       => $item['contactName'] ?? '',
                'contactEmail'      => $item['contactEmail'] ?? '',
                'total'             => $item['total'] ?? 0,
                'amountDue'         => $item['amountDue'] ?? 0,
                'currency'          => $item['currency'] ?? 'AUD',
                'status'            => $item['status'] ?? 'draft',
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
        $locationId = sanitize_text_field($request->get_param('locationId') ?? '');

        // Use config default if locationId not provided
        if (empty($locationId)) {
            $config = $this->container->get(\CheapAlarms\Plugin\Config\Config::class);
            $locationId = $config->getLocationId();
        }

        // Fetch invoice from GHL
        $invoice = $this->invoiceService->getInvoice($invoiceId, $locationId);
        if (is_wp_error($invoice)) {
            return $this->respond($invoice);
        }

        // Find linked estimate
        $linkedEstimateId = $this->findEstimateIdByInvoiceId($invoiceId);
        $linkedEstimate = null;
        if ($linkedEstimateId) {
            // Get basic estimate info from portal meta
            $meta = $this->getPortalMeta($linkedEstimateId);
            if (!empty($meta)) {
                $linkedEstimate = [
                    'id'             => $linkedEstimateId,
                    'estimateNumber' => $meta['quote']['number'] ?? $linkedEstimateId,
                ];
            }
        }

        return $this->respond([
            'ok'            => true,
            'id'            => $invoice['id'] ?? $invoiceId,
            'invoiceNumber' => $invoice['invoiceNumber'] ?? null,
            'title'         => $invoice['title'] ?? 'INVOICE',
            'status'        => $invoice['status'] ?? 'draft',
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
        ]);
    }

    /**
     * Sync invoice by re-fetching from GHL.
     */
    public function syncInvoice(WP_REST_Request $request): WP_REST_Response
    {
        $invoiceId = sanitize_text_field($request->get_param('invoiceId'));
        $locationId = sanitize_text_field($request->get_param('locationId') ?? '');

        // Use config default if locationId not provided
        if (empty($locationId)) {
            $config = $this->container->get(\CheapAlarms\Plugin\Config\Config::class);
            $locationId = $config->getLocationId();
        }

        // Re-fetch from GHL
        $invoice = $this->invoiceService->syncInvoice($invoiceId, $locationId);
        if (is_wp_error($invoice)) {
            return $this->respond($invoice);
        }

        return $this->getInvoice($request); // Reuse getInvoice logic
    }

    /**
     * Find estimate ID that has this invoice ID in its portal meta.
     * This is a reverse lookup - searches all portal meta options.
     *
     * @return string|null
     */
    private function findEstimateIdByInvoiceId(string $invoiceId): ?string
    {
        global $wpdb;

        // Search all ca_portal_meta_* options for invoice.id match
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
                // Extract estimateId from option_name (ca_portal_meta_{estimateId})
                $estimateId = str_replace('ca_portal_meta_', '', $row->option_name);
                return $estimateId ?: null;
            }
        }

        return null;
    }

    /**
     * Get portal meta for an estimate.
     *
     * @return array<string, mixed>
     */
    private function getPortalMeta(string $estimateId): array
    {
        $stored = get_option('ca_portal_meta_' . $estimateId, '{}');
        $decoded = json_decode(is_string($stored) ? $stored : '{}', true);
        return is_array($decoded) ? $decoded : [];
    }

    /**
     * @param array|WP_Error $result
     */
    private function respond($result, ?WP_REST_Request $request = null): WP_REST_Response
    {
        if (is_wp_error($result)) {
            $status = $result->get_error_data()['status'] ?? 500;
            return new WP_REST_Response([
                'ok'   => false,
                'err'  => $result->get_error_message(),
                'code' => $result->get_error_code(),
            ], $status);
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

