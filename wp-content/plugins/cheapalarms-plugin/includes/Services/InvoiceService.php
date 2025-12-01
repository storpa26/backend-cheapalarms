<?php

namespace CheapAlarms\Plugin\Services;

use CheapAlarms\Plugin\Config\Config;
use CheapAlarms\Plugin\Services\Logger;
use WP_Error;

use function sanitize_text_field;

class InvoiceService
{
    public function __construct(
        private Config $config,
        private GhlClient $client,
        private Logger $logger
    ) {
    }

    /**
     * List invoices from GHL with optional filters.
     *
     * @param string $locationId Location ID (defaults to config)
     * @param array<string, mixed> $filters Optional filters (search, status, limit, offset)
     * @return array|WP_Error
     */
    public function listInvoices(string $locationId = '', array $filters = [])
    {
        $locationId = $locationId ?: $this->config->getLocationId();
        if (!$locationId) {
            return new WP_Error('missing_location', __('Location ID is required.', 'cheapalarms'), ['status' => 400]);
        }

        $limit  = max(1, min(100, (int)($filters['limit'] ?? 20)));
        $offset = max(0, (int)($filters['offset'] ?? 0));

        // Build query params - GHL invoice list endpoint
        // GHL requires altId and altType for multi-location accounts (same as estimates)
        $query = [
            'altId'   => $locationId,
            'altType' => 'location',
            'limit'   => $limit,
            'offset'  => $offset,
        ];

        // Add status filter if provided
        if (!empty($filters['status'])) {
            $query['status'] = sanitize_text_field($filters['status']);
        }

        $response = $this->client->get('/invoices/', $query, 25, $locationId);
        if (is_wp_error($response)) {
            return $response;
        }

        $invoices = $response['invoices'] ?? $response['items'] ?? [];
        $out      = [];

        foreach ($invoices as $invoice) {
            $invoiceId = $invoice['id'] ?? $invoice['_id'] ?? $invoice['invoiceId'] ?? null;
            if (!$invoiceId) {
                continue;
            }

            $contact = $invoice['contact'] ?? $invoice['contactDetails'] ?? [];
            $contactName = $contact['name'] ?? ($contact['firstName'] . ' ' . ($contact['lastName'] ?? '')) ?? '';
            $contactEmail = $contact['email'] ?? '';

            $out[] = [
                'id'            => $invoiceId,
                'invoiceNumber' => $invoice['invoiceNumber'] ?? $invoice['number'] ?? null,
                'contactName'   => trim($contactName),
                'contactEmail'  => $contactEmail,
                'total'         => (float)($invoice['total'] ?? 0),
                'amountDue'     => (float)($invoice['amountDue'] ?? $invoice['total'] ?? 0),
                'currency'      => $invoice['currency'] ?? 'AUD',
                'status'        => $invoice['status'] ?? 'draft',
                'createdAt'     => $invoice['createdAt'] ?? '',
                'updatedAt'     => $invoice['updatedAt'] ?? '',
                'dueDate'       => $invoice['dueDate'] ?? null,
            ];
        }

        return [
            'ok'         => true,
            'locationId' => $locationId,
            'count'      => count($out),
            'items'      => $out,
            'total'      => $response['meta']['total'] ?? count($out),
        ];
    }

    /**
     * Get a single invoice by ID.
     *
     * @param string $invoiceId Invoice ID
     * @param string $locationId Location ID (defaults to config)
     * @return array|WP_Error
     */
    public function getInvoice(string $invoiceId, string $locationId = '')
    {
        $invoiceId = sanitize_text_field($invoiceId);
        if (!$invoiceId) {
            return new WP_Error('bad_request', __('Invoice ID is required.', 'cheapalarms'), ['status' => 400]);
        }

        $locationId = $locationId ?: $this->config->getLocationId();
        if (!$locationId) {
            return new WP_Error('missing_location', __('Location ID is required.', 'cheapalarms'), ['status' => 400]);
        }

        // GHL requires altId and altType query params for multi-location accounts
        $query = [
            'altId'   => $locationId,
            'altType' => 'location',
        ];

        $response = $this->client->get('/invoices/' . rawurlencode($invoiceId), $query, 25, $locationId);
        if (is_wp_error($response)) {
            return $response;
        }

        $invoice = $response['invoice'] ?? $response;

        // Normalize invoice data
        $contact = $invoice['contact'] ?? $invoice['contactDetails'] ?? [];
        
        // Extract items - handle different GHL response structures
        $items = $invoice['items'] ?? $invoice['lineItems'] ?? $invoice['invoiceItems'] ?? [];
        
        // Ensure items is an array
        if (!is_array($items)) {
            $items = [];
        }
        
        // If items is empty but invoice has a total, log for debugging
        if (empty($items) && !empty($invoice['total']) && $invoice['total'] > 0) {
            $this->logger->warning('Invoice has total but no items', [
                'invoiceId' => $invoiceId,
                'total' => $invoice['total'],
                'raw_keys' => array_keys($invoice),
            ]);
        }

        return [
            'ok'            => true,
            'id'            => $invoice['id'] ?? $invoice['_id'] ?? $invoiceId,
            'invoiceNumber' => $invoice['invoiceNumber'] ?? $invoice['number'] ?? null,
            'title'        => $invoice['title'] ?? 'INVOICE',
            'status'       => $invoice['status'] ?? 'draft',
            'contact'      => [
                'id'    => $contact['id'] ?? $contact['contactId'] ?? null,
                'name'  => $contact['name'] ?? (($contact['firstName'] ?? '') . ' ' . ($contact['lastName'] ?? '')),
                'email' => $contact['email'] ?? '',
                'phone' => $contact['phone'] ?? '',
            ],
            'items'        => $items,
            'subtotal'    => (float)($invoice['subtotal'] ?? 0),
            'tax'          => (float)($invoice['tax'] ?? 0),
            'discount'    => (float)($invoice['discount'] ?? 0),
            'total'       => (float)($invoice['total'] ?? 0),
            'amountDue'   => (float)($invoice['amountDue'] ?? $invoice['total'] ?? 0),
            'currency'    => $invoice['currency'] ?? 'AUD',
            'issueDate'   => $invoice['issueDate'] ?? null,
            'dueDate'     => $invoice['dueDate'] ?? null,
            'createdAt'   => $invoice['createdAt'] ?? '',
            'updatedAt'   => $invoice['updatedAt'] ?? '',
            'payments'    => $invoice['payments'] ?? [],
            'raw'         => $invoice,
        ];
    }

    /**
     * Sync invoice by re-fetching from GHL.
     *
     * @param string $invoiceId Invoice ID
     * @param string $locationId Location ID (defaults to config)
     * @return array|WP_Error
     */
    public function syncInvoice(string $invoiceId, string $locationId = '')
    {
        return $this->getInvoice($invoiceId, $locationId);
    }

    /**
     * Send invoice via GHL API.
     *
     * @param string $invoiceId Invoice ID
     * @param string $locationId Location ID (defaults to config)
     * @param array<string, mixed> $options Optional options (method: 'email'|'sms', etc.)
     * @return array|WP_Error
     */
    public function sendInvoice(string $invoiceId, string $locationId = '', array $options = [])
    {
        $invoiceId = sanitize_text_field($invoiceId);
        if (!$invoiceId) {
            return new WP_Error('bad_request', __('Invoice ID is required to send.', 'cheapalarms'), ['status' => 400]);
        }

        $locationId = $locationId ?: $this->config->getLocationId();
        if (!$locationId) {
            return new WP_Error('missing_location', __('Location ID is required to send invoice.', 'cheapalarms'), ['status' => 400]);
        }

        $payload = array_merge([
            'altId'   => $locationId,
            'altType' => 'location',
        ], $options);

        // GHL API: POST /invoices/{id}/send
        $response = $this->client->post(
            '/invoices/' . rawurlencode($invoiceId) . '/send',
            $payload,
            30,
            $locationId
        );

        if (is_wp_error($response)) {
            return $response;
        }

        return ['ok' => true, 'result' => $response];
    }
}

