<?php

namespace CheapAlarms\Plugin\Services\Estimate;

use CheapAlarms\Plugin\Config\Config;
use CheapAlarms\Plugin\Services\GhlClient;
use WP_Error;

use function sanitize_text_field;

/**
 * Handles invoice creation from estimates.
 */
class EstimateInvoiceService
{
    public function __construct(
        private Config $config,
        private GhlClient $client,
        private \CheapAlarms\Plugin\Services\Logger $logger,
        private EstimateNormalizer $normalizer
    ) {
    }

    /**
     * Creates an invoice directly from draft estimate data (without requiring estimate to be accepted).
     * This bypasses the "estimate must be accepted" requirement.
     *
     * @return array|WP_Error
     */
    public function createInvoiceFromDraftEstimate(string $estimateId, string $locationId, array $options = [], callable $getEstimateCallback)
    {
        // Fetch the draft estimate using callback (avoids circular dependency)
        $record = $getEstimateCallback($estimateId, $locationId);
        if (is_wp_error($record)) {
            return $record;
        }
        if (!$record) {
            return new WP_Error('not_found', __('Estimate not found.', 'cheapalarms'), ['status' => 404]);
        }

        // Extract contact details
        $contactDetails = $this->normalizer->extractContactDetails($record);
        
        // Ensure contact has an ID (required for invoice creation)
        if (empty($contactDetails['id'])) {
            // Try to find contact by email
            $contactEmail = $contactDetails['email'] ?? '';
            if ($contactEmail) {
                // This would need access to CustomerService - for now, return error
                return new WP_Error('missing_contact', __('Contact ID required to create invoice.', 'cheapalarms'), ['status' => 400]);
            }
            return new WP_Error('missing_contact', __('Contact ID required to create invoice.', 'cheapalarms'), ['status' => 400]);
        }

        $currency = $record['currency'] ?? ($record['currencyOptions']['code'] ?? 'AUD');

        $items = $this->mapEstimateItemsToInvoiceItems(
            $record['items'] ?? [],
            $currency,
            (float) ($record['total'] ?? 0),
            $options['items'] ?? []
        );

        $issueDate = $this->normalizer->formatDate($record['issueDate'] ?? null);
        $dueDate = $this->normalizer->formatDate($record['expiryDate'] ?? null, '+14 days');

        $overrides = $options['overrides'] ?? [];

        $payload = [
            'altId'           => $locationId,
            'altType'         => 'location',
            'name'            => $this->normalizer->truncateName($record['name'] ?? $record['title'] ?? 'Estimate'),
            'title'           => $overrides['title'] ?? 'INVOICE',
            'currency'        => $currency,
            'items'           => $items,
            'discount'        => $record['discount'] ?? null,
            'termsNotes'      => $record['termsNotes'] ?? null,
            'contactDetails'  => $this->mapContact($contactDetails),
            'issueDate'       => $issueDate,
            'dueDate'         => $dueDate,
            'liveMode'        => true,
            'sentTo'          => [
                'email' => isset($contactDetails['email']) ? [$contactDetails['email']] : [],
            ],
        ];

        $response = $this->client->post('/invoices', $payload, 30, $locationId);

        if (is_wp_error($response)) {
            return $response;
        }

        return ['ok' => true, 'result' => $response];
    }

    /**
     * Map estimate items to invoice items format.
     *
     * @param array<int, array<string, mixed>> $estimateItems
     * @param array<int, array<string, mixed>> $overrides
     * @return array<int, array<string, mixed>>
     */
    private function mapEstimateItemsToInvoiceItems(array $estimateItems, string $currency, float $total, array $overrides = []): array
    {
        $items = [];
        $overrideMap = [];
        foreach ($overrides as $override) {
            $key = $override['id'] ?? $override['name'] ?? null;
            if ($key) {
                $overrideMap[$key] = $override;
            }
        }

        foreach ($estimateItems as $item) {
            $id = $item['id'] ?? $item['_id'] ?? null;
            $override = $overrideMap[$id] ?? $overrideMap[$item['name'] ?? ''] ?? null;

            $items[] = [
                'id'                => $id,
                'name'              => $override['name'] ?? $item['name'] ?? '',
                'description'      => $override['description'] ?? $item['description'] ?? '',
                'currency'         => $currency,
                'amount'           => $override['amount'] ?? (float)($item['amount'] ?? 0),
                'qty'              => $override['qty'] ?? (isset($item['quantity']) ? (int)$item['quantity'] : (isset($item['qty']) ? (int)$item['qty'] : 1)),
                'sku'              => $item['sku'] ?? '',
                'originalDescription' => $item['originalDescription'] ?? $item['description'] ?? '',
            ];
        }

        return $items;
    }

    /**
     * Map contact details for invoice payload.
     *
     * @param array<string, mixed> $contact
     * @return array<string, mixed>
     */
    private function mapContact(array $contact): array
    {
        return [
            'id'      => $contact['id'] ?? '',
            'name'    => $contact['name'] ?? '',
            'email'   => $contact['email'] ?? '',
            'phoneNo' => $contact['phoneNo'] ?? $contact['phone'] ?? '',
        ];
    }
}

