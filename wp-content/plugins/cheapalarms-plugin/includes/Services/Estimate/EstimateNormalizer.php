<?php

namespace CheapAlarms\Plugin\Services\Estimate;

use CheapAlarms\Plugin\Config\Config;

/**
 * Handles normalization and formatting of estimate data.
 */
class EstimateNormalizer
{
    public function __construct(
        private Config $config
    ) {
    }

    /**
     * Format a date value with optional fallback.
     */
    public function formatDate($value, ?string $fallback = null): string
    {
        if ($value) {
            $ts = is_numeric($value) ? (int)$value : strtotime((string)$value);
            if ($ts > 0) {
                return gmdate('Y-m-d', $ts);
            }
        }
        if ($fallback) {
            $ts = strtotime($fallback);
            if ($ts > 0) {
                return gmdate('Y-m-d', $ts);
            }
        }
        return gmdate('Y-m-d');
    }

    /**
     * Truncate name to max length.
     */
    public function truncateName(string $name): string
    {
        return mb_substr($name, 0, 40);
    }

    /**
     * Extract contact details from estimate record.
     *
     * @param array<string, mixed> $record
     * @return array<string, mixed>
     */
    public function extractContactDetails(array $record): array
    {
        $c = $record['contactDetails'] ?? $record['contact'] ?? [];
        return [
            'id'      => $c['id'] ?? ($c['contactId'] ?? ''),
            'name'    => $c['name'] ?? (($c['firstName'] ?? '') . ' ' . ($c['lastName'] ?? '')),
            'email'   => $c['email'] ?? '',
            'phoneNo' => $c['phone'] ?? '',
        ];
    }

    /**
     * Trim/normalize estimate record for API response.
     *
     * @param array<string, mixed> $record
     * @return array<string, mixed>
     */
    public function trimEstimate(array $record, int $includeRaw = 0): array
    {
        $items = [];
        foreach (($record['items'] ?? []) as $item) {
            $qty = isset($item['quantity']) ? (int)$item['quantity'] : (isset($item['qty']) ? (int)$item['qty'] : 1);
            $items[] = [
                'id'                  => $item['id'] ?? ($item['_id'] ?? null),
                'name'                => $item['name'] ?? '',
                'description'         => $item['description'] ?? '',
                'qty'                 => $qty,
                'amount'              => (float)($item['amount'] ?? 0),
                'currency'            => $item['currency'] ?? ($record['currency'] ?? 'AUD'),
                'originalDescription' => $item['originalDescription'] ?? $item['description'] ?? '',
                'sku'                 => $item['sku'] ?? '',
            ];
        }

        $contact = $record['contactDetails'] ?? $record['contact'] ?? [];

        $out = [
            'estimateId'     => $record['id'] ?? $record['_id'] ?? $record['estimateId'] ?? null,
            'estimateNumber' => $record['estimateNumber'] ?? $record['number'] ?? null,
            'status'         => $record['status'] ?? 'draft',
            'title'           => $record['title'] ?? $record['name'] ?? 'ESTIMATE',
            'contact'         => [
                'id'    => $contact['id'] ?? $contact['contactId'] ?? null,
                'name'  => $contact['name'] ?? (($contact['firstName'] ?? '') . ' ' . ($contact['lastName'] ?? '')),
                'email' => $contact['email'] ?? '',
                'phone' => $contact['phone'] ?? '',
                'address' => $contact['address'] ?? null,
            ],
            'items'           => $items,
            'subtotal'        => $record['subtotal'] ?? null,
            'taxTotal'        => $record['taxTotal'] ?? $record['tax'] ?? null,
            'total'           => (float)($record['total'] ?? 0),
            'currency'        => $record['currency'] ?? ($record['currencyOptions']['code'] ?? 'AUD'),
            'createdAt'       => $record['createdAt'] ?? null,
            'updatedAt'       => $record['updatedAt'] ?? null,
        ];

        if ($includeRaw) {
            $out['raw'] = $record;
        }

        return $out;
    }
}

