<?php

namespace CheapAlarms\Plugin\Services\Shared;

use function get_option;
use function json_decode;
use function update_option;

/**
 * Repository for portal metadata stored in WordPress options.
 */
class PortalMetaRepository
{
    /**
     * Get portal meta for an estimate.
     *
     * @return array<string, mixed>
     */
    public function get(string $estimateId): array
    {
        $stored = get_option('ca_portal_meta_' . $estimateId, '{}');
        $decoded = json_decode(is_string($stored) ? $stored : '{}', true);
        return is_array($decoded) ? $decoded : [];
    }

    /**
     * Update portal meta for an estimate.
     *
     * @param array<string, mixed> $meta
     */
    public function update(string $estimateId, array $meta): bool
    {
        return update_option('ca_portal_meta_' . $estimateId, json_encode($meta));
    }

    /**
     * Merge new data into existing portal meta.
     *
     * @param array<string, mixed> $newData
     */
    public function merge(string $estimateId, array $newData): bool
    {
        $existing = $this->get($estimateId);
        $merged = array_merge($existing, $newData);
        return $this->update($estimateId, $merged);
    }

    /**
     * Find estimate ID that has this invoice ID in its portal meta.
     * This is a reverse lookup - searches all portal meta options.
     *
     * @return string|null
     */
    public function findEstimateIdByInvoiceId(string $invoiceId): ?string
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
}

