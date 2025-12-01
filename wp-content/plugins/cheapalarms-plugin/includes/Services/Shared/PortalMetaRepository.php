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
        if (json_last_error() !== JSON_ERROR_NONE) {
            // Log JSON decode errors for debugging
            if (function_exists('error_log')) {
                error_log(sprintf(
                    '[CheapAlarms] Failed to decode portal meta for estimate %s: %s',
                    $estimateId,
                    json_last_error_msg()
                ));
            }
            return [];
        }
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
            if (json_last_error() !== JSON_ERROR_NONE) {
                // Log JSON decode errors but continue searching
                if (function_exists('error_log')) {
                    error_log(sprintf(
                        '[CheapAlarms] Failed to decode portal meta in findEstimateIdByInvoiceId: %s',
                        json_last_error_msg()
                    ));
                }
                continue;
            }
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
     * Find estimate ID by matching invoice contact ID and date.
     * This is a fallback for manually created invoices that aren't linked in portal meta.
     * 
     * IMPORTANT: This method requires EstimateService to verify contact ID matches.
     * The caller should pass EstimateService to enable contact ID verification.
     *
     * @param string $invoiceContactId Invoice contact ID from GHL
     * @param string $invoiceDate Invoice issue date (YYYY-MM-DD format)
     * @param \CheapAlarms\Plugin\Services\EstimateService|null $estimateService Optional service to verify contact ID
     * @param string|null $locationId Location ID for fetching estimate details
     * @return string|null
     */
    public function findEstimateIdByContactAndDate(string $invoiceContactId, string $invoiceDate, ?\CheapAlarms\Plugin\Services\EstimateService $estimateService = null, ?string $locationId = null): ?string
    {
        global $wpdb;

        // Search all ca_portal_meta_* options
        $optionNamePattern = 'ca_portal_meta_%';
        $results = $wpdb->get_results($wpdb->prepare(
            "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s",
            $optionNamePattern
        ));

        $bestMatch = null;
        $bestMatchScore = 0;

        foreach ($results as $row) {
            $meta = json_decode($row->option_value, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                // Log JSON decode errors but continue searching
                if (function_exists('error_log')) {
                    error_log(sprintf(
                        '[CheapAlarms] Failed to decode portal meta in findEstimateIdByContactAndDate: %s',
                        json_last_error_msg()
                    ));
                }
                continue;
            }
            if (!is_array($meta)) {
                continue;
            }

            // Skip if estimate already has an invoice linked
            if (!empty($meta['invoice']['id'])) {
                continue;
            }

            // Extract estimateId from option_name
            $estimateId = str_replace('ca_portal_meta_', '', $row->option_name);
            if (!$estimateId) {
                continue;
            }

            // Check if estimate was accepted (more likely to have invoice)
            $quoteStatus = $meta['quote']['status'] ?? 'sent';
            if ($quoteStatus !== 'accepted') {
                continue; // Only match accepted estimates
            }

            // Verify contact ID matches if EstimateService is provided
            if ($estimateService && $locationId) {
                try {
                    $estimate = $estimateService->getEstimate([
                        'estimateId' => $estimateId,
                        'locationId' => $locationId,
                    ]);
                    
                    // Check if estimate fetch was successful and contact ID matches
                    if (!is_wp_error($estimate)) {
                        $estimateContactId = $estimate['contact']['id'] ?? $estimate['contact']['contactId'] ?? null;
                        if ($estimateContactId !== $invoiceContactId) {
                            // Contact ID doesn't match - skip this estimate
                            continue;
                        }
                    } else {
                        // If we can't fetch the estimate, skip it (can't verify contact ID)
                        continue;
                    }
                } catch (\Exception $e) {
                    // If there's an error fetching estimate, skip it
                    continue;
                }
            }

            // Try to match by date proximity (invoice created within 7 days of acceptance)
            $acceptedAt = $meta['quote']['acceptedAt'] ?? null;
            if ($acceptedAt) {
                // Parse dates and check if within 7 days
                $invoiceTimestamp = strtotime($invoiceDate);
                $acceptedTimestamp = strtotime($acceptedAt);
                
                if ($invoiceTimestamp && $acceptedTimestamp) {
                    $daysDiff = abs($invoiceTimestamp - $acceptedTimestamp) / (60 * 60 * 24);
                    if ($daysDiff <= 7) {
                        // Score based on how close the dates are (closer = higher score)
                        // If contact ID was verified, give bonus points
                        $contactVerified = ($estimateService && $locationId) ? 50 : 0;
                        $score = 100 - ($daysDiff * 10) + $contactVerified;
                        if ($score > $bestMatchScore) {
                            $bestMatchScore = $score;
                            $bestMatch = $estimateId;
                        }
                    }
                }
            }
        }

        return $bestMatch;
    }
}

