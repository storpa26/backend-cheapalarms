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
        $encoded = json_encode($meta);
        if ($encoded === false) {
            // Log JSON encoding errors for debugging
            if (function_exists('error_log')) {
                error_log(sprintf(
                    '[CheapAlarms] Failed to encode portal meta for estimate %s: %s',
                    $estimateId,
                    json_last_error_msg()
                ));
            }
            return false;
        }
        return update_option('ca_portal_meta_' . $estimateId, $encoded);
    }

    /**
     * Batch get portal meta for multiple estimates.
     * This prevents N+1 queries by fetching all metadata in one query.
     *
     * @param string[] $estimateIds
     * @return array<string, array> Map of estimateId => meta
     */
    public function batchGet(array $estimateIds): array
    {
        if (empty($estimateIds)) {
            return [];
        }

        // Normalize all IDs to strings for consistency
        $normalizedIds = array_map('strval', $estimateIds);
        
        // Deduplicate IDs to avoid processing duplicates
        $uniqueIds = array_unique($normalizedIds, SORT_REGULAR);
        
        // Chunk large arrays to avoid SQL IN clause limits (MySQL typically limits to 1000 items)
        $chunkSize = 1000;
        $allMeta = [];
        
        global $wpdb;
        $prefix = 'ca_portal_meta_';
        
        foreach (array_chunk($uniqueIds, $chunkSize) as $chunk) {
            // Build option names
            $optionNames = array_map(fn($id) => $prefix . $id, $chunk);
            
            // Create placeholders for prepared statement
            $placeholders = implode(',', array_fill(0, count($optionNames), '%s'));
            
            // Fetch all in one query
            $query = $wpdb->prepare(
                "SELECT option_name, option_value 
                 FROM {$wpdb->options} 
                 WHERE option_name IN ($placeholders)",
                $optionNames
            );
            
            $results = $wpdb->get_results($query, ARRAY_A);
            
            // Check for database errors
            if ($wpdb->last_error) {
                if (function_exists('error_log')) {
                    error_log(sprintf(
                        '[CheapAlarms] Database error in batchGet: %s (Query: %s)',
                        $wpdb->last_error,
                        $wpdb->last_query
                    ));
                }
                // Continue with empty results for this chunk
                continue;
            }
            
            // Ensure results is an array (get_results can return null on error)
            if (!is_array($results)) {
                $results = [];
            }
            
            // Build result map for this chunk
            foreach ($results as $row) {
                $estimateId = str_replace($prefix, '', $row['option_name']);
                // Safety check: verify prefix was actually removed
                if ($estimateId === $row['option_name']) {
                    // Prefix not found, skip this row
                    continue;
                }
                
                // Normalize to string to ensure consistent key type (already a string from str_replace, but explicit for clarity)
                $estimateId = (string)$estimateId;
                
                $decoded = json_decode($row['option_value'], true);
                
                if (json_last_error() !== JSON_ERROR_NONE) {
                    // Log error but continue
                    if (function_exists('error_log')) {
                        error_log(sprintf(
                            '[CheapAlarms] Failed to decode portal meta for estimate %s in batchGet: %s',
                            $estimateId,
                            json_last_error_msg()
                        ));
                    }
                    $allMeta[$estimateId] = [];
                } else {
                    $allMeta[$estimateId] = is_array($decoded) ? $decoded : [];
                }
            }
        }
        
        // Fill in missing estimates with empty arrays (normalize IDs to match keys)
        foreach ($estimateIds as $id) {
            $normalizedId = (string)$id;
            if (!isset($allMeta[$normalizedId])) {
                $allMeta[$normalizedId] = [];
            }
        }
        
        return $allMeta;
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
     * Batch find estimate IDs by invoice IDs (reverse lookup).
     * This prevents N+1 queries by fetching all mappings in one query.
     *
     * @param string[] $invoiceIds
     * @return array<string, string> Map of invoiceId => estimateId
     */
    public function batchFindEstimateIdsByInvoiceIds(array $invoiceIds): array
    {
        if (empty($invoiceIds)) {
            return [];
        }

        global $wpdb;

        // Normalize invoice IDs to strings for consistent lookup
        $normalizedInvoiceIds = array_map('strval', $invoiceIds);

        // Search all ca_portal_meta_* options
        $optionNamePattern = 'ca_portal_meta_%';
        $results = $wpdb->get_results($wpdb->prepare(
            "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s",
            $optionNamePattern
        ));

        // Check for database errors
        if ($wpdb->last_error) {
            if (function_exists('error_log')) {
                error_log(sprintf(
                    '[CheapAlarms] Database error in batchFindEstimateIdsByInvoiceIds: %s',
                    $wpdb->last_error
                ));
            }
            return []; // Return empty map on error
        }

        // Ensure results is an array (get_results can return null on error)
        if (!is_array($results)) {
            $results = [];
        }

        // Build map of invoiceId => estimateId
        $mapping = [];
        $invoiceIdsSet = array_flip($normalizedInvoiceIds); // Use normalized IDs for fast lookup

        foreach ($results as $row) {
            $meta = json_decode($row->option_value, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                // Log JSON decode errors but continue searching
                if (function_exists('error_log')) {
                    error_log(sprintf(
                        '[CheapAlarms] Failed to decode portal meta in batchFindEstimateIdsByInvoiceIds: %s',
                        json_last_error_msg()
                    ));
                }
                continue;
            }
            if (!is_array($meta)) {
                continue;
            }

            $metaInvoiceId = $meta['invoice']['id'] ?? null;
            // Normalize to string for consistent lookup
            if ($metaInvoiceId) {
                $metaInvoiceId = (string)$metaInvoiceId;
            }
            if ($metaInvoiceId && isset($invoiceIdsSet[$metaInvoiceId])) {
                // Extract estimateId from option_name (ca_portal_meta_{estimateId})
                $estimateId = str_replace('ca_portal_meta_', '', $row->option_name);
                // Safety check: verify prefix was actually removed
                if ($estimateId && $estimateId !== $row->option_name) {
                    // Normalize to string for consistency (already a string from str_replace, but explicit for clarity)
                    $estimateId = (string)$estimateId;
                    $mapping[$metaInvoiceId] = $estimateId;
                }
            }
        }

        return $mapping;
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

