<?php

namespace CheapAlarms\Plugin\Services\Estimate;

use CheapAlarms\Plugin\Services\Logger;
use WP_Error;

use function delete_option;
use function is_wp_error;

class RetentionCleanupService
{
    public function __construct(
        private EstimateSnapshotRepository $repo,
        private Logger $logger
    ) {
    }

    /**
     * Permanently delete estimates that have been soft-deleted for > 30 days.
     *
     * @return array{ok:bool, deleted:int, errors:array<int, array{estimateId:string, error:string}>}|WP_Error
     */
    public function cleanup(): array|WP_Error
    {
        $batchSize = 1000;
        $deleted = 0;
        $errors = [];

        while (true) {
            // Get batch of expired soft-deletes
            $expired = $this->repo->findExpiredDeletes($batchSize);
            
            if (is_wp_error($expired)) {
                return $expired;
            }

            if (empty($expired)) {
                break; // No more expired deletes
            }

            foreach ($expired as $row) {
                $estimateId = $row['estimate_id'] ?? null;
                $locationId = $row['location_id'] ?? null;
                
                if (!$estimateId || !$locationId) {
                    continue;
                }

                // Hard delete from snapshot table (location-scoped)
                $result = $this->repo->hardDelete($estimateId, $locationId);
                
                if (is_wp_error($result)) {
                    $errors[] = ['estimateId' => $estimateId, 'error' => $result->get_error_message()];
                } else {
                    $deleted++;
                    
                    // Also hard delete related options (if still exist)
                    delete_option('ca_portal_meta_' . $estimateId);
                    delete_option('ca_estimate_uploads_' . $estimateId);
                    
                    // Clean up job links (if exists)
                    delete_option('ca_estimate_job_link_' . $estimateId);
                    // Note: Job link index cleanup handled by JobLinkService if needed
                }
            }

            // If we got a full batch, there might be more
            if (count($expired) < $batchSize) {
                break; // Last batch
            }
        }

        $this->logger->info('Retention cleanup completed', [
            'deleted' => $deleted,
            'errors' => count($errors),
        ]);

        return [
            'ok' => true,
            'deleted' => $deleted,
            'errors' => $errors,
        ];
    }
}

