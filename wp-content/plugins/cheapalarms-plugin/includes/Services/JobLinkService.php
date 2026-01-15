<?php

namespace CheapAlarms\Plugin\Services;

use WP_Error;
use WP_User;

use function current_time;
use function delete_option;
use function get_current_user_id;
use function get_option;
use function get_user_by;
use function is_wp_error;
use function sanitize_text_field;
use function update_option;
use function wp_json_encode;

/**
 * Service for managing bidirectional links between GHL estimates and ServiceM8 jobs.
 *
 * Stores links in WordPress options:
 * - ca_estimate_job_{estimateId} → job UUID
 * - ca_job_estimate_{jobUuid} → estimate ID
 * - ca_job_links → master index array
 */
class JobLinkService
{
    private const OPTION_PREFIX_ESTIMATE = 'ca_estimate_job_';
    private const OPTION_PREFIX_JOB = 'ca_job_estimate_';
    private const OPTION_INDEX = 'ca_job_links';

    public function __construct(
        private Logger $logger
    ) {
    }

    /**
     * Create or update a link between an estimate and a job.
     *
     * @param string $estimateId GHL estimate ID
     * @param string $jobUuid ServiceM8 job UUID
     * @param array<string, mixed>|null $metadata Optional metadata (companyUuid, staffUuid, notes, etc.)
     * @return bool|WP_Error True on success, WP_Error on failure
     */
    public function linkEstimateToJob(string $estimateId, string $jobUuid, ?array $metadata = null): bool|WP_Error
    {
        $estimateId = sanitize_text_field($estimateId);
        $jobUuid = sanitize_text_field($jobUuid);

        if (empty($estimateId)) {
            return new WP_Error('invalid_estimate_id', 'Estimate ID is required', ['status' => 400]);
        }

        if (empty($jobUuid)) {
            return new WP_Error('invalid_job_uuid', 'Job UUID is required', ['status' => 400]);
        }

        // Validate UUID format (consistent with ServiceM8Controller - allows variable length)
        if (!preg_match('/^[a-zA-Z0-9\-]+$/', $jobUuid)) {
            return new WP_Error('invalid_uuid_format', 'Invalid UUID format', ['status' => 400]);
        }

        // Check if estimate is already linked to a different job
        $existingJobUuid = $this->getJobUuidByEstimateId($estimateId);
        if ($existingJobUuid && $existingJobUuid !== $jobUuid) {
            // Unlink the old job first
            $this->unlinkEstimateFromJob($estimateId);
        }

        // Check if job is already linked to a different estimate
        $existingEstimateId = $this->getEstimateIdByJobUuid($jobUuid);
        if ($existingEstimateId && $existingEstimateId !== $estimateId) {
            // Unlink the old estimate first
            $this->unlinkEstimateFromJob($existingEstimateId);
        }

        $userId = get_current_user_id();
        $user = $userId > 0 ? get_user_by('id', $userId) : null;
        $linkedBy = $user ? $userId : 0;

        $linkData = [
            'estimateId' => $estimateId,
            'jobUuid' => $jobUuid,
            'linkedAt' => current_time('mysql'),
            'linkedBy' => $linkedBy,
            'metadata' => is_array($metadata) ? $metadata : [],
        ];

        // Encode JSON and validate
        $encoded = wp_json_encode($linkData);
        if ($encoded === false) {
            $this->logger->error('Failed to encode job link data JSON', [
                'estimateId' => $estimateId,
                'jobUuid' => $jobUuid,
                'error' => json_last_error_msg(),
            ]);
            return false;
        }

        // Store bidirectional links
        update_option(self::OPTION_PREFIX_ESTIMATE . $estimateId, $encoded, false);
        update_option(self::OPTION_PREFIX_JOB . $jobUuid, $encoded, false);

        // Update master index
        $this->updateIndex($estimateId, $jobUuid, $linkData);

        $this->logger->info('Estimate linked to job', [
            'estimateId' => $estimateId,
            'jobUuid' => $jobUuid,
            'linkedBy' => $linkedBy,
        ]);

        return true;
    }

    /**
     * Get job UUID by estimate ID.
     *
     * @param string $estimateId GHL estimate ID
     * @return string|null Job UUID or null if not linked
     */
    public function getJobUuidByEstimateId(string $estimateId): ?string
    {
        $estimateId = sanitize_text_field($estimateId);
        if (empty($estimateId)) {
            return null;
        }

        $stored = get_option(self::OPTION_PREFIX_ESTIMATE . $estimateId, null);
        if (!$stored) {
            return null;
        }

        $decoded = json_decode($stored, true);
        if (!is_array($decoded) || empty($decoded['jobUuid'])) {
            return null;
        }

        return (string) $decoded['jobUuid'];
    }

    /**
     * Get estimate ID by job UUID.
     *
     * @param string $jobUuid ServiceM8 job UUID
     * @return string|null Estimate ID or null if not linked
     */
    public function getEstimateIdByJobUuid(string $jobUuid): ?string
    {
        $jobUuid = sanitize_text_field($jobUuid);
        if (empty($jobUuid)) {
            return null;
        }

        $stored = get_option(self::OPTION_PREFIX_JOB . $jobUuid, null);
        if (!$stored) {
            return null;
        }

        $decoded = json_decode($stored, true);
        if (!is_array($decoded) || empty($decoded['estimateId'])) {
            return null;
        }

        return (string) $decoded['estimateId'];
    }

    /**
     * Get full link data by estimate ID.
     *
     * @param string $estimateId GHL estimate ID
     * @return array<string, mixed>|null Link data or null if not linked
     */
    public function getLinkByEstimateId(string $estimateId): ?array
    {
        $estimateId = sanitize_text_field($estimateId);
        if (empty($estimateId)) {
            return null;
        }

        $stored = get_option(self::OPTION_PREFIX_ESTIMATE . $estimateId, null);
        if (!$stored) {
            return null;
        }

        $decoded = json_decode($stored, true);
        if (!is_array($decoded)) {
            return null;
        }

        return $decoded;
    }

    /**
     * Get full link data by job UUID.
     *
     * @param string $jobUuid ServiceM8 job UUID
     * @return array<string, mixed>|null Link data or null if not linked
     */
    public function getLinkByJobUuid(string $jobUuid): ?array
    {
        $jobUuid = sanitize_text_field($jobUuid);
        if (empty($jobUuid)) {
            return null;
        }

        $stored = get_option(self::OPTION_PREFIX_JOB . $jobUuid, null);
        if (!$stored) {
            return null;
        }

        $decoded = json_decode($stored, true);
        if (!is_array($decoded)) {
            return null;
        }

        return $decoded;
    }

    /**
     * Remove link between estimate and job.
     *
     * @param string $estimateId GHL estimate ID
     * @return bool True if link was removed, false if it didn't exist
     */
    public function unlinkEstimateFromJob(string $estimateId): bool
    {
        $estimateId = sanitize_text_field($estimateId);
        if (empty($estimateId)) {
            return false;
        }

        $linkData = $this->getLinkByEstimateId($estimateId);
        if (!$linkData) {
            return false;
        }

        $jobUuid = $linkData['jobUuid'] ?? null;

        // Remove bidirectional links
        delete_option(self::OPTION_PREFIX_ESTIMATE . $estimateId);
        if ($jobUuid) {
            delete_option(self::OPTION_PREFIX_JOB . $jobUuid);
        }

        // Remove from index
        $this->removeFromIndex($estimateId, $jobUuid);

        $this->logger->info('Estimate unlinked from job', [
            'estimateId' => $estimateId,
            'jobUuid' => $jobUuid,
        ]);

        return true;
    }

    /**
     * Check if estimate is linked to a job.
     *
     * @param string $estimateId GHL estimate ID
     * @return bool True if linked
     */
    public function isEstimateLinked(string $estimateId): bool
    {
        return $this->getJobUuidByEstimateId($estimateId) !== null;
    }

    /**
     * Check if job is linked to an estimate.
     *
     * @param string $jobUuid ServiceM8 job UUID
     * @return bool True if linked
     */
    public function isJobLinked(string $jobUuid): bool
    {
        return $this->getEstimateIdByJobUuid($jobUuid) !== null;
    }

    /**
     * Get all links (for admin/debugging).
     *
     * @param int $limit Maximum number of links to return
     * @return array<int, array<string, mixed>> Array of link data
     */
    public function getAllLinks(int $limit = 100): array
    {
        $index = get_option(self::OPTION_INDEX, []);
        if (!is_array($index)) {
            return [];
        }

        // Sort by linkedAt descending (most recent first)
        usort($index, function ($a, $b) {
            $timeA = $a['linkedAt'] ?? '';
            $timeB = $b['linkedAt'] ?? '';
            return strcmp($timeB, $timeA);
        });

        return array_slice($index, 0, $limit);
    }

    /**
     * Update master index with link data.
     *
     * @param string $estimateId
     * @param string $jobUuid
     * @param array<string, mixed> $linkData
     * @return void
     */
    private function updateIndex(string $estimateId, string $jobUuid, array $linkData): void
    {
        $index = get_option(self::OPTION_INDEX, []);
        if (!is_array($index)) {
            $index = [];
        }

        // Remove existing entry if it exists (by estimateId or jobUuid)
        $index = array_filter($index, function ($entry) use ($estimateId, $jobUuid) {
            return ($entry['estimateId'] ?? '') !== $estimateId
                && ($entry['jobUuid'] ?? '') !== $jobUuid;
        });

        // Add new entry
        $index[] = $linkData;

        update_option(self::OPTION_INDEX, $index, false);
    }

    /**
     * Remove entry from master index.
     *
     * @param string $estimateId
     * @param string|null $jobUuid
     * @return void
     */
    private function removeFromIndex(string $estimateId, ?string $jobUuid): void
    {
        $index = get_option(self::OPTION_INDEX, []);
        if (!is_array($index)) {
            return;
        }

        $index = array_filter($index, function ($entry) use ($estimateId, $jobUuid) {
            return ($entry['estimateId'] ?? '') !== $estimateId
                && ($entry['jobUuid'] ?? '') !== $jobUuid;
        });

        update_option(self::OPTION_INDEX, array_values($index), false);
    }
}

