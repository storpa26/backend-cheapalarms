<?php

namespace CheapAlarms\Plugin\Services\Estimate;

use WP_Error;

use function current_time;
use function is_wp_error;

class EstimateSnapshotRepository
{
    private string $tableName;

    public function __construct()
    {
        global $wpdb;
        $this->tableName = $wpdb->prefix . 'ca_estimate_snapshots';
    }

    public function getTableName(): string
    {
        return $this->tableName;
    }

    /**
     * @param array<int, array<string, mixed>> $records Normalized records.
     * @return true|WP_Error
     */
    public function upsertMany(string $locationId, array $records)
    {
        global $wpdb;

        if (!$locationId) {
            return new WP_Error('bad_request', 'locationId is required', ['status' => 400]);
        }

        if (!$records) {
            return true;
        }

        // Build one multi-row insert with ON DUPLICATE KEY UPDATE.
        $syncedAt = current_time('mysql');

        $values = [];
        $params = [];

        foreach ($records as $r) {
            $estimateId = (string)($r['id'] ?? '');
            if (!$estimateId) {
                continue;
            }

            // Use NULLIF wrappers so empty strings don't become invalid DATETIME values under strict SQL modes.
            $values[] = "(%s,%s,NULLIF(%s,''),NULLIF(%s,''),NULLIF(%s,''),%f,NULLIF(%s,''),NULLIF(%s,''),NULLIF(%s,''),%s,NULLIF(%s,''))";
            $params[] = $locationId;
            $params[] = $estimateId;
            $params[] = (string)($r['estimateNumber'] ?? '');
            $params[] = (string)($r['email'] ?? '');
            $params[] = (string)($r['status'] ?? ''); // GHL status
            $params[] = (float)($r['total'] ?? 0);
            $params[] = (string)($r['currency'] ?? '');
            $params[] = (string)($r['createdAt'] ?? '');
            $params[] = (string)($r['updatedAt'] ?? '');
            $params[] = $syncedAt;
            $params[] = (string)($r['rawJson'] ?? '');
        }

        if (!$values) {
            return true;
        }

        $sql = "
            INSERT INTO {$this->tableName}
                (location_id, estimate_id, estimate_number, email, ghl_status, total, currency, created_at, updated_at, synced_at, raw_json)
            VALUES " . implode(',', $values) . "
            ON DUPLICATE KEY UPDATE
                estimate_number = VALUES(estimate_number),
                email = VALUES(email),
                ghl_status = VALUES(ghl_status),
                total = VALUES(total),
                currency = VALUES(currency),
                created_at = VALUES(created_at),
                updated_at = VALUES(updated_at),
                synced_at = VALUES(synced_at),
                raw_json = VALUES(raw_json)
        ";

        $prepared = $wpdb->prepare($sql, $params);
        $res      = $wpdb->query($prepared);

        if ($res === false) {
            return new WP_Error('db_error', 'Failed to upsert snapshots', [
                'status'  => 500,
                'details' => $wpdb->last_error,
            ]);
        }

        return true;
    }

    /**
     * @return array<int, array<string, mixed>>|WP_Error
     */
    public function listByLocation(string $locationId)
    {
        global $wpdb;

        if (!$locationId) {
            return new WP_Error('bad_request', 'locationId is required', ['status' => 400]);
        }

        // We intentionally return a shape compatible with EstimateService::listEstimates() items.
        // CRITICAL: Filter out soft-deleted estimates
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT estimate_id, estimate_number, email, ghl_status, total, currency, created_at, updated_at
                 FROM {$this->tableName}
                 WHERE location_id = %s
                 AND deleted_at IS NULL
                 ORDER BY COALESCE(updated_at, created_at) DESC",
                $locationId
            ),
            ARRAY_A
        );

        if ($rows === null) {
            return new WP_Error('db_error', 'Failed to read snapshots', [
                'status'  => 500,
                'details' => $wpdb->last_error,
            ]);
        }

        $out = [];
        foreach ($rows as $row) {
            $out[] = [
                'id'             => $row['estimate_id'] ?? null,
                'estimateNumber' => $row['estimate_number'] ?? null,
                'email'          => $row['email'] ?? '',
                'status'         => $row['ghl_status'] ?? '',
                'total'          => (float)($row['total'] ?? 0),
                'currency'       => $row['currency'] ?? 'AUD',
                'createdAt'      => $row['created_at'] ?? '',
                'updatedAt'      => $row['updated_at'] ?? '',
            ];
        }

        return $out;
    }

    /**
     * @return string|null|WP_Error
     */
    public function lastSyncedAt(string $locationId)
    {
        global $wpdb;

        if (!$locationId) {
            return new WP_Error('bad_request', 'locationId is required', ['status' => 400]);
        }

        $val = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT MAX(synced_at) FROM {$this->tableName} WHERE location_id = %s",
                $locationId
            )
        );

        if ($val === null && $wpdb->last_error) {
            return new WP_Error('db_error', 'Failed to read last synced_at', [
                'status'  => 500,
                'details' => $wpdb->last_error,
            ]);
        }

        return is_string($val) ? $val : null;
    }

    /**
     * Delete snapshot rows for a specific estimate.
     *
     * @param string $estimateId Estimate ID to delete
     * @return bool|WP_Error True on success, WP_Error on failure
     * @deprecated Use softDelete() instead for soft delete functionality
     */
    public function deleteByEstimateId(string $estimateId)
    {
        global $wpdb;

        if (!$estimateId) {
            return new WP_Error('bad_request', 'estimateId is required', ['status' => 400]);
        }

        $deleted = $wpdb->delete(
            $this->tableName,
            ['estimate_id' => $estimateId],
            ['%s']
        );

        if ($deleted === false) {
            return new WP_Error('db_error', 'Failed to delete snapshot rows', [
                'status'  => 500,
                'details' => $wpdb->last_error,
            ]);
        }

        return true;
    }

    /**
     * Soft delete (set deleted_at timestamp)
     * 
     * CRITICAL: Must be location-scoped to prevent data collisions in multi-location setups.
     *
     * @param string $estimateId
     * @param string $locationId Location ID (required for safety)
     * @param int $userId WordPress user_id who deleted
     * @param string $scope 'local', 'ghl', 'both', or 'orphan_cleanup' (validated in PHP)
     * @param string|null $reason Optional deletion reason
     * @return bool|WP_Error
     */
    public function softDelete(string $estimateId, string $locationId, int $userId, string $scope, ?string $reason = null): bool|WP_Error
    {
        global $wpdb;
        
        if (!$estimateId) {
            return new WP_Error('bad_request', 'estimateId is required', ['status' => 400]);
        }
        
        if (!$locationId) {
            return new WP_Error('bad_request', 'locationId is required', ['status' => 400]);
        }
        
        // Validate scope (PHP validation, not DB ENUM)
        $allowedScopes = ['local', 'ghl', 'both', 'orphan_cleanup'];
        if (!in_array($scope, $allowedScopes, true)) {
            return new WP_Error('bad_request', sprintf('Invalid scope. Must be one of: %s', implode(', ', $allowedScopes)), ['status' => 400]);
        }
        
        // Check if already soft-deleted (location-scoped)
        $existing = $wpdb->get_var($wpdb->prepare(
            "SELECT deleted_at FROM {$this->tableName} 
             WHERE location_id = %s AND estimate_id = %s",
            $locationId,
            $estimateId
        ));
        
        if ($existing !== null && $existing !== '') {
            return new WP_Error('already_deleted', 'Estimate is already soft-deleted', ['status' => 409]);
        }
        
        // Check if estimate exists (location-scoped)
        $exists = $wpdb->get_var($wpdb->prepare(
            "SELECT estimate_id FROM {$this->tableName} 
             WHERE location_id = %s AND estimate_id = %s",
            $locationId,
            $estimateId
        ));
        
        if (!$exists) {
            return new WP_Error('not_found', 'Estimate not found for this location', ['status' => 404]);
        }
        
        $updated = $wpdb->update(
            $this->tableName,
            [
                'deleted_at' => current_time('mysql'),
                'deleted_by' => $userId,
                'deletion_scope' => $scope,
                'deletion_reason' => $reason,
            ],
            [
                'location_id' => $locationId,
                'estimate_id' => $estimateId,
            ],
            ['%s', '%d', '%s', '%s'],
            ['%s', '%s']
        );
        
        if ($updated === false) {
            return new WP_Error('db_error', 'Failed to soft delete snapshot', [
                'status' => 500,
                'details' => $wpdb->last_error,
            ]);
        }
        
        if ($updated === 0) {
            return new WP_Error('not_found', 'Estimate not found for this location', ['status' => 404]);
        }
        
        return true;
    }

    /**
     * Restore (set deleted_at = NULL)
     * 
     * CRITICAL: Must be location-scoped to prevent data collisions in multi-location setups.
     *
     * @param string $estimateId
     * @param string $locationId Location ID (required for safety)
     * @param int $userId WordPress user_id who restored
     * @return bool|WP_Error
     */
    public function restore(string $estimateId, string $locationId, int $userId): bool|WP_Error
    {
        global $wpdb;
        
        if (!$estimateId) {
            return new WP_Error('bad_request', 'estimateId is required', ['status' => 400]);
        }
        
        if (!$locationId) {
            return new WP_Error('bad_request', 'locationId is required', ['status' => 400]);
        }
        
        // Check if actually soft-deleted (location-scoped)
        $deletedAt = $wpdb->get_var($wpdb->prepare(
            "SELECT deleted_at FROM {$this->tableName} 
             WHERE location_id = %s AND estimate_id = %s",
            $locationId,
            $estimateId
        ));
        
        if ($deletedAt === null || $deletedAt === '') {
            return new WP_Error('not_deleted', 'Estimate is not soft-deleted', ['status' => 400]);
        }
        
        // Check if estimate exists (location-scoped)
        $exists = $wpdb->get_var($wpdb->prepare(
            "SELECT estimate_id FROM {$this->tableName} 
             WHERE location_id = %s AND estimate_id = %s",
            $locationId,
            $estimateId
        ));
        
        if (!$exists) {
            return new WP_Error('not_found', 'Estimate not found for this location', ['status' => 404]);
        }
        
        $updated = $wpdb->update(
            $this->tableName,
            [
                'deleted_at' => null,
                'deleted_by' => null,
                'deletion_scope' => null,
                'deletion_reason' => null,
                'restored_at' => current_time('mysql'),
                'restored_by' => $userId,
            ],
            [
                'location_id' => $locationId,
                'estimate_id' => $estimateId,
            ],
            [null, null, null, null, '%s', '%d'],
            ['%s', '%s']
        );
        
        if ($updated === false) {
            return new WP_Error('db_error', 'Failed to restore snapshot', [
                'status' => 500,
                'details' => $wpdb->last_error,
            ]);
        }
        
        if ($updated === 0) {
            return new WP_Error('not_found', 'Estimate not found for this location', ['status' => 404]);
        }
        
        return true;
    }

    /**
     * Find soft-deleted estimates (trash)
     *
     * @param string $locationId
     * @param int $limit
     * @return array<int, array<string, mixed>>|WP_Error
     */
    public function findInTrash(string $locationId, int $limit = 100): array|WP_Error
    {
        global $wpdb;
        
        if (!$locationId) {
            return new WP_Error('bad_request', 'locationId is required', ['status' => 400]);
        }
        
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT estimate_id, estimate_number, email, ghl_status, total, currency, 
                        created_at, updated_at, deleted_at, deleted_by, deletion_scope, deletion_reason
                 FROM {$this->tableName}
                 WHERE location_id = %s 
                 AND deleted_at IS NOT NULL
                 AND deleted_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                 ORDER BY deleted_at DESC
                 LIMIT %d",
                $locationId,
                $limit
            ),
            ARRAY_A
        );
        
        if ($rows === null) {
            return new WP_Error('db_error', 'Failed to read trash', [
                'status' => 500,
                'details' => $wpdb->last_error,
            ]);
        }
        
        return $rows;
    }

    /**
     * Find all soft-deleted estimates in trash (for empty trash functionality)
     *
     * @param string $locationId
     * @return array<int, array<string, mixed>>|WP_Error
     */
    public function findAllInTrash(string $locationId): array|WP_Error
    {
        global $wpdb;
        
        if (!$locationId) {
            return new WP_Error('bad_request', 'locationId is required', ['status' => 400]);
        }
        
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT estimate_id, location_id
                 FROM {$this->tableName}
                 WHERE location_id = %s 
                 AND deleted_at IS NOT NULL
                 ORDER BY deleted_at DESC",
                $locationId
            ),
            ARRAY_A
        );
        
        // Check for database errors first (more explicit error handling)
        if ($wpdb->last_error) {
            return new WP_Error('db_error', 'Failed to read trash', [
                'status' => 500,
                'details' => $wpdb->last_error,
            ]);
        }
        
        // get_results returns null on error, empty array on no results
        if ($rows === null) {
            return new WP_Error('db_error', 'Failed to read trash', [
                'status' => 500,
                'details' => $wpdb->last_error ?: 'Unknown database error',
            ]);
        }
        
        return $rows;
    }

    /**
     * Find expired soft-deletes (older than 30 days, ready for permanent deletion)
     *
     * @param int $batchSize
     * @return array<int, array<string, mixed>>|WP_Error
     */
    public function findExpiredDeletes(int $batchSize = 1000): array|WP_Error
    {
        global $wpdb;
        
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT estimate_id, location_id
                 FROM {$this->tableName}
                 WHERE deleted_at IS NOT NULL
                 AND deleted_at < DATE_SUB(NOW(), INTERVAL 30 DAY)
                 LIMIT %d",
                $batchSize
            ),
            ARRAY_A
        );
        
        if ($rows === null) {
            return new WP_Error('db_error', 'Failed to find expired deletes', [
                'status' => 500,
                'details' => $wpdb->last_error,
            ]);
        }
        
        return $rows;
    }

    /**
     * Hard delete (permanent removal after retention period)
     * 
     * CRITICAL: Must be location-scoped to prevent data collisions in multi-location setups.
     *
     * @param string $estimateId
     * @param string $locationId Location ID (required for safety)
     * @return bool|WP_Error
     */
    public function hardDelete(string $estimateId, string $locationId): bool|WP_Error
    {
        global $wpdb;
        
        if (!$estimateId) {
            return new WP_Error('bad_request', 'estimateId is required', ['status' => 400]);
        }
        
        if (!$locationId) {
            return new WP_Error('bad_request', 'locationId is required', ['status' => 400]);
        }
        
        $deleted = $wpdb->delete(
            $this->tableName,
            [
                'location_id' => $locationId,
                'estimate_id' => $estimateId,
            ],
            ['%s', '%s']
        );
        
        if ($deleted === false) {
            return new WP_Error('db_error', 'Failed to hard delete snapshot', [
                'status' => 500,
                'details' => $wpdb->last_error,
            ]);
        }
        
        return true;
    }
}


