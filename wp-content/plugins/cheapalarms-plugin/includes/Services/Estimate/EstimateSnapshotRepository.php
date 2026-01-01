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
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT estimate_id, estimate_number, email, ghl_status, total, currency, created_at, updated_at
                 FROM {$this->tableName}
                 WHERE location_id = %s
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
}


