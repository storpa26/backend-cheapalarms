<?php

namespace CheapAlarms\Plugin\Db;

use function current_time;
use function get_option;
use function update_option;

class Schema
{
    public const OPTION_KEY = 'ca_db_schema_version';
    public const VERSION    = '2025-01-15-01'; // Updated for webhook events table

    public static function maybeMigrate(): void
    {
        $current = (string) get_option(self::OPTION_KEY, '');
        if ($current === self::VERSION) {
            return;
        }

        self::migrate();
        update_option(self::OPTION_KEY, self::VERSION, true);
        update_option('ca_db_schema_last_migrated_at', current_time('mysql'), false);
    }

    public static function migrate(): void
    {
        global $wpdb;

        // dbDelta lives here.
        if (!function_exists('dbDelta')) {
            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        }

        $tableName      = $wpdb->prefix . 'ca_estimate_snapshots';
        $charsetCollate = $wpdb->get_charset_collate();

        // Note: keep columns intentionally small/indexed for admin list performance.
        // Raw GHL payload is stored in `raw_json` to avoid future breaking changes.
        $sql = "CREATE TABLE {$tableName} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            location_id VARCHAR(64) NOT NULL,
            estimate_id VARCHAR(64) NOT NULL,
            estimate_number VARCHAR(64) NULL,
            email VARCHAR(190) NULL,
            ghl_status VARCHAR(32) NULL,
            total DECIMAL(18,2) NULL,
            currency VARCHAR(8) NULL,
            created_at DATETIME NULL,
            updated_at DATETIME NULL,
            synced_at DATETIME NOT NULL,
            raw_json LONGTEXT NULL,
            deleted_at DATETIME NULL,
            deleted_by BIGINT(20) UNSIGNED NULL,
            deletion_reason VARCHAR(255) NULL,
            deletion_scope VARCHAR(20) NULL,
            restored_at DATETIME NULL,
            restored_by BIGINT(20) UNSIGNED NULL,
            PRIMARY KEY (id),
            UNIQUE KEY location_estimate (location_id, estimate_id),
            KEY location_updated (location_id, updated_at),
            KEY location_synced (location_id, synced_at),
            KEY estimate_id (estimate_id),
            KEY idx_deleted_at (deleted_at),
            KEY idx_deletion_scope (deletion_scope, deleted_at)
        ) {$charsetCollate};";

        dbDelta($sql);

        // Add soft delete columns if they don't exist (for existing installations)
        $columns = $wpdb->get_col("DESCRIBE {$tableName}");
        $columnsToAdd = [];

        if (!in_array('deleted_at', $columns, true)) {
            $columnsToAdd[] = "ALTER TABLE {$tableName} ADD COLUMN deleted_at DATETIME NULL";
        }
        if (!in_array('deleted_by', $columns, true)) {
            $columnsToAdd[] = "ALTER TABLE {$tableName} ADD COLUMN deleted_by BIGINT(20) UNSIGNED NULL";
        }
        if (!in_array('deletion_reason', $columns, true)) {
            $columnsToAdd[] = "ALTER TABLE {$tableName} ADD COLUMN deletion_reason VARCHAR(255) NULL";
        }
        if (!in_array('deletion_scope', $columns, true)) {
            $columnsToAdd[] = "ALTER TABLE {$tableName} ADD COLUMN deletion_scope VARCHAR(20) NULL";
        }
        if (!in_array('restored_at', $columns, true)) {
            $columnsToAdd[] = "ALTER TABLE {$tableName} ADD COLUMN restored_at DATETIME NULL";
        }
        if (!in_array('restored_by', $columns, true)) {
            $columnsToAdd[] = "ALTER TABLE {$tableName} ADD COLUMN restored_by BIGINT(20) UNSIGNED NULL";
        }

        foreach ($columnsToAdd as $alterSql) {
            $result = $wpdb->query($alterSql);
            if ($result === false && !empty($wpdb->last_error)) {
                // Log but don't fail - column might already exist or migration might have run
                error_log('Schema migration warning (column add): ' . $wpdb->last_error);
            }
        }

        // Add indexes if they don't exist (use prepared statements for safety)
        $indexes = $wpdb->get_col($wpdb->prepare(
            "SHOW INDEX FROM {$tableName} WHERE Key_name = %s",
            'idx_deleted_at'
        ));
        if (empty($indexes)) {
            $result = $wpdb->query("ALTER TABLE {$tableName} ADD INDEX idx_deleted_at (deleted_at)");
            if ($result === false && !empty($wpdb->last_error)) {
                // Log but don't fail - index might already exist
                error_log('Schema migration warning (index add): ' . $wpdb->last_error);
            }
        }

        $indexes = $wpdb->get_col($wpdb->prepare(
            "SHOW INDEX FROM {$tableName} WHERE Key_name = %s",
            'idx_deletion_scope'
        ));
        if (empty($indexes)) {
            $result = $wpdb->query("ALTER TABLE {$tableName} ADD INDEX idx_deletion_scope (deletion_scope, deleted_at)");
            if ($result === false && !empty($wpdb->last_error)) {
                // Log but don't fail - index might already exist
                error_log('Schema migration warning (index add): ' . $wpdb->last_error);
            }
        }

        // Create webhook events table
        $webhookTableName = $wpdb->prefix . 'ca_webhook_events';
        $webhookSql = "CREATE TABLE IF NOT EXISTS {$webhookTableName} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            estimate_id VARCHAR(255) NOT NULL,
            event_id VARCHAR(255) NOT NULL,
            event_type VARCHAR(100) NOT NULL,
            payload LONGTEXT NULL COMMENT 'Raw JSON payload for retry/replay',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            processing_started_at DATETIME NULL COMMENT 'When processing started',
            processed_at DATETIME NULL COMMENT 'NULL = pending, timestamp = processed',
            retry_count INT UNSIGNED DEFAULT 0,
            error_message TEXT NULL COMMENT 'Error if processing failed',
            PRIMARY KEY (id),
            UNIQUE KEY unique_event (event_id),
            KEY idx_estimate_id (estimate_id),
            KEY idx_event_type (event_type),
            KEY idx_processed_at (processed_at),
            KEY idx_pending (processed_at, processing_started_at) COMMENT 'Find pending/failed events'
        ) {$charsetCollate};";
        
        dbDelta($webhookSql);
    }
}


