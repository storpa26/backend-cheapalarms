<?php

namespace CheapAlarms\Plugin\Db;

use function current_time;
use function get_option;
use function update_option;

class Schema
{
    public const OPTION_KEY = 'ca_db_schema_version';
    public const VERSION    = '2025-12-29-01';

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
            PRIMARY KEY (id),
            UNIQUE KEY location_estimate (location_id, estimate_id),
            KEY location_updated (location_id, updated_at),
            KEY location_synced (location_id, synced_at),
            KEY estimate_id (estimate_id)
        ) {$charsetCollate};";

        dbDelta($sql);
    }
}


