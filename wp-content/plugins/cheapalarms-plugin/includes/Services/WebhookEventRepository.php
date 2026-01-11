<?php

namespace CheapAlarms\Plugin\Services;

use function current_time;

/**
 * Repository for storing and managing Stripe webhook events
 */
class WebhookEventRepository
{
    private string $tableName;
    
    public function __construct()
    {
        global $wpdb;
        $this->tableName = $wpdb->prefix . 'ca_webhook_events';
    }
    
    /**
     * Get table name (for use in other services)
     */
    public function getTableName(): string
    {
        return $this->tableName;
    }
    
    /**
     * Store event BEFORE processing (safe retries)
     * Returns true if new event, false if already exists
     */
    public function storeEvent(string $estimateId, string $eventId, string $eventType, string $payload): bool
    {
        global $wpdb;
        
        $result = $wpdb->query($wpdb->prepare(
            "INSERT IGNORE INTO {$this->tableName} 
             (estimate_id, event_id, event_type, payload, created_at) 
             VALUES (%s, %s, %s, %s, %s)",
            $estimateId,
            $eventId,
            $eventType,
            $payload,
            current_time('mysql')
        ));
        
        return $wpdb->rows_affected > 0;
    }
    
    public function isProcessed(string $eventId): bool
    {
        global $wpdb;
        $processed = $wpdb->get_var($wpdb->prepare(
            "SELECT processed_at FROM {$this->tableName} WHERE event_id = %s",
            $eventId
        ));
        return !empty($processed);
    }
    
    public function markProcessingStarted(string $eventId): bool
    {
        global $wpdb;
        return $wpdb->update(
            $this->tableName,
            ['processing_started_at' => current_time('mysql')],
            ['event_id' => $eventId, 'processed_at' => null],
            ['%s'],
            ['%s', '%s']
        ) !== false;
    }
    
    public function markProcessed(string $eventId): bool
    {
        global $wpdb;
        return $wpdb->update(
            $this->tableName,
            ['processed_at' => current_time('mysql'), 'error_message' => null],
            ['event_id' => $eventId],
            ['%s', '%s'],
            ['%s']
        ) !== false;
    }
    
    public function markFailed(string $eventId, string $errorMessage): bool
    {
        global $wpdb;
        return $wpdb->query($wpdb->prepare(
            "UPDATE {$this->tableName} 
             SET error_message = %s, retry_count = retry_count + 1, processing_started_at = NULL
             WHERE event_id = %s",
            $errorMessage,
            $eventId
        )) !== false;
    }
    
    public function getPendingEvents(int $limit = 100): array
    {
        global $wpdb;
        $results = $wpdb->get_results($wpdb->prepare(
            "SELECT event_id, estimate_id, event_type, payload, retry_count, error_message
             FROM {$this->tableName} 
             WHERE processed_at IS NULL 
             AND (processing_started_at IS NULL OR processing_started_at < DATE_SUB(NOW(), INTERVAL 5 MINUTE))
             AND retry_count < 3
             ORDER BY created_at ASC
             LIMIT %d",
            $limit
        ), ARRAY_A);
        return $results ?: [];
    }
    
    public function getEventPayload(string $eventId): ?string
    {
        global $wpdb;
        $payload = $wpdb->get_var($wpdb->prepare(
            "SELECT payload FROM {$this->tableName} WHERE event_id = %s",
            $eventId
        ));
        return $payload ?: null;
    }
}
