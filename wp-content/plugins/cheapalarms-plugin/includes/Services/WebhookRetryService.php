<?php

namespace CheapAlarms\Plugin\Services;

/**
 * Retry failed webhook events
 */
class WebhookRetryService
{
    public function __construct(
        private WebhookEventRepository $webhookEventRepo,
        private StripeWebhookProcessor $processor,
        private Logger $logger
    ) {
    }
    
    /**
     * Retry pending webhook events
     * 
     * Called by WP-Cron: ca_retry_failed_webhooks
     */
    public function retryPendingEvents(): array
    {
        $pendingEvents = $this->webhookEventRepo->getPendingEvents(50);
        $processed = 0;
        $failed = 0;
        
        foreach ($pendingEvents as $event) {
            $result = $this->processor->processEvent($event['event_id']);
            
            if (is_wp_error($result)) {
                $failed++;
                $this->logger->warning('Webhook retry failed', [
                    'eventId' => $event['event_id'],
                    'error' => $result->get_error_message(),
                    'retryCount' => $event['retry_count'],
                ]);
            } else {
                $processed++;
            }
        }
        
        return [
            'ok' => true,
            'processed' => $processed,
            'failed' => $failed,
            'total' => count($pendingEvents),
        ];
    }
}
