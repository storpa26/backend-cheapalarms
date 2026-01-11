<?php

namespace CheapAlarms\Plugin\Services;

use WP_Error;
use function current_time;

/**
 * Process Stripe webhook events asynchronously
 * 
 * Called via WP-Cron to avoid webhook timeouts
 */
class StripeWebhookProcessor
{
    public function __construct(
        private WebhookEventRepository $webhookEventRepo,
        private \CheapAlarms\Plugin\Services\Shared\PortalMetaRepository $portalMetaRepo,
        private Logger $logger
    ) {
    }
    
    /**
     * Process a single webhook event
     * 
     * Called by WP-Cron hook: ca_process_stripe_webhook
     */
    public function processEvent(string $eventId): bool|WP_Error
    {
        // Get event from database
        global $wpdb;
        $tableName = $this->webhookEventRepo->getTableName();
        $event = $wpdb->get_row($wpdb->prepare(
            "SELECT estimate_id, event_id, event_type, payload, retry_count
             FROM {$tableName} 
             WHERE event_id = %s",
            $eventId
        ), ARRAY_A);
        
        if (!$event) {
            return new WP_Error('not_found', __('Webhook event not found.', 'cheapalarms'), ['status' => 404]);
        }
        
        // Check if already processed
        if ($this->webhookEventRepo->isProcessed($eventId)) {
            $this->logger->info('Webhook event already processed', ['eventId' => $eventId]);
            return true;
        }
        
        // Mark processing started
        $this->webhookEventRepo->markProcessingStarted($eventId);
        
        try {
            // Parse payload
            $eventData = json_decode($event['payload'], true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new \Exception('Failed to parse event payload: ' . json_last_error_msg());
            }
            
            $eventType = $event['event_type'];
            $estimateId = $event['estimate_id'];
            $data = $eventData['data']['object'] ?? [];
            
            // Process based on event type
            $result = $this->processEventByType($estimateId, $eventId, $eventType, $data);
            
            if (is_wp_error($result)) {
                $this->webhookEventRepo->markFailed($eventId, $result->get_error_message());
                return $result;
            }
            
            // Mark as processed (after successful processing)
            $this->webhookEventRepo->markProcessed($eventId);
            
            $this->logger->info('Webhook event processed successfully', [
                'eventId' => $eventId,
                'eventType' => $eventType,
                'estimateId' => $estimateId,
            ]);
            
            return true;
            
        } catch (\Exception $e) {
            $this->webhookEventRepo->markFailed($eventId, $e->getMessage());
            
            $this->logger->error('Webhook processing exception', [
                'eventId' => $eventId,
                'error' => $e->getMessage(),
            ]);
            
            return new WP_Error('processing_error', $e->getMessage(), ['status' => 500]);
        }
    }
    
    private function processEventByType(string $estimateId, string $eventId, string $eventType, array $data): bool|WP_Error
    {
        switch ($eventType) {
            case 'payment_intent.succeeded':
                return $this->handlePaymentIntentSucceeded($estimateId, $eventId, $data);
                
            case 'payment_intent.payment_failed':
                return $this->handlePaymentIntentFailed($estimateId, $eventId, $data);
                
            case 'charge.refunded':
                return $this->handleChargeRefunded($estimateId, $eventId, $data);
                
            default:
                $this->logger->info('Unhandled webhook event type', [
                    'eventId' => $eventId,
                    'eventType' => $eventType,
                ]);
                return true; // Don't error on unknown types
        }
    }
    
    private function handlePaymentIntentSucceeded(string $estimateId, string $eventId, array $data): bool|WP_Error
    {
        $paymentIntentId = $data['id'] ?? null;
        $amount = isset($data['amount']) ? ($data['amount'] / 100) : 0;
        
        if (empty($paymentIntentId)) {
            return new WP_Error('invalid_event', __('Payment intent ID missing.', 'cheapalarms'), ['status' => 400]);
        }
        
        $meta = $this->portalMetaRepo->get($estimateId);
        $payment = $meta['payment'] ?? [];
        $payments = $payment['payments'] ?? [];
        
        // Find or create payment record
        $paymentRecord = null;
        $paymentIndex = null;
        
        foreach ($payments as $index => $p) {
            if (($p['paymentIntentId'] ?? '') === $paymentIntentId) {
                $paymentRecord = $p;
                $paymentIndex = $index;
                break;
            }
        }
        
        if (!$paymentRecord) {
            // Create new payment record
            $invoice = $meta['invoice'] ?? [];
            $depositRequired = $invoice['depositRequired'] ?? false;
            $hasDepositPaid = $payment['hasDepositPaid'] ?? false;
            $paymentType = ($depositRequired && !$hasDepositPaid) ? 'deposit' : 'final';
            
            $paymentRecord = [
                'paymentIntentId' => $paymentIntentId,
                'amount' => $amount,
                'currency' => $data['currency'] ?? 'aud',
                'paymentType' => $paymentType,
                'status' => 'succeeded',
                'stripeEventId' => $eventId,
                'paidAt' => current_time('mysql'),
                'refunded' => false,
            ];
            
            $payments[] = $paymentRecord;
            $paymentIndex = count($payments) - 1;
        } else {
            // Update existing record
            $paymentRecord['stripeEventId'] = $eventId;
            $paymentRecord['status'] = 'succeeded';
            $payments[$paymentIndex] = $paymentRecord;
        }
        
        // Recompute totals
        $invoiceTotal = $meta['invoice']['total'] ?? $meta['invoice']['ghl']['total'] ?? 0;
        $totals = $this->computePaymentTotals($payments, $invoiceTotal);
        
        // Update portal meta
        $this->portalMetaRepo->merge($estimateId, [
            'payment' => array_merge($payment, [
                'payments' => $payments,
                'totalPaid' => $totals['totalPaid'],
                'remainingBalance' => $totals['remainingBalance'],
                'isFullyPaid' => $totals['isFullyPaid'],
                'hasDepositPaid' => $totals['hasDepositPaid'],
                'depositPaidAt' => $totals['depositPaidAt'],
                'status' => $totals['status'],
            ]),
        ]);
        
        return true;
    }
    
    private function handlePaymentIntentFailed(string $estimateId, string $eventId, array $data): bool|WP_Error
    {
        $paymentIntentId = $data['id'] ?? null;
        
        $meta = $this->portalMetaRepo->get($estimateId);
        $payment = $meta['payment'] ?? [];
        $payments = $payment['payments'] ?? [];
        
        foreach ($payments as $index => $p) {
            if (($p['paymentIntentId'] ?? '') === $paymentIntentId) {
                $payments[$index]['status'] = 'failed';
                $payments[$index]['stripeEventId'] = $eventId;
                break;
            }
        }
        
        $this->portalMetaRepo->merge($estimateId, [
            'payment' => array_merge($payment, [
                'payments' => $payments,
            ]),
        ]);
        
        return true;
    }
    
    private function handleChargeRefunded(string $estimateId, string $eventId, array $data): bool|WP_Error
    {
        $paymentIntentId = $data['payment_intent'] ?? null;
        $refundAmount = isset($data['amount']) ? ($data['amount'] / 100) : 0;
        
        if (empty($paymentIntentId)) {
            return new WP_Error('invalid_event', __('Payment intent ID missing from refund event.', 'cheapalarms'), ['status' => 400]);
        }
        
        $meta = $this->portalMetaRepo->get($estimateId);
        $payment = $meta['payment'] ?? [];
        $payments = $payment['payments'] ?? [];
        
        $depositRefunded = false;
        
        foreach ($payments as $index => $p) {
            if (($p['paymentIntentId'] ?? '') === $paymentIntentId) {
                $payments[$index]['refunded'] = true;
                $payments[$index]['refundedAt'] = current_time('mysql');
                $payments[$index]['refundAmount'] = $refundAmount;
                
                if (($p['paymentType'] ?? '') === 'deposit') {
                    $depositRefunded = true;
                }
                break;
            }
        }
        
        // Recompute totals
        $invoiceTotal = $meta['invoice']['total'] ?? $meta['invoice']['ghl']['total'] ?? 0;
        $totals = $this->computePaymentTotals($payments, $invoiceTotal);
        
        // Update hasDepositPaid if deposit was refunded
        $hasDepositPaid = $totals['hasDepositPaid'] && !$depositRefunded;
        
        $this->portalMetaRepo->merge($estimateId, [
            'payment' => array_merge($payment, [
                'payments' => $payments,
                'totalPaid' => $totals['totalPaid'],
                'remainingBalance' => $totals['remainingBalance'],
                'hasDepositPaid' => $hasDepositPaid,
                'status' => $totals['status'],
            ]),
        ]);
        
        return true;
    }
    
    private function computePaymentTotals(array $payments, float $invoiceTotal): array
    {
        $totalPaid = 0;
        $depositPaid = false;
        $depositPaidAt = null;
        
        foreach ($payments as $p) {
            if (($p['status'] ?? '') === 'succeeded' && !($p['refunded'] ?? false)) {
                $totalPaid += (float) ($p['amount'] ?? 0);
                if (($p['paymentType'] ?? '') === 'deposit') {
                    $depositPaid = true;
                    $depositPaidAt = $depositPaidAt ?: ($p['paidAt'] ?? null);
                }
            }
        }
        
        $remainingBalance = max(0, $invoiceTotal - $totalPaid);
        $isFullyPaid = ($totalPaid >= $invoiceTotal);
        
        return [
            'totalPaid' => $totalPaid,
            'remainingBalance' => $remainingBalance,
            'isFullyPaid' => $isFullyPaid,
            'hasDepositPaid' => $depositPaid,
            'depositPaidAt' => $depositPaidAt,
            'status' => $isFullyPaid ? 'paid' : ($totalPaid > 0 ? 'partial' : 'pending'),
        ];
    }
}
