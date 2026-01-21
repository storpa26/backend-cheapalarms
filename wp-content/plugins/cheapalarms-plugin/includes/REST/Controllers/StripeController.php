<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\REST\Controllers\Base\AdminController;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\StripeService;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

use function current_time;
use function delete_transient;
use function get_transient;
use function is_wp_error;
use function sanitize_text_field;
use function set_transient;
use function wp_schedule_single_event;

class StripeController extends AdminController
{
    private StripeService $stripeService;
    private Authenticator $auth;

    public function __construct(Container $container)
    {
        parent::__construct($container);
        $this->stripeService = $this->container->get(StripeService::class);
        $this->auth = $this->container->get(Authenticator::class);
    }

    public function register(): void
    {
        // Create payment intent
        register_rest_route('ca/v1', '/stripe/create-payment-intent', [
            'methods' => 'POST',
            'permission_callback' => fn () => $this->requirePortalOrAdmin(),
            'callback' => fn (WP_REST_Request $request) => $this->createPaymentIntent($request),
        ]);

        // Confirm payment intent (verify payment was successful)
        register_rest_route('ca/v1', '/stripe/confirm-payment-intent', [
            'methods' => 'POST',
            'permission_callback' => fn () => $this->requirePortalOrAdmin(),
            'callback' => fn (WP_REST_Request $request) => $this->confirmPaymentIntent($request),
        ]);

        // Get client secret for existing payment intent (for reused payment intents)
        register_rest_route('ca/v1', '/stripe/get-client-secret', [
            'methods' => 'GET',
            'permission_callback' => fn () => $this->requirePortalOrAdmin(),
            'callback' => fn (WP_REST_Request $request) => $this->getClientSecret($request),
        ]);

        // Check payment intent status (for pre-confirmation validation)
        register_rest_route('ca/v1', '/stripe/check-payment-intent-status', [
            'methods' => 'POST',
            'permission_callback' => fn () => $this->requirePortalOrAdmin(),
            'callback' => fn (WP_REST_Request $request) => $this->checkPaymentIntentStatus($request),
        ]);

        // Handle Stripe webhook events
        register_rest_route('ca/v1', '/stripe/webhook', [
            'methods' => 'POST',
            'permission_callback' => '__return_true', // Public (verified by signature)
            'callback' => fn (WP_REST_Request $request) => $this->handleWebhook($request),
        ]);
    }

    /**
     * Require portal or admin capability (used in permission callbacks)
     */
    private function requirePortalOrAdmin()
    {
        $this->ensureUserLoaded();
        $portalCheck = $this->auth->requireCapability('ca_access_portal');
        if (!is_wp_error($portalCheck)) {
            return true;
        }
        $adminCheck = $this->auth->requireCapability('ca_manage_portal');
        return is_wp_error($adminCheck) ? $portalCheck : true;
    }

    /**
     * Calculate minimum payment amount based on invoice, deposit, and payment history
     * 
     * Business Rules:
     * - First payment (before work): Can be partial - Use deposit if configured, otherwise 25% of invoice or $50 (whichever is higher)
     * - Second payment (after work): MUST be full remaining balance (no partials allowed - only 2 installments total)
     * - If remaining balance < $10: Require full remaining balance
     * - If invoice < $50: Require full payment (no partials allowed)
     * 
     * @param float $invoiceTotal Total invoice amount
     * @param float $existingPaidAmount Amount already paid
     * @param array $invoice Invoice data (contains depositRequired, depositAmount, depositType)
     * @return float Minimum payment amount (rounded to 2 decimals)
     */
    private function calculateMinimumPayment(float $invoiceTotal, float $existingPaidAmount, array $invoice): float
    {
        // Constants
        $MINIMUM_PAYMENT_FIRST_PERCENTAGE = 0.25; // 25% of invoice
        $MINIMUM_ABSOLUTE_FLOOR = 50.00; // $50 AUD minimum
        $MINIMUM_FINAL_THRESHOLD = 10.00; // If remaining < $10, require full

        // Calculate remaining balance
        $remainingBalance = max(0, $invoiceTotal - $existingPaidAmount);

        // If invoice is very small (< $50), require full payment
        if ($invoiceTotal < $MINIMUM_ABSOLUTE_FLOOR) {
            return round($invoiceTotal, 2);
        }

        // If remaining balance is very small (< $10), require full remaining
        if ($remainingBalance < $MINIMUM_FINAL_THRESHOLD) {
            return round($remainingBalance, 2);
        }

        // Determine minimum based on payment status (first vs subsequent)
        $isFirstPayment = ($existingPaidAmount == 0);

        if ($isFirstPayment) {
            // First payment (before work): Can be partial
            // Check for deposit requirement
            $depositRequired = $invoice['depositRequired'] ?? false;
            
            if ($depositRequired) {
                $depositType = $invoice['depositType'] ?? 'fixed';
                $depositAmount = (float) ($invoice['depositAmount'] ?? 0);

                if ($depositType === 'percentage') {
                    // Calculate deposit from percentage of invoice total
                    $depositAmount = ($invoiceTotal * $depositAmount) / 100;
                }

                // Deposit minimum: use deposit amount or $50, whichever is higher
                $minimum = max($depositAmount, $MINIMUM_ABSOLUTE_FLOOR);
            } else {
                // No deposit: use 25% of invoice or $50, whichever is higher
                $percentageMinimum = $invoiceTotal * $MINIMUM_PAYMENT_FIRST_PERCENTAGE;
                $minimum = max($percentageMinimum, $MINIMUM_ABSOLUTE_FLOOR);
            }

            // Cap minimum at invoice total (deposit can't exceed total)
            $minimum = min($minimum, $invoiceTotal);
        } else {
            // Second payment (after work): MUST be full remaining balance
            // Only 2 installments allowed: before work (partial) and after work (full)
            $minimum = $remainingBalance;
        }

        // Final check: if remaining balance < calculated minimum, require full remaining
        if ($remainingBalance < $minimum) {
            return round($remainingBalance, 2);
        }

        return round($minimum, 2);
    }

    private function createPaymentIntent(WP_REST_Request $request): WP_REST_Response
    {
        $body = $request->get_json_params();
        $amount = isset($body['amount']) ? (float) $body['amount'] : null;
        $currency = sanitize_text_field($body['currency'] ?? 'aud');
        $metadata = $body['metadata'] ?? [];
        $estimateId = sanitize_text_field($body['estimateId'] ?? $metadata['estimateId'] ?? '');

        // SECURITY: Require estimateId to validate payment amount against invoice total
        // This prevents users from creating payment intents with manipulated amounts
        if (empty($estimateId)) {
            return $this->respond(new WP_Error(
                'missing_estimate_id',
                __('Estimate ID is required to create payment intent.', 'cheapalarms'),
                ['status' => 400]
            ));
        }

        if (!preg_match('/^[\w-]+$/', $estimateId)) {
            return $this->respond(new WP_Error(
                'invalid_estimate_id',
                __('Invalid estimateId format.', 'cheapalarms'),
                ['status' => 400]
            ));
        }

        // Verify user has access to this estimate
        $portalService = $this->container->get(\CheapAlarms\Plugin\Services\PortalService::class);
        $user = wp_get_current_user();
        $status = $portalService->getStatus($estimateId, '', null, $user);
        if (is_wp_error($status)) {
            return $this->respond(new WP_Error(
                'unauthorized_estimate',
                __('You do not have access to this estimate.', 'cheapalarms'),
                ['status' => 403]
            ));
        }

        // Get invoice total from portal meta for validation
        $portalMetaRepo = $this->container->get(\CheapAlarms\Plugin\Services\Shared\PortalMetaRepository::class);
        $meta = $portalMetaRepo->get($estimateId);
        $invoice = $meta['invoice'] ?? null;

        if (!$invoice) {
            return $this->respond(new WP_Error(
                'no_invoice',
                __('Invoice not found for this estimate. Please create an invoice first.', 'cheapalarms'),
                ['status' => 400]
            ));
        }

        // SECURITY: Prevent creating payment intents for already-paid invoices
        // This prevents duplicate payment attempts and potential confusion
        $existingPayment = $meta['payment'] ?? null;
        if (!empty($existingPayment['status']) && $existingPayment['status'] === 'paid') {
            return $this->respond(new WP_Error(
                'already_paid',
                __('This invoice has already been paid. Cannot create a new payment intent.', 'cheapalarms'),
                ['status' => 400]
            ));
        }

        // Get invoice total for validation
        $invoiceTotal = null;
        if (isset($invoice['ghl']['total'])) {
            $invoiceTotal = (float) $invoice['ghl']['total'];
        } elseif (isset($invoice['total'])) {
            $invoiceTotal = (float) $invoice['total'];
        }

        if ($invoiceTotal === null || $invoiceTotal <= 0) {
            return $this->respond(new WP_Error(
                'invalid_invoice',
                __('Invalid invoice total. Cannot create payment intent.', 'cheapalarms'),
                ['status' => 400]
            ));
        }

        // Validate amount
        if ($amount === null || $amount <= 0) {
            return $this->respond(new WP_Error(
                'invalid_amount',
                __('Payment amount is required and must be greater than zero.', 'cheapalarms'),
                ['status' => 400]
            ));
        }

        // Calculate existing paid amount for minimum payment calculation
        // FIXED: Use consistent calculation logic (exclude refunded payments)
        $existingPaidAmount = $this->calculateExistingPaidAmount($meta);

        // Calculate minimum payment requirement
        $minimumPayment = $this->calculateMinimumPayment($invoiceTotal, $existingPaidAmount, $invoice);
        $remainingBalance = max(0, $invoiceTotal - $existingPaidAmount);

        // SECURITY: Validate amount meets minimum payment requirement
        if ($amount < $minimumPayment) {
            // Allow small tolerance for rounding (0.01)
            if (abs($amount - $minimumPayment) > 0.01) {
                $isSubsequentPayment = ($existingPaidAmount > 0);
                $errorMessage = $isSubsequentPayment
                    ? sprintf(
                        __('Second payment must be the full remaining balance of %s. Only 2 installments allowed: before work (partial) and after work (full).', 'cheapalarms'),
                        number_format($minimumPayment, 2)
                    )
                    : sprintf(
                        __('Payment amount must be at least %s. Minimum payment: %s', 'cheapalarms'),
                        number_format($minimumPayment, 2),
                        number_format($minimumPayment, 2)
                    );
                
                return $this->respond(new WP_Error(
                    'amount_below_minimum',
                    $errorMessage,
                    [
                        'status' => 400,
                        'minimumPayment' => $minimumPayment,
                        'remainingBalance' => $remainingBalance,
                        'invoiceTotal' => $invoiceTotal,
                        'existingPaidAmount' => $existingPaidAmount,
                        'isSubsequentPayment' => $isSubsequentPayment,
                    ]
                ));
            }
        }

        // SECURITY: Validate amount against invoice total
        // Allow partial payments (up to invoice total), but prevent overpayment
        // Note: existingPaidAmount already calculated above for minimum payment check
        $totalAfterPayment = $existingPaidAmount + $amount;
        if ($totalAfterPayment > $invoiceTotal) {
            return $this->respond(new WP_Error(
                'amount_exceeds_invoice',
                sprintf(
                    __('Total payment amount (%.2f) would exceed invoice total (%.2f). Remaining balance: %.2f', 'cheapalarms'),
                    $totalAfterPayment,
                    $invoiceTotal,
                    max(0, $invoiceTotal - $existingPaidAmount)
                ),
                [
                    'status' => 400,
                    'invoiceTotal' => $invoiceTotal,
                    'existingPaidAmount' => $existingPaidAmount,
                    'amountProvided' => $amount,
                    'totalAfterPayment' => $totalAfterPayment,
                    'remainingBalance' => max(0, $invoiceTotal - $existingPaidAmount),
                ]
            ));
        }

        // SECURITY: Use lock to prevent race conditions during payment intent creation
        $lockKey = 'ca_payment_intent_lock_' . $estimateId;
        $lockValue = get_transient($lockKey);
        if ($lockValue !== false) {
            // Check if lock is stale (older than 5 seconds)
            $lockAge = time() - (int)$lockValue;
            if ($lockAge > 5) {
                delete_transient($lockKey);
            } else {
                // Lock is active - another request is creating payment intent
                return $this->respond(new WP_Error(
                    'processing',
                    __('Payment is being processed. Please wait a moment and try again.', 'cheapalarms'),
                    ['status' => 409]
                ));
            }
        }
        
        // Set lock
        set_transient($lockKey, time(), 5);

        try {
            // FIXED: Generate stable idempotency key (no time() - defeats idempotency)
            // Format: pi_{estimateId}_{amountFixed2}_{currency}_{revisionNumber}
            // Note: This key ensures that retries of the same request (same estimate, amount, currency, revision)
            // will reuse the same PaymentIntent, preventing duplicate charges. If the existing PaymentIntent
            // is succeeded/canceled, the code below will create a new one (bypassing this idempotency key).
            $revisionNumber = $meta['quote']['revisionNumber'] ?? 0;
            $idempotencyKey = sprintf(
                'pi_%s_%s_%s_%d',
                $estimateId,
                number_format($amount, 2, '.', ''), // Stable decimal format (e.g., "500.00")
                strtolower($currency),
                $revisionNumber
            );

            // Check for existing payment intent with same parameters
            $existingIntentId = $meta['payment']['paymentIntentId'] ?? null;
            $existingAmount = $meta['payment']['amount'] ?? null;
            $existingCurrency = $meta['payment']['currency'] ?? 'aud';

            // Reuse existing payment intent if amount, currency, and revision match
            // FIXED: Check status FIRST, then expiry to prevent race conditions
            if ($existingIntentId && 
                $existingAmount === $amount && 
                $existingCurrency === $currency &&
                ($meta['quote']['revisionNumber'] ?? 0) === $revisionNumber) {
                
                // Retrieve existing payment intent to check status FIRST (before checking expiry)
                $existingIntent = $this->stripeService->getPaymentIntent($existingIntentId);
                
                if (is_wp_error($existingIntent)) {
                    // FIXED: Log error but keep lock (will create new payment intent)
                    // Lock remains active from line 314, will be used for new intent creation
                    $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
                    $logger->warning('Failed to retrieve existing payment intent for reuse', [
                        'estimateId' => $estimateId,
                        'paymentIntentId' => $existingIntentId,
                        'error' => $existingIntent->get_error_message(),
                    ]);
                    // Continue to payment intent creation below (lock already set)
                } else {
                    // Check if payment intent is in a reusable state
                    $status = $existingIntent['status'] ?? '';
                    $reusableStates = ['requires_payment_method', 'requires_confirmation'];
                    $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
                    
                    // SECURITY: Explicitly prevent reusing PaymentIntents that have already succeeded
                    // This prevents the "payment_intent_unexpected_state" error
                    if ($status === 'succeeded') {
                        $logger->info('Payment intent already succeeded, creating new one', [
                            'estimateId' => $estimateId,
                            'paymentIntentId' => $existingIntentId,
                            'status' => $status,
                        ]);
                        // Explicitly skip reuse - execution continues below to create new payment intent
                        // Lock remains active for new payment intent creation (set at line 322)
                        // Note: This block intentionally falls through - new intent will be created after this if/elseif/else block
                    }
                    // Only proceed if status is reusable
                    elseif (in_array($status, $reusableStates)) {
                        // Now check expiry (after confirming status is valid)
                        $expiresAt = $meta['payment']['paymentIntentExpiresAt'] ?? null;
                        if ($expiresAt && time() < (int)$expiresAt) {
                            $clientSecret = $existingIntent['client_secret'] ?? null;
                            
                            if ($clientSecret) {
                                // FIXED: Release lock before returning (payment intent reused, no new creation needed)
                                delete_transient($lockKey);
                                return $this->respond([
                                    'ok' => true,
                                    'clientSecret' => $clientSecret,
                                    'paymentIntentId' => $existingIntentId,
                                    'amount' => $amount,
                                    'currency' => $currency,
                                    'reused' => true,
                                ]);
                            }
                        }
                        // If expired or no client secret, create new payment intent
                        // Lock remains active (will be used for new intent creation)
                    } else {
                        // If status is not reusable (e.g., 'canceled', 'processing', etc.), create new payment intent
                        // Lock remains active (will be used for new intent creation)
                        $logger->info('Payment intent not reusable, creating new one', [
                            'estimateId' => $estimateId,
                            'paymentIntentId' => $existingIntentId,
                            'status' => $status,
                        ]);
                    }
                }
                // Lock remains active for new payment intent creation (set at line 314)
            }

            // ALWAYS include estimateId in metadata (required for webhook processing)
            $paymentMetadata = array_merge($metadata, [
                'estimateId' => $estimateId, // REQUIRED - never omit
                'invoiceId' => $meta['invoice']['ghl']['id'] ?? $meta['invoice']['id'] ?? '',
                'revisionNumber' => (string)$revisionNumber,
            ]);

            // Create payment intent with stable idempotency key
            $result = $this->stripeService->createPaymentIntent($amount, $currency, $paymentMetadata, $idempotencyKey);

            if (is_wp_error($result)) {
                delete_transient($lockKey);
                return $this->respond($result);
            }

            // SECURITY: Store payment intent details in portal meta for validation during confirmation
            // This ensures the amount cannot be manipulated between creation and confirmation
            $expiresAt = current_time('timestamp') + 30 * 60; // 30 minutes TTL

            $portalMetaRepo->merge($estimateId, [
                'payment' => array_merge($meta['payment'] ?? [], [
                    'paymentIntentId' => $result['paymentIntentId'] ?? null,
                    'amount' => $amount,
                    'invoiceTotal' => $invoiceTotal,
                    'currency' => $currency,
                    'createdAt' => current_time('mysql'),
                    'paymentIntentExpiresAt' => $expiresAt,
                ]),
            ]);

            // Release lock
            delete_transient($lockKey);

            return $this->respond($result);
        } catch (\Exception $e) {
            // Release lock on error
            delete_transient($lockKey);
            $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
            $logger->error('Exception during payment intent creation', [
                'estimateId' => $estimateId,
                'error' => $e->getMessage(),
            ]);
            return $this->respond(new WP_Error(
                'payment_intent_creation_error',
                __('An error occurred while creating payment intent. Please try again.', 'cheapalarms'),
                ['status' => 500]
            ));
        }
    }

    private function getClientSecret(WP_REST_Request $request): WP_REST_Response
    {
        $paymentIntentId = sanitize_text_field($request->get_param('paymentIntentId') ?? '');
        
        if (empty($paymentIntentId)) {
            return $this->respond(new WP_Error('missing_payment_intent_id', __('Payment intent ID is required.', 'cheapalarms'), ['status' => 400]));
        }

        // Retrieve payment intent from Stripe
        $paymentIntent = $this->stripeService->getPaymentIntent($paymentIntentId);
        
        if (is_wp_error($paymentIntent)) {
            return $this->respond($paymentIntent);
        }

        // Check if payment intent is in a state that allows payment
        $status = $paymentIntent['status'] ?? '';
        $reusableStates = ['requires_payment_method', 'requires_confirmation'];
        
        if (!in_array($status, $reusableStates)) {
            return $this->respond(new WP_Error(
                'invalid_payment_intent_status',
                sprintf(__('Payment intent is in "%s" status and cannot be used for payment. Please create a new payment intent.', 'cheapalarms'), $status),
                ['status' => 400, 'paymentIntentStatus' => $status]
            ));
        }

        $clientSecret = $paymentIntent['client_secret'] ?? null;
        
        if (empty($clientSecret)) {
            return $this->respond(new WP_Error(
                'no_client_secret',
                __('Client secret not available for this payment intent. The payment intent may have been completed or cancelled.', 'cheapalarms'),
                ['status' => 404]
            ));
        }

        return $this->respond([
            'ok' => true,
            'clientSecret' => $clientSecret,
            'paymentIntentId' => $paymentIntentId,
        ]);
    }

    /**
     * Check PaymentIntent status before confirmation
     * Used to prevent reusing already-succeeded PaymentIntents
     * 
     * @param WP_REST_Request $request
     * @return WP_REST_Response
     */
    private function checkPaymentIntentStatus(WP_REST_Request $request): WP_REST_Response
    {
        $body = $request->get_json_params();
        $paymentIntentId = sanitize_text_field($body['paymentIntentId'] ?? '');
        
        if (empty($paymentIntentId)) {
            return $this->respond(new WP_Error('missing_payment_intent_id', __('Payment intent ID is required.', 'cheapalarms'), ['status' => 400]));
        }
        
        // Retrieve payment intent from Stripe
        $paymentIntent = $this->stripeService->getPaymentIntent($paymentIntentId);
        
        if (is_wp_error($paymentIntent)) {
            return $this->respond($paymentIntent);
        }
        
        $status = $paymentIntent['status'] ?? 'unknown';
        
        return $this->respond([
            'ok' => true,
            'status' => $status,
            'paymentIntent' => $paymentIntent,
        ]);
    }

    private function confirmPaymentIntent(WP_REST_Request $request): WP_REST_Response
    {
        $body = $request->get_json_params();
        $paymentIntentId = sanitize_text_field($body['paymentIntentId'] ?? '');
        $estimateId = sanitize_text_field($body['estimateId'] ?? '');

        if (empty($paymentIntentId)) {
            return $this->respond(new WP_Error('missing_payment_intent_id', __('Payment intent ID is required.', 'cheapalarms'), ['status' => 400]));
        }

        // SECURITY: Require estimateId to validate payment intent ownership
        // This prevents users from confirming payment intents that belong to other users' estimates
        if (empty($estimateId)) {
            return $this->respond(new WP_Error(
                'missing_estimate_id',
                __('Estimate ID is required to confirm payment intent.', 'cheapalarms'),
                ['status' => 400]
            ));
        }

        // Validate estimateId format
        if (!preg_match('/^[\w-]+$/', $estimateId)) {
            return $this->respond(new WP_Error(
                'invalid_estimate_id',
                __('Invalid estimateId format.', 'cheapalarms'),
                ['status' => 400]
            ));
        }

        // SECURITY: Use lock to prevent duplicate confirmations (idempotency)
        $lockKey = 'ca_confirm_payment_intent_lock_' . $estimateId . '_' . $paymentIntentId;
        $lockValue = get_transient($lockKey);
        if ($lockValue !== false) {
            // Check if lock is stale (older than 10 seconds)
            $lockAge = time() - (int)$lockValue;
            if ($lockAge > 10) {
                delete_transient($lockKey);
            } else {
                // Lock is active - another request is confirming this payment intent
                $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
                $logger->warning('Duplicate payment intent confirmation attempt prevented', [
                    'estimateId' => $estimateId,
                    'paymentIntentId' => $paymentIntentId,
                ]);
                return $this->respond(new WP_Error(
                    'processing',
                    __('Payment confirmation is already in progress. Please wait a moment.', 'cheapalarms'),
                    ['status' => 409]
                ));
            }
        }
        
        // Set lock
        set_transient($lockKey, time(), 10);

        try {
            $portalService = $this->container->get(\CheapAlarms\Plugin\Services\PortalService::class);
            $user = wp_get_current_user();
            
            // Verify user has access to this estimate
            $status = $portalService->getStatus($estimateId, '', null, $user);
            if (is_wp_error($status)) {
                delete_transient($lockKey);
                return $this->respond(new WP_Error(
                    'unauthorized_estimate',
                    __('You do not have access to this estimate.', 'cheapalarms'),
                    ['status' => 403]
                ));
            }
            
            // Validate paymentIntentId against stored value in portal meta
            // Get portal meta via repository to check stored paymentIntentId
            $portalMetaRepo = $this->container->get(\CheapAlarms\Plugin\Services\Shared\PortalMetaRepository::class);
            $meta = $portalMetaRepo->get($estimateId);
            $storedPaymentIntentId = $meta['payment']['paymentIntentId'] ?? null;
            $storedAmount = $meta['payment']['amount'] ?? null;
            $invoiceTotal = $meta['payment']['invoiceTotal'] ?? null;
            $expiresAt = $meta['payment']['paymentIntentExpiresAt'] ?? null;

            // Expiry check to prevent reusing stale intents
            if (!empty($expiresAt) && time() > (int) $expiresAt) {
                $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
                $logger->warning('Payment intent expired', [
                    'estimateId' => $estimateId,
                    'paymentIntentId' => $paymentIntentId,
                    'expiresAt' => $expiresAt,
                ]);
                delete_transient($lockKey);
                return $this->respond(new WP_Error(
                    'payment_intent_expired',
                    __('Payment intent has expired. Please create a new payment intent.', 'cheapalarms'),
                    ['status' => 400]
                ));
            }
            
            // SECURITY: Require stored payment intent ID (no null bypass)
            // This prevents users from confirming payment intents that weren't created for this estimate
            if (empty($storedPaymentIntentId)) {
                $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
                $logger->warning('Payment intent confirmation attempted without stored payment intent ID', [
                    'estimateId' => $estimateId,
                    'providedPaymentIntentId' => $paymentIntentId,
                ]);
                delete_transient($lockKey);
                return $this->respond(new WP_Error(
                    'no_payment_intent',
                    __('No payment intent found for this estimate. Please create a payment intent first.', 'cheapalarms'),
                    ['status' => 400]
                ));
            }
            
            // SECURITY: Validate payment intent ID matches stored value
            if ($storedPaymentIntentId !== $paymentIntentId) {
                $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
                $logger->warning('Payment intent ID mismatch', [
                    'estimateId' => $estimateId,
                    'providedPaymentIntentId' => $paymentIntentId,
                    'storedPaymentIntentId' => $storedPaymentIntentId,
                ]);
                delete_transient($lockKey);
                return $this->respond(new WP_Error(
                    'payment_intent_mismatch',
                    __('Payment intent does not match this estimate.', 'cheapalarms'),
                    ['status' => 400]
                ));
            }

            // Retrieve payment intent from Stripe to verify status and amount
            $result = $this->stripeService->confirmPaymentIntent($paymentIntentId);

            if (is_wp_error($result)) {
                delete_transient($lockKey);
                return $this->respond($result);
            }

            // SECURITY: Validate payment intent amount against stored/invoice amount
            // This prevents confirming payment intents with manipulated amounts
            $paymentIntentAmount = $result['amount'] ?? 0; // Already converted from cents in StripeService
            $currency = $result['currency'] ?? 'aud';
            
            if ($storedAmount !== null) {
                // Validate against stored amount (tolerance for floating point precision)
                if (abs($paymentIntentAmount - $storedAmount) > 0.01) {
                    $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
                    $logger->warning('Payment intent amount mismatch', [
                        'estimateId' => $estimateId,
                        'paymentIntentAmount' => $paymentIntentAmount,
                        'storedAmount' => $storedAmount,
                        'paymentIntentId' => $paymentIntentId,
                    ]);
                    delete_transient($lockKey);
                    return $this->respond(new WP_Error(
                        'amount_mismatch',
                        sprintf(
                            __('Payment intent amount (%.2f) does not match expected amount (%.2f).', 'cheapalarms'),
                            $paymentIntentAmount,
                            $storedAmount
                        ),
                        ['status' => 400, 'expectedAmount' => $storedAmount, 'actualAmount' => $paymentIntentAmount]
                    ));
                }
            } elseif ($invoiceTotal !== null) {
                // Fallback: validate against invoice total if stored amount not available
                // Use tolerance for floating point precision (0.01 = 1 cent)
                // This prevents false positives when amounts are equal within rounding error
                $tolerance = 0.01;
                if ($paymentIntentAmount > ($invoiceTotal + $tolerance)) {
                    $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
                    $logger->warning('Payment intent amount exceeds invoice total', [
                        'estimateId' => $estimateId,
                        'paymentIntentAmount' => $paymentIntentAmount,
                        'invoiceTotal' => $invoiceTotal,
                        'paymentIntentId' => $paymentIntentId,
                    ]);
                    delete_transient($lockKey);
                    return $this->respond(new WP_Error(
                        'amount_exceeds_invoice',
                    sprintf(
                        __('Payment intent amount (%.2f) exceeds invoice total (%.2f).', 'cheapalarms'),
                        $paymentIntentAmount,
                        $invoiceTotal
                    ),
                    ['status' => 400, 'invoiceTotal' => $invoiceTotal, 'actualAmount' => $paymentIntentAmount]
                ));
            }
        }

            // Update payment records in portal meta
            $payment = $meta['payment'] ?? [];
            $payments = $payment['payments'] ?? [];
            
            // Check for duplicate payment (idempotency)
            $isDuplicate = false;
            $paymentRecord = null;

            foreach ($payments as $existingPayment) {
                if (($existingPayment['paymentIntentId'] ?? '') === $paymentIntentId) {
                    // Payment already recorded - return existing record (idempotency)
                    $isDuplicate = true;
                    $paymentRecord = $existingPayment;
                    $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
                    $logger->info('Duplicate payment confirmation detected and prevented', [
                        'estimateId' => $estimateId,
                        'paymentIntentId' => $paymentIntentId,
                    ]);
                    delete_transient($lockKey);
                    return $this->respond([
                        'ok' => true,
                        'paymentIntent' => $result,
                        'payment' => $paymentRecord,
                        'duplicate' => true,
                    ]);
                }
            }

        if (!$isDuplicate) {
            // Determine payment type
            $invoice = $meta['invoice'] ?? [];
            $depositRequired = $invoice['depositRequired'] ?? false;
            $hasDepositPaid = $payment['hasDepositPaid'] ?? false;
            $paymentType = ($depositRequired && !$hasDepositPaid) ? 'deposit' : 'final';
            
            // Create new payment record
            $paymentRecord = [
                'paymentIntentId' => $paymentIntentId,
                'amount' => $paymentIntentAmount,
                'currency' => $currency,
                'paymentType' => $paymentType,
                'status' => 'succeeded',
                'provider' => 'stripe', // FIX 1: Set provider to 'stripe' for Stripe payments
                'transactionId' => $paymentIntentId, // FIX 1: Set transactionId for consistency with PortalService
                'stripeEventId' => null, // Will be set when webhook arrives
                'paidAt' => current_time('mysql'),
                'refunded' => false,
                'refundedAt' => null,
                'refundAmount' => null,
            ];
            
                $payments[] = $paymentRecord;
            }

            // Compute totals using helper method
            $invoiceTotal = $meta['invoice']['total'] ?? $meta['invoice']['ghl']['total'] ?? $invoiceTotal ?? 0;
            $totals = $this->computePaymentTotals($payments, $invoiceTotal);

            // Update workflow status based on payment status
            $workflow = $meta['workflow'] ?? [];
            if ($totals['isFullyPaid']) {
                $workflow['status'] = 'paid';
                $workflow['currentStep'] = 5;
                $workflow['paidAt'] = current_time('mysql');
            } else {
                // Keep status as "booked" if partial payment (or keep existing if no payment yet)
                if ($totals['totalPaid'] > 0) {
                    $workflow['status'] = 'booked';
                }
                // Otherwise keep existing status (might be 'accepted')
            }
            
            // Preserve existing timestamps (consistent with PortalService.php)
            if (!isset($workflow['requestedAt']) && isset($meta['workflow']['requestedAt'])) {
                $workflow['requestedAt'] = $meta['workflow']['requestedAt'];
            }
            if (!isset($workflow['reviewedAt']) && isset($meta['workflow']['reviewedAt'])) {
                $workflow['reviewedAt'] = $meta['workflow']['reviewedAt'];
            }
            if (!isset($workflow['acceptedAt']) && isset($meta['workflow']['acceptedAt'])) {
                $workflow['acceptedAt'] = $meta['workflow']['acceptedAt'];
            }
            if (!isset($workflow['bookedAt']) && isset($meta['workflow']['bookedAt'])) {
                $workflow['bookedAt'] = $meta['workflow']['bookedAt'];
            }

            // Update payment meta
            $paymentUpdate = [
                'payment' => array_merge($payment, [
                    'payments' => $payments,
                    'totalPaid' => $totals['totalPaid'],
                    'remainingBalance' => $totals['remainingBalance'],
                    'isFullyPaid' => $totals['isFullyPaid'],
                    'hasDepositPaid' => $totals['hasDepositPaid'],
                    'depositPaidAt' => $totals['depositPaidAt'],
                    'status' => $totals['status'],
                    // FIXED: Clear paymentIntentId after payment is confirmed to allow creating new payment intents
                    // The payment intent ID is preserved in the payments array for tracking
                    'paymentIntentId' => null,
                    'paymentIntentExpiresAt' => null,
                    // Backward compatibility
                    'amount' => $paymentIntentAmount,
                    'invoiceTotal' => $invoiceTotal,
                ]),
            ];

            // FIXED: Also update workflow status
            $portalMetaRepo->merge($estimateId, array_merge($paymentUpdate, [
                'workflow' => $workflow,
            ]));

            // Release lock before returning success
            delete_transient($lockKey);

            return $this->respond($result);
        } catch (\Exception $e) {
            // Release lock on exception
            delete_transient($lockKey);
            $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
            $logger->error('Exception during payment intent confirmation', [
                'estimateId' => $estimateId,
                'paymentIntentId' => $paymentIntentId,
                'error' => $e->getMessage(),
            ]);
            return $this->respond(new WP_Error(
                'payment_intent_confirmation_error',
                __('An error occurred while confirming payment intent. Please try again.', 'cheapalarms'),
                ['status' => 500]
            ));
        }
    }

    /**
     * Compute payment totals from payments array
     * 
     * @param array $payments Array of payment records
     * @param float $invoiceTotal Total invoice amount
     * @return array Computed totals
     */
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

    /**
     * Handle Stripe webhook events
     * 
     * FIXED: Return 200 fast, process async via WP-Cron
     * This prevents Stripe timeouts and retries
     * 
     * Route: POST /ca/v1/stripe/webhook
     */
    public function handleWebhook(WP_REST_Request $request): WP_REST_Response
    {
        // Read raw body (don't use get_json_params - need raw for signature)
        $payload = $request->get_body();
        $signature = $request->get_header('Stripe-Signature');
        
        if (empty($payload) || empty($signature)) {
            return $this->respond(new WP_Error(
                'bad_request',
                __('Missing webhook payload or signature.', 'cheapalarms'),
                ['status' => 400]
            ));
        }
        
        // Verify webhook signature FIRST (must be fast)
        $config = $this->container->get(\CheapAlarms\Plugin\Config\Config::class);
        $webhookSecret = $config->getStripeWebhookSecret();
        if (empty($webhookSecret)) {
            $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
            $logger->error('Stripe webhook secret not configured');
            return $this->respond(new WP_Error(
                'configuration_error',
                __('Webhook secret not configured.', 'cheapalarms'),
                ['status' => 500]
            ));
        }
        
        // FIXED: Use Stripe library for signature verification
        $isValid = $this->verifyWebhookSignature($payload, $signature, $webhookSecret);
        if (!$isValid) {
            $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
            $logger->warning('Invalid webhook signature');
            return $this->respond(new WP_Error(
                'invalid_signature',
                __('Invalid webhook signature.', 'cheapalarms'),
                ['status' => 401]
            ));
        }
        
        // Parse event (must be fast)
        $event = json_decode($payload, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return $this->respond(new WP_Error(
                'parse_error',
                __('Failed to parse webhook payload.', 'cheapalarms'),
                ['status' => 400]
            ));
        }
        
        $eventId = $event['id'] ?? null;
        $eventType = $event['type'] ?? null;
        $eventData = $event['data']['object'] ?? [];
        
        if (empty($eventId) || empty($eventType)) {
            return $this->respond(new WP_Error(
                'invalid_event',
                __('Invalid webhook event structure.', 'cheapalarms'),
                ['status' => 400]
            ));
        }
        
        // FIXED: Get estimateId from metadata (required, fail if missing)
        // NEVER scan WP options - always require metadata
        $estimateId = $eventData['metadata']['estimateId'] ?? null;
        
        if (empty($estimateId)) {
            $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
            $logger->error('Webhook event missing estimateId in metadata', [
                'eventId' => $eventId,
                'eventType' => $eventType,
                'paymentIntentId' => $eventData['id'] ?? null,
            ]);
            
            return $this->respond(new WP_Error(
                'missing_estimate_id',
                __('Webhook event missing estimateId in metadata. Payment intent must include estimateId in metadata.', 'cheapalarms'),
                ['status' => 400]
            ));
        }
        
        // FIXED: Store event BEFORE processing (safe retries)
        $webhookEventRepo = $this->container->get(\CheapAlarms\Plugin\Services\WebhookEventRepository::class);
        
        // Check if already processed
        if ($webhookEventRepo->isProcessed($eventId)) {
            $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
            $logger->info('Webhook event already processed (idempotency)', [
                'eventId' => $eventId,
                'estimateId' => $estimateId,
            ]);
            return $this->respond([
                'ok' => true,
                'eventId' => $eventId,
                'alreadyProcessed' => true,
            ]);
        }
        
        // Store event (idempotent - INSERT IGNORE)
        $isNewEvent = $webhookEventRepo->storeEvent($estimateId, $eventId, $eventType, $payload);
        
        // FIXED: Schedule async processing via WP-Cron (return 200 fast)
        // This prevents Stripe timeouts and retries
        wp_schedule_single_event(time() + 1, 'ca_process_stripe_webhook', [$eventId]);
        
        // Return 200 immediately (event stored, will be processed async)
        $response = $this->respond([
            'ok' => true,
            'eventId' => $eventId,
            'eventType' => $eventType,
            'queued' => true,
            'message' => __('Webhook event received and queued for processing.', 'cheapalarms'),
        ]);
        $response->set_status(200);
        return $response;
    }

    /**
     * FIXED: Use Stripe library for signature verification
     * Handles timestamp tolerance and multiple signatures automatically
     */
    private function verifyWebhookSignature(string $payload, string $signature, string $secret): bool
    {
        // Check if Stripe library is available
        if (!class_exists('\Stripe\Webhook')) {
            $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
            $logger->error('Stripe PHP library not available. Install via: composer require stripe/stripe-php');
            return false;
        }
        
        try {
            // Use Stripe's official verification method
            // Handles timestamp tolerance (default 5 minutes) and multiple signatures
            $event = \Stripe\Webhook::constructEvent($payload, $signature, $secret);
            return true;
        } catch (\Stripe\Exception\SignatureVerificationException $e) {
            $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
            $logger->warning('Webhook signature verification failed', [
                'error' => $e->getMessage(),
            ]);
            return false;
        } catch (\Exception $e) {
            $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
            $logger->error('Webhook verification error', [
                'error' => $e->getMessage(),
            ]);
            return false;
        }
    }

    /**
     * Calculate existing paid amount from meta (excluding refunded payments)
     * 
     * FIXED: Consistent calculation logic used in both StripeController and PortalService
     * Only counts successful, non-refunded payments
     * 
     * @param array $meta Portal meta data
     * @return float Existing paid amount
     */
    private function calculateExistingPaidAmount(array $meta): float
    {
        $existingPaidAmount = 0;
        $existingPayment = $meta['payment'] ?? null;
        
        // If already fully paid (legacy structure), use existing amount
        if (!empty($existingPayment['amount']) && ($existingPayment['status'] ?? '') === 'paid') {
            return (float) $existingPayment['amount'];
        }
        
        // Sum all successful, non-refunded payments from payments array
        if (!empty($meta['payment']['payments']) && is_array($meta['payment']['payments'])) {
            foreach ($meta['payment']['payments'] as $prevPayment) {
                $isSuccessful = ($prevPayment['status'] ?? 'succeeded') === 'succeeded';
                $isRefunded = ($prevPayment['refunded'] ?? false) === true;
                if ($isSuccessful && !$isRefunded && !empty($prevPayment['amount'])) {
                    $existingPaidAmount += (float) $prevPayment['amount'];
                }
            }
        }
        
        return $existingPaidAmount;
    }
}

