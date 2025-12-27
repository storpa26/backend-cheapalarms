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

        if (!preg_match('/^[a-zA-Z0-9]+$/', $estimateId)) {
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

        // SECURITY: Validate amount against invoice total
        // Allow partial payments (up to invoice total), but prevent overpayment
        // Check cumulative payments if partial payments exist
        $existingPaidAmount = 0;
        if (!empty($meta['payment']['payments']) && is_array($meta['payment']['payments'])) {
            foreach ($meta['payment']['payments'] as $prevPayment) {
                if (!empty($prevPayment['amount'])) {
                    $existingPaidAmount += (float) $prevPayment['amount'];
                }
            }
        }
        
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
                    __('Another request is currently creating a payment intent. Please wait a moment and try again.', 'cheapalarms'),
                    ['status' => 409]
                ));
            }
        }
        
        // Set lock
        set_transient($lockKey, time(), 5);

        try {
            // Create payment intent with validated amount
            // Include estimateId in metadata for tracking
            $result = $this->stripeService->createPaymentIntent($amount, $currency, array_merge($metadata, [
                'estimateId' => $estimateId,
            ]));

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
        if (!preg_match('/^[a-zA-Z0-9]+$/', $estimateId)) {
            return $this->respond(new WP_Error(
                'invalid_estimate_id',
                __('Invalid estimateId format.', 'cheapalarms'),
                ['status' => 400]
            ));
        }

        $portalService = $this->container->get(\CheapAlarms\Plugin\Services\PortalService::class);
        $user = wp_get_current_user();
        
        // Verify user has access to this estimate
        $status = $portalService->getStatus($estimateId, '', null, $user);
        if (is_wp_error($status)) {
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
            return $this->respond(new WP_Error(
                'payment_intent_mismatch',
                __('Payment intent does not match this estimate.', 'cheapalarms'),
                ['status' => 400]
            ));
        }

        // Retrieve payment intent from Stripe to verify status and amount
        $result = $this->stripeService->confirmPaymentIntent($paymentIntentId);

        if (is_wp_error($result)) {
            return $this->respond($result);
        }

        // SECURITY: Validate payment intent amount against stored/invoice amount
        // This prevents confirming payment intents with manipulated amounts
        $paymentIntentAmount = $result['amount'] ?? 0; // Already converted from cents in StripeService
        
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
            if ($paymentIntentAmount > $invoiceTotal) {
                $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
                $logger->warning('Payment intent amount exceeds invoice total', [
                    'estimateId' => $estimateId,
                    'paymentIntentAmount' => $paymentIntentAmount,
                    'invoiceTotal' => $invoiceTotal,
                    'paymentIntentId' => $paymentIntentId,
                ]);
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

        return $this->respond($result);
    }
}

