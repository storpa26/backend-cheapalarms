<?php

namespace CheapAlarms\Plugin\Services;

use CheapAlarms\Plugin\Config\Config;
use CheapAlarms\Plugin\Services\Logger;
use WP_Error;
use function wp_remote_post;
use function wp_remote_get;
use function wp_remote_retrieve_response_code;
use function wp_remote_retrieve_body;
use function is_wp_error;

/**
 * StripeService - Handles Stripe payment processing
 */
class StripeService
{
    private const STRIPE_API_BASE = 'https://api.stripe.com/v1';

    public function __construct(
        private Config $config,
        private Logger $logger
    ) {
    }

    /**
     * Create a payment intent
     * 
     * @param float $amount Payment amount in cents (or smallest currency unit)
     * @param string $currency Currency code (default: 'aud')
     * @param array $metadata Additional metadata to attach
     * @param string|null $idempotencyKey Optional idempotency key for safe retries
     * @return array|WP_Error
     */
    public function createPaymentIntent(float $amount, string $currency = 'aud', array $metadata = [], ?string $idempotencyKey = null)
    {
        $secretKey = $this->config->getStripeSecretKey();
        
        if (empty($secretKey)) {
            return new WP_Error('stripe_not_configured', __('Stripe secret key is not configured.', 'cheapalarms'), ['status' => 500]);
        }

        // Convert amount to cents (Stripe uses smallest currency unit)
        $amountInCents = (int) round($amount * 100);

        if ($amountInCents <= 0) {
            return new WP_Error('invalid_amount', __('Payment amount must be greater than zero.', 'cheapalarms'), ['status' => 400]);
        }

        $bodyParams = [
            'amount' => $amountInCents,
            'currency' => strtolower($currency),
            'automatic_payment_methods[enabled]' => 'true',
        ];

        // Add metadata if provided
        if (!empty($metadata)) {
            foreach ($metadata as $key => $value) {
                $bodyParams['metadata[' . $key . ']'] = (string) $value;
            }
        }

        // Build headers
        $headers = [
            'Authorization' => 'Bearer ' . $secretKey,
            'Content-Type' => 'application/x-www-form-urlencoded',
        ];
        
        // FIXED: Add idempotency key header if provided
        if (!empty($idempotencyKey)) {
            $headers['Idempotency-Key'] = $idempotencyKey;
        }
        
        // Use http_build_query for proper form encoding
        $response = wp_remote_post(self::STRIPE_API_BASE . '/payment_intents', [
            'headers' => $headers,
            'body' => http_build_query($bodyParams),
            'timeout' => 30,
        ]);

        if (is_wp_error($response)) {
            $this->logger->error('Stripe API request failed', [
                'error' => $response->get_error_message(),
            ]);
            return $response;
        }

        $statusCode = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        // Validate JSON decode
        if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
            $this->logger->error('Failed to decode Stripe API response', [
                'status' => $statusCode,
                'body' => $body,
                'json_error' => json_last_error_msg(),
            ]);
            return new WP_Error('stripe_parse_error', __('Invalid response from Stripe API.', 'cheapalarms'), ['status' => 500]);
        }

        if ($statusCode !== 200) {
            $errorMessage = $data['error']['message'] ?? 'Unknown Stripe API error';
            $this->logger->error('Stripe payment intent creation failed', [
                'status' => $statusCode,
                'error' => $errorMessage,
            ]);
            return new WP_Error('stripe_api_error', $errorMessage, [
                'status' => $statusCode,
                'data' => $data,
            ]);
        }

        if (defined('WP_DEBUG') && WP_DEBUG) {
            $this->logger->info('Stripe payment intent created', [
                'payment_intent_id' => $data['id'] ?? null,
                'amount' => $amount,
                'currency' => $currency,
            ]);
        }

        return [
            'ok' => true,
            'clientSecret' => $data['client_secret'] ?? null,
            'paymentIntentId' => $data['id'] ?? null,
            'amount' => $amount,
            'currency' => $currency,
        ];
    }

    /**
     * Verify a payment intent (retrieve and check status)
     * Note: Payment is confirmed on the frontend, this just verifies the status
     * 
     * @param string $paymentIntentId Payment intent ID
     * @return array|WP_Error
     */
    public function confirmPaymentIntent(string $paymentIntentId)
    {
        // Use getPaymentIntent to retrieve and verify status
        $result = $this->getPaymentIntent($paymentIntentId);
        
        if (is_wp_error($result)) {
            return $result;
        }

        // Check payment status
        $status = $result['status'] ?? 'unknown';
        if ($status !== 'succeeded') {
            $this->logger->warning('Stripe payment intent not succeeded', [
                'payment_intent_id' => $paymentIntentId,
                'status' => $status,
            ]);
            return new WP_Error('payment_not_succeeded', __('Payment was not successful.', 'cheapalarms'), [
                'status' => 400,
                'payment_status' => $status,
            ]);
        }

        if (defined('WP_DEBUG') && WP_DEBUG) {
            $this->logger->info('Stripe payment intent verified', [
                'payment_intent_id' => $paymentIntentId,
                'status' => $status,
                'amount' => $result['amount'] ?? 0,
            ]);
        }

        return $result;
    }

    /**
     * Retrieve a payment intent
     * 
     * @param string $paymentIntentId Payment intent ID
     * @return array|WP_Error
     */
    public function getPaymentIntent(string $paymentIntentId)
    {
        $secretKey = $this->config->getStripeSecretKey();
        
        if (empty($secretKey)) {
            return new WP_Error('stripe_not_configured', __('Stripe secret key is not configured.', 'cheapalarms'), ['status' => 500]);
        }

        $response = wp_remote_get(self::STRIPE_API_BASE . '/payment_intents/' . $paymentIntentId, [
            'headers' => [
                'Authorization' => 'Bearer ' . $secretKey,
            ],
            'timeout' => 30,
        ]);

        if (is_wp_error($response)) {
            $this->logger->error('Stripe get payment intent request failed', [
                'error' => $response->get_error_message(),
                // Only include IDs in debug
                ...(defined('WP_DEBUG') && WP_DEBUG ? ['payment_intent_id' => $paymentIntentId] : []),
            ]);
            return $response;
        }

        $statusCode = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        // Validate JSON decode
        if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
            $this->logger->error('Failed to decode Stripe API response', [
                'payment_intent_id' => $paymentIntentId,
                'status' => $statusCode,
                'body' => $body,
                'json_error' => json_last_error_msg(),
            ]);
            return new WP_Error('stripe_parse_error', __('Invalid response from Stripe API.', 'cheapalarms'), ['status' => 500]);
        }

        if ($statusCode !== 200) {
            $errorMessage = $data['error']['message'] ?? 'Unknown Stripe API error';
            $this->logger->error('Stripe get payment intent failed', [
                'status' => $statusCode,
                'error' => $errorMessage,
                ...(defined('WP_DEBUG') && WP_DEBUG ? ['payment_intent_id' => $paymentIntentId] : []),
            ]);
            return new WP_Error('stripe_api_error', $errorMessage, [
                'status' => $statusCode,
                'data' => $data,
            ]);
        }

        return [
            'ok' => true,
            'paymentIntentId' => $data['id'] ?? null,
            'status' => $data['status'] ?? 'unknown',
            'amount' => ($data['amount'] ?? 0) / 100,
            'currency' => $data['currency'] ?? 'aud',
            'metadata' => $data['metadata'] ?? [],
            'client_secret' => $data['client_secret'] ?? null, // Include client secret for reuse scenarios
        ];
    }

    /**
     * Refund a payment intent (full refund)
     *
     * @param string $paymentIntentId Payment intent ID
     * @param string $reason Optional refund reason
     * @param float|null $amount Optional amount to refund (in standard units, defaults to full)
     * @return array|WP_Error
     */
    public function refundPaymentIntent(string $paymentIntentId, string $reason = 'requested_by_customer', ?float $amount = null)
    {
        $secretKey = $this->config->getStripeSecretKey();

        if (empty($secretKey)) {
            return new WP_Error('stripe_not_configured', __('Stripe secret key is not configured.', 'cheapalarms'), ['status' => 500]);
        }

        $bodyParams = [
            'payment_intent' => $paymentIntentId,
            'reason' => $reason,
        ];

        if ($amount !== null) {
            $amountInCents = (int) round($amount * 100);
            if ($amountInCents > 0) {
                $bodyParams['amount'] = $amountInCents;
            }
        }

        $response = wp_remote_post(self::STRIPE_API_BASE . '/refunds', [
            'headers' => [
                'Authorization' => 'Bearer ' . $secretKey,
                'Content-Type' => 'application/x-www-form-urlencoded',
            ],
            'body' => http_build_query($bodyParams),
            'timeout' => 30,
        ]);

        if (is_wp_error($response)) {
            $this->logger->error('Stripe refund request failed', [
                'error' => $response->get_error_message(),
                ...(defined('WP_DEBUG') && WP_DEBUG ? ['payment_intent_id' => $paymentIntentId] : []),
            ]);
            return $response;
        }

        $statusCode = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
            $this->logger->error('Failed to decode Stripe refund response', [
                'status' => $statusCode,
                'json_error' => json_last_error_msg(),
                ...(defined('WP_DEBUG') && WP_DEBUG ? ['payment_intent_id' => $paymentIntentId] : []),
            ]);
            return new WP_Error('stripe_parse_error', __('Invalid response from Stripe API.', 'cheapalarms'), ['status' => 500]);
        }

        if ($statusCode !== 200) {
            $errorMessage = $data['error']['message'] ?? 'Unknown Stripe API error';
            $this->logger->error('Stripe refund failed', [
                'status' => $statusCode,
                'error' => $errorMessage,
                ...(defined('WP_DEBUG') && WP_DEBUG ? ['payment_intent_id' => $paymentIntentId] : []),
            ]);
            return new WP_Error('stripe_api_error', $errorMessage, [
                'status' => $statusCode,
                'data' => $data,
            ]);
        }

        if (defined('WP_DEBUG') && WP_DEBUG) {
            $this->logger->info('Stripe refund processed', [
                'payment_intent_id' => $paymentIntentId,
                'amount_refunded' => ($data['amount'] ?? 0) / 100,
                'currency' => $data['currency'] ?? 'aud',
                'status' => $data['status'] ?? 'unknown',
            ]);
        }

        return [
            'ok' => true,
            'refundId' => $data['id'] ?? null,
            'status' => $data['status'] ?? 'unknown',
            'amount' => ($data['amount'] ?? 0) / 100,
            'currency' => $data['currency'] ?? 'aud',
        ];
    }
}

