<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\REST\Controllers\Base\AdminController;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\StripeService;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

use function sanitize_text_field;

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
            'permission_callback' => fn () => true,
            'callback' => function (WP_REST_Request $request) {
                // Allow authenticated portal users (via JWT) or admin users
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_access_portal');
                if (is_wp_error($authCheck)) {
                    // Try admin capability as fallback
                    $adminCheck = $this->auth->requireCapability('ca_manage_portal');
                    if (is_wp_error($adminCheck)) {
                        return $this->respond($authCheck);
                    }
                }
                return $this->createPaymentIntent($request);
            },
        ]);

        // Confirm payment intent (verify payment was successful)
        register_rest_route('ca/v1', '/stripe/confirm-payment-intent', [
            'methods' => 'POST',
            'permission_callback' => fn () => true,
            'callback' => function (WP_REST_Request $request) {
                $this->ensureUserLoaded();
                $authCheck = $this->auth->requireCapability('ca_access_portal');
                if (is_wp_error($authCheck)) {
                    $adminCheck = $this->auth->requireCapability('ca_manage_portal');
                    if (is_wp_error($adminCheck)) {
                        return $this->respond($authCheck);
                    }
                }
                return $this->confirmPaymentIntent($request);
            },
        ]);
    }

    private function createPaymentIntent(WP_REST_Request $request): WP_REST_Response
    {
        $body = $request->get_json_params();
        $amount = isset($body['amount']) ? (float) $body['amount'] : null;
        $currency = sanitize_text_field($body['currency'] ?? 'aud');
        $metadata = $body['metadata'] ?? [];

        if ($amount === null || $amount <= 0) {
            return $this->respond(new WP_Error('invalid_amount', __('Payment amount is required and must be greater than zero.', 'cheapalarms'), ['status' => 400]));
        }

        $result = $this->stripeService->createPaymentIntent($amount, $currency, $metadata);

        if (is_wp_error($result)) {
            return $this->respond($result);
        }

        return $this->respond($result);
    }

    private function confirmPaymentIntent(WP_REST_Request $request): WP_REST_Response
    {
        $body = $request->get_json_params();
        $paymentIntentId = sanitize_text_field($body['paymentIntentId'] ?? '');

        if (empty($paymentIntentId)) {
            return $this->respond(new WP_Error('missing_payment_intent_id', __('Payment intent ID is required.', 'cheapalarms'), ['status' => 400]));
        }

        $result = $this->stripeService->confirmPaymentIntent($paymentIntentId);

        if (is_wp_error($result)) {
            return $this->respond($result);
        }

        return $this->respond($result);
    }
}

