<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\EstimateService;
use CheapAlarms\Plugin\Services\PortalService;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

use function is_user_logged_in;
use function current_user_can;
use function sanitize_text_field;
use function wp_get_current_user;

class PortalController implements ControllerInterface
{
    private PortalService $service;
    private EstimateService $estimateService;
    private Authenticator $auth;

    public function __construct(private Container $container)
    {
        $this->service         = $this->container->get(PortalService::class);
        $this->estimateService = $this->container->get(EstimateService::class);
        $this->auth            = $this->container->get(Authenticator::class);
    }

    public function register(): void
    {
        register_rest_route('ca/v1', '/portal/status', [
            'methods'             => 'GET',
            'permission_callback' => function (WP_REST_Request $request) {
                $estimateId = sanitize_text_field($request->get_param('estimateId'));
                $inviteToken = sanitize_text_field($request->get_param('inviteToken'));
                if (is_user_logged_in()) {
                    return current_user_can('ca_access_portal') || current_user_can('ca_manage_portal');
                }
                return $estimateId && $inviteToken && $this->service->validateInviteToken($estimateId, $inviteToken);
            },
            'callback'            => function (WP_REST_Request $request) {
                $estimateId  = sanitize_text_field($request->get_param('estimateId'));
                $locationId  = sanitize_text_field($request->get_param('locationId'));
                $inviteToken = sanitize_text_field($request->get_param('inviteToken'));
                if (!$estimateId) {
                    return new WP_REST_Response(['ok' => false, 'err' => 'estimateId required'], 400);
                }
                $user = wp_get_current_user();
                $result = $this->service->getStatus($estimateId, $locationId, $inviteToken, $user);
                return $this->respond($result);
            },
        ]);

        register_rest_route('ca/v1', '/portal/dashboard', [
            'methods'             => 'GET',
            'permission_callback' => fn () => is_user_logged_in() && (current_user_can('ca_access_portal') || current_user_can('ca_manage_portal')),
            'callback'            => function () {
                $user = wp_get_current_user();
                if (!$user || 0 === $user->ID) {
                    return new WP_REST_Response(['ok' => false, 'err' => 'Authentication required'], 401);
                }

                $result = $this->service->getDashboardData($user);
                return $this->respond($result);
            },
        ]);

        register_rest_route('ca/v1', '/portal/accept', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $payload    = $request->get_json_params();
                $estimateId = sanitize_text_field($payload['estimateId'] ?? '');
                $locationId = sanitize_text_field($payload['locationId'] ?? '');
                if (!$estimateId) {
                    return new WP_REST_Response(['ok' => false, 'err' => 'estimateId required'], 400);
                }
                $result = $this->service->acceptEstimate($estimateId, $locationId);
                return $this->respond($result);
            },
        ]);

        register_rest_route('ca/v1', '/portal/create-account', [
            'methods'             => 'POST',
            'permission_callback' => fn () => $this->auth->requireCapability('ca_manage_portal'),
            'callback'            => function (WP_REST_Request $request) {
                $payload    = $request->get_json_params();
                $estimateId = sanitize_text_field($payload['estimateId'] ?? '');
                $locationId = sanitize_text_field($payload['locationId'] ?? '');
                if (!$estimateId) {
                    return new WP_REST_Response(['ok' => false, 'err' => 'estimateId required'], 400);
                }

                $estimate = $this->estimateService->getEstimate([
                    'estimateId' => $estimateId,
                    'locationId' => $locationId,
                ]);
                if (is_wp_error($estimate)) {
                    return $this->respond($estimate);
                }

                $result = $this->service->provisionAccount($estimateId, $estimate['contact'] ?? [], $locationId);
                return $this->respond($result);
            },
        ]);

        register_rest_route('ca/v1', '/portal/resend-invite', [
            'methods'             => 'POST',
            'permission_callback' => fn () => $this->auth->requireCapability('ca_manage_support'),
            'callback'            => function (WP_REST_Request $request) {
                $payload    = $request->get_json_params();
                $estimateId = sanitize_text_field($payload['estimateId'] ?? '');
                $locationId = sanitize_text_field($payload['locationId'] ?? '');
                if (!$estimateId) {
                    return new WP_REST_Response(['ok' => false, 'err' => 'estimateId required'], 400);
                }

                $estimate = $this->estimateService->getEstimate([
                    'estimateId' => $estimateId,
                    'locationId' => $locationId,
                ]);
                if (is_wp_error($estimate)) {
                    return $this->respond($estimate);
                }

                $result    = $this->service->resendInvite($estimateId, $estimate['contact'] ?? []);
                return $this->respond($result);
            },
        ]);

        register_rest_route('ca/v1', '/portal/test-account', [
            'methods'             => 'GET',
            'permission_callback' => function (WP_REST_Request $request) {
                $estimateId = sanitize_text_field($request->get_param('estimateId'));
                $inviteToken = sanitize_text_field($request->get_param('inviteToken'));
                if (is_user_logged_in()) {
                    return current_user_can('ca_access_portal') || current_user_can('ca_manage_portal');
                }
                return $estimateId && $inviteToken && $this->service->validateInviteToken($estimateId, $inviteToken);
            },
            'callback'            => function (WP_REST_Request $request) {
                $estimateId  = sanitize_text_field($request->get_param('estimateId'));
                $locationId  = sanitize_text_field($request->get_param('locationId'));
                $inviteToken = sanitize_text_field($request->get_param('inviteToken'));
                if (!$estimateId) {
                    return new WP_REST_Response(['ok' => false, 'err' => 'estimateId required'], 400);
                }

                $user = wp_get_current_user();
                $status = $this->service->getStatus($estimateId, $locationId, $inviteToken, $user);
                if (is_wp_error($status)) {
                    return $this->respond($status);
                }

                return $this->respond([
                    'account' => $status['account'] ?? null,
                    'ok'      => true,
                ]);
            },
        ]);
    }

    /**
     * @param array|WP_Error $result
     */
    private function respond($result): WP_REST_Response
    {
        if (is_wp_error($result)) {
            $status = $result->get_error_data()['status'] ?? 500;
            return new WP_REST_Response([
                'ok'  => false,
                'err' => $result->get_error_message(),
                'code'=> $result->get_error_code(),
            ], $status);
        }

        if (!isset($result['ok'])) {
            $result['ok'] = true;
        }

        return new WP_REST_Response($result, 200);
    }
}

