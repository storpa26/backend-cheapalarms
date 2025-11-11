<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\EstimateService;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

use function get_option;
use function sanitize_email;
use function sanitize_text_field;
use Throwable;

class EstimateController implements ControllerInterface
{
    private EstimateService $service;
    private Authenticator $auth;

    public function __construct(private Container $container)
    {
        $this->service = $this->container->get(EstimateService::class);
        $this->auth    = $this->container->get(Authenticator::class);
    }

    public function register(): void
    {
        if (function_exists('error_log')) {
            error_log('[CheapAlarms Plugin] registering EstimateController routes');
        }
        register_rest_route('ca/v1', '/diag', [
            'methods'             => 'GET',
            'permission_callback' => fn () => $this->auth->requireCapability('ca_view_estimates'),
            'callback'            => function (WP_REST_Request $request) {
                $this->auth->ensureConfigured();
                $result = $this->service->diagnostics(sanitize_text_field($request->get_param('locationId')));
                return $this->respond($result);
            },
        ]);

        register_rest_route('ca/v1', '/estimate', [
            'methods'             => 'GET',
            'permission_callback' => fn () => $this->auth->requireCapability('ca_view_estimates'),
            'callback'            => function (WP_REST_Request $request) {
                $this->auth->ensureConfigured();
                $result = $this->service->getEstimate($request->get_params());
                return $this->respond($result);
            },
        ]);

        register_rest_route('ca/v1', '/estimate/list', [
            'methods'             => 'GET',
            'permission_callback' => fn () => $this->auth->requireCapability('ca_view_estimates'),
            'callback'            => function (WP_REST_Request $request) {
                $this->auth->ensureConfigured();
                $result = $this->service->listEstimates(
                    sanitize_text_field($request->get_param('locationId')),
                    (int)$request->get_param('limit'),
                    (int)$request->get_param('raw')
                );
                return $this->respond($result);
            },
        ]);

        register_rest_route('ca/v1', '/estimate/search', [
            'methods'             => 'GET',
            'permission_callback' => fn () => $this->auth->requireCapability('ca_view_estimates'),
            'callback'            => function (WP_REST_Request $request) {
                $this->auth->ensureConfigured();
                $result = $this->service->findByContactEmail(
                    sanitize_email($request->get_param('email')),
                    sanitize_text_field($request->get_param('locationId')),
                    (int)$request->get_param('raw')
                );
                return $this->respond($result);
            },
        ]);

        register_rest_route('ca/v1', '/estimate/create', [
            'methods'             => 'POST',
            'permission_callback' => fn () => $this->auth->requireCapability('ca_manage_portal'),
            'callback'            => function (WP_REST_Request $request) {
                $this->auth->ensureConfigured();
                $body = $request->get_json_params();
                if (!is_array($body)) {
                    $body = json_decode($request->get_body(), true);
                }
                if (!is_array($body)) {
                    $body = [];
                }
                try {
                    $result = $this->service->createEstimate($body);
                    return $this->respond($result);
                } catch (Throwable $e) {
                    if (function_exists('error_log')) {
                        error_log('[CheapAlarms][ERROR] Estimate create exception: ' . $e->getMessage());
                        error_log('[CheapAlarms][ERROR] Stack trace: ' . $e->getTraceAsString());
                    }
                    $error = new WP_Error(
                        'estimate_create_exception',
                        $e->getMessage(),
                        ['status' => 500]
                    );
                    return $this->respond($error);
                }
            },
        ]);

        register_rest_route('ca/v1', '/estimate/update', [
            'methods'             => 'PUT',
            'permission_callback' => fn () => $this->auth->requireCapability('ca_manage_portal'),
            'callback'            => function (WP_REST_Request $request) {
                $this->auth->ensureConfigured();
                $body = $request->get_json_params();
                if (!is_array($body)) {
                    $body = json_decode($request->get_body(), true);
                }
                if (!is_array($body)) {
                    $body = [];
                }
                $result = $this->service->updateEstimate($body);
                return $this->respond($result);
            },
        ]);

        register_rest_route('ca/v1', '/estimate/photos', [
            [
                'methods'             => 'POST',
                'permission_callback' => fn () => $this->auth->requireCapability('ca_manage_portal'),
                'callback'            => function (WP_REST_Request $request) {
                    $this->auth->ensureConfigured();
                    $body = $request->get_json_params();
                    if (!is_array($body)) {
                        $body = json_decode($request->get_body(), true);
                    }
                    if (!is_array($body)) {
                        $body = [];
                    }
                    $result = $this->service->storePhotoMapping($body);
                    return $this->respond($result);
                },
            ],
            [
                'methods'             => 'GET',
                'permission_callback' => fn () => $this->auth->requireCapability('ca_view_estimates'),
                'callback'            => function (WP_REST_Request $request) {
                    $estimateId = sanitize_text_field($request->get_param('estimateId'));
                    if (!$estimateId) {
                        return new WP_REST_Response(['ok' => false, 'err' => 'estimateId required'], 400);
                    }
                    $raw = get_option('ca_estimate_uploads_' . $estimateId, '');
                    return new WP_REST_Response([
                        'ok'     => true,
                        'stored' => $raw ? json_decode($raw, true) : null,
                    ], 200);
                },
            ],
        ]);

        register_rest_route('ca/v1', '/estimate/apply-photos', [
            'methods'             => 'POST',
            'permission_callback' => fn () => $this->auth->requireCapability('ca_manage_portal'),
            'callback'            => function (WP_REST_Request $request) {
                $this->auth->ensureConfigured();
                $body = $request->get_json_params();
                if (!is_array($body)) {
                    $body = json_decode($request->get_body(), true);
                }
                if (!is_array($body)) {
                    $body = [];
                }
                $result = $this->service->applyPhotos($body);
                return $this->respond($result);
            },
        ]);

        register_rest_route('ca/v1', '/estimate/annotate', [
            'methods'             => 'POST',
            'permission_callback' => fn () => $this->auth->requireCapability('ca_manage_portal'),
            'callback'            => function (WP_REST_Request $request) {
                $this->auth->ensureConfigured();
                $body = $request->get_json_params();
                if (!is_array($body)) {
                    $body = json_decode($request->get_body(), true);
                }
                if (!is_array($body)) {
                    $body = [];
                }
                $result = $this->service->annotateEstimate($body);
                return $this->respond($result);
            },
        ]);
    }

    /**
     * @param array|WP_Error $result
     */
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

