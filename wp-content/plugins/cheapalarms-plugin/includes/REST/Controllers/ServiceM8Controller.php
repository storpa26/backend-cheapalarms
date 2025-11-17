<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\ServiceM8Service;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

use function sanitize_email;
use function sanitize_text_field;
use function sanitize_textarea_field;

class ServiceM8Controller implements ControllerInterface
{
    private ServiceM8Service $service;
    private Authenticator $auth;

    public function __construct(private Container $container)
    {
        $this->service = $this->container->get(ServiceM8Service::class);
        $this->auth    = $this->container->get(Authenticator::class);
    }

    public function register(): void
    {
        // Test connection endpoint
        register_rest_route('ca/v1', '/servicem8/test', [
            'methods'             => 'GET',
            'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_view_estimates'),
            'callback'            => function () {
                $result = $this->service->testConnection();
                return $this->respond($result);
            },
        ]);

        // Companies endpoints
        register_rest_route('ca/v1', '/servicem8/companies', [
            [
                'methods'             => 'GET',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_view_estimates'),
                'callback'            => function (WP_REST_Request $request) {
                    $params = [
                        'uuid' => $request->get_param('uuid'),
                        'name' => $request->get_param('name'),
                    ];
                    $result = $this->service->getCompanies($params);
                    return $this->respond($result);
                },
            ],
            [
                'methods'             => 'POST',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_manage_portal'),
                'callback'            => function (WP_REST_Request $request) {
                    $body = $request->get_json_params();
                    if (!is_array($body)) {
                        $body = json_decode($request->get_body(), true);
                    }
                    if (!is_array($body)) {
                        $body = [];
                    }
                    $result = $this->service->createCompany($body);
                    return $this->respond($result);
                },
            ],
        ]);

        // Jobs endpoints
        register_rest_route('ca/v1', '/servicem8/jobs', [
            [
                'methods'             => 'GET',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_view_estimates'),
                'callback'            => function (WP_REST_Request $request) {
                    $params = [
                        'uuid' => $request->get_param('uuid'),
                        'company_uuid' => $request->get_param('company_uuid'),
                        'status' => $request->get_param('status'),
                    ];
                    $result = $this->service->getJobs($params);
                    return $this->respond($result);
                },
            ],
            [
                'methods'             => 'POST',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_manage_portal'),
                'callback'            => function (WP_REST_Request $request) {
                    $body = $request->get_json_params();
                    if (!is_array($body)) {
                        $body = json_decode($request->get_body(), true);
                    }
                    if (!is_array($body)) {
                        $body = [];
                    }
                    $result = $this->service->createJob($body);
                    return $this->respond($result);
                },
            ],
        ]);

        // Single job endpoints
        register_rest_route('ca/v1', '/servicem8/jobs/(?P<uuid>[a-zA-Z0-9\-]+)', [
            [
                'methods'             => 'GET',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_view_estimates'),
                'callback'            => function (WP_REST_Request $request) {
                    $uuid = sanitize_text_field($request->get_param('uuid'));
                    $result = $this->service->getJob($uuid);
                    return $this->respond($result);
                },
            ],
            [
                'methods'             => 'DELETE',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_manage_portal'),
                'callback'            => function (WP_REST_Request $request) {
                    $uuid = sanitize_text_field($request->get_param('uuid'));
                    $result = $this->service->deleteJob($uuid);
                    return $this->respond($result);
                },
            ],
        ]);
    }

    /**
     * @param array|WP_Error $result
     */
    private function respond($result): WP_REST_Response
    {
        if (is_wp_error($result)) {
            $status = $result->get_error_data()['status'] ?? 500;
            $errorData = $result->get_error_data();
            $body = $errorData['body'] ?? null;
            
            // Try to parse ServiceM8 error message from response body
            $errorMessage = $result->get_error_message();
            $errorDetails = null;
            
            if ($body) {
                $parsedBody = json_decode($body, true);
                if (is_array($parsedBody)) {
                    $errorDetails = $parsedBody;
                    // ServiceM8 often returns error details in 'message' or 'error' field
                    if (!empty($parsedBody['message'])) {
                        $errorMessage = $parsedBody['message'];
                    } elseif (!empty($parsedBody['error'])) {
                        $errorMessage = $parsedBody['error'];
                    } elseif (!empty($parsedBody['errors'])) {
                        if (is_array($parsedBody['errors'])) {
                            $errorMessage = implode(', ', array_map(function($err) {
                                return is_array($err) ? json_encode($err) : $err;
                            }, $parsedBody['errors']));
                        } else {
                            $errorMessage = $parsedBody['errors'];
                        }
                    }
                } else {
                    // If not JSON, include raw body
                    $errorMessage = $body;
                }
            }
            
            return new WP_REST_Response([
                'ok'  => false,
                'err' => $errorMessage,
                'code'=> $result->get_error_code(),
                'details' => $errorDetails, // Include full error details for debugging
            ], $status);
        }

        if (!isset($result['ok'])) {
            $result['ok'] = true;
        }

        return new WP_REST_Response($result, 200);
    }

    private function isDevBypass(): bool
    {
        return defined('WP_DEBUG') && WP_DEBUG && isset($_SERVER['HTTP_X_CA_DEV']) && $_SERVER['HTTP_X_CA_DEV'] === '1';
    }
}

