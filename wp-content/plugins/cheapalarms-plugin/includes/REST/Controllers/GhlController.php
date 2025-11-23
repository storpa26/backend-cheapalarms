<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\GhlClient;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

use function sanitize_email;
use function sanitize_text_field;

class GhlController implements ControllerInterface
{
    private GhlClient $client;
    private Authenticator $auth;

    public function __construct(private Container $container)
    {
        $this->client = $this->container->get(GhlClient::class);
        $this->auth   = $this->container->get(Authenticator::class);
    }

    public function register(): void
    {
        // Contacts endpoint
        register_rest_route('ca/v1', '/ghl/contacts', [
            [
                'methods'             => 'GET',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_view_estimates'),
                'callback'            => function () {
                    $result = [
                        'ok' => true,
                        'hasKey' => !empty($this->container->get(\CheapAlarms\Plugin\Config\Config::class)->getGhlToken()),
                        'hasLocationId' => !empty($this->container->get(\CheapAlarms\Plugin\Config\Config::class)->getLocationId()),
                    ];
                    return $this->respond($result);
                },
            ],
            [
                'methods'             => 'POST',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_manage_portal'),
                'callback'            => function (WP_REST_Request $request) {
                    $config = $this->container->get(\CheapAlarms\Plugin\Config\Config::class);
                    
                    if (empty($config->getGhlToken())) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'Missing GHL_API_KEY in environment',
                        ], 500);
                    }
                    
                    if (empty($config->getLocationId())) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'Missing GHL_LOCATION_ID in environment',
                        ], 500);
                    }

                    $body = $request->get_json_params();
                    if (!is_array($body)) {
                        $body = json_decode($request->get_body(), true);
                    }
                    if (!is_array($body)) {
                        $body = [];
                    }

                    $email = !empty($body['email']) ? sanitize_email($body['email']) : '';
                    $phone = !empty($body['phone']) ? sanitize_text_field($body['phone']) : '';
                    $firstName = !empty($body['firstName']) ? sanitize_text_field($body['firstName']) : '';
                    $lastName = !empty($body['lastName']) ? sanitize_text_field($body['lastName']) : '';

                    if (empty($email) && empty($phone)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'email or phone required',
                        ], 400);
                    }

                    $payload = [
                        'email' => $email,
                        'phone' => $phone,
                        'firstName' => $firstName,
                        'lastName' => $lastName,
                        'locationId' => $config->getLocationId(),
                    ];

                    $result = $this->client->post('/contacts/', $payload);
                    
                    if (is_wp_error($result)) {
                        // Check if this is a duplicate contact error (400 with contactId in meta)
                        $errorData = $result->get_error_data();
                        $errorCode = $result->get_error_code();
                        
                        if ($errorCode === 'ghl_http_error' && isset($errorData['code']) && $errorData['code'] === 400) {
                            $errorBody = $errorData['body'] ?? null;
                            
                            // Parse error body if it's a string
                            if (is_string($errorBody)) {
                                $decoded = json_decode($errorBody, true);
                                if (json_last_error() === JSON_ERROR_NONE) {
                                    $errorBody = $decoded;
                                } else {
                                    $errorBody = null; // Don't use invalid JSON
                                }
                            }
                            
                            // Check if error indicates duplicate contact with contactId in meta
                            // GHL error structure: { "statusCode": 400, "message": "...", "meta": { "contactId": "..." } }
                            if (is_array($errorBody)) {
                                $errorMessage = $errorBody['message'] ?? '';
                                $statusCode = $errorBody['statusCode'] ?? $errorData['code'] ?? null;
                                $hasDuplicateMessage = stripos($errorMessage, 'duplicate') !== false || stripos($errorMessage, 'duplicated') !== false;
                                $hasContactId = isset($errorBody['meta']['contactId']) && !empty($errorBody['meta']['contactId']);
                                
                                if ($statusCode === 400 && ($hasDuplicateMessage || $hasContactId)) {
                                    // Extract contactId from error metadata
                                    $existingContactId = $errorBody['meta']['contactId'] ?? '';
                                    
                                    if (!empty($existingContactId)) {
                                        // Contact exists, return it as success
                                        return new WP_REST_Response([
                                            'ok' => true,
                                            'contact' => [
                                                'id' => $existingContactId,
                                                'email' => $email,
                                                'firstName' => $firstName,
                                                'lastName' => $lastName,
                                            ],
                                        ], 200);
                                    }
                                }
                            }
                        }
                        
                        // For other errors, return the error
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => $result->get_error_message(),
                        ], $result->get_error_data()['code'] ?? 500);
                    }

                    return new WP_REST_Response([
                        'ok' => true,
                        'contact' => $result,
                    ], 200);
                },
            ],
        ]);

        // Messages endpoint
        register_rest_route('ca/v1', '/ghl/messages', [
            'methods'             => 'POST',
            'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_manage_portal'),
            'callback'            => function (WP_REST_Request $request) {
                $config = $this->container->get(\CheapAlarms\Plugin\Config\Config::class);
                
                if (empty($config->getGhlToken())) {
                    return new WP_REST_Response([
                        'ok' => false,
                        'error' => 'Missing GHL_API_KEY in environment',
                    ], 500);
                }

                $body = $request->get_json_params();
                if (!is_array($body)) {
                    $body = json_decode($request->get_body(), true);
                }
                if (!is_array($body)) {
                    $body = [];
                }

                $contactId = !empty($body['contactId']) ? sanitize_text_field($body['contactId']) : '';
                $subject = !empty($body['subject']) ? sanitize_text_field($body['subject']) : '';
                $html = !empty($body['html']) ? $body['html'] : '';
                $text = !empty($body['text']) ? sanitize_textarea_field($body['text']) : '';
                $fromEmail = !empty($body['fromEmail']) ? sanitize_email($body['fromEmail']) : '';

                if (empty($contactId)) {
                    return new WP_REST_Response([
                        'ok' => false,
                        'error' => 'contactId required',
                    ], 400);
                }

                if (empty($subject)) {
                    return new WP_REST_Response([
                        'ok' => false,
                        'error' => 'subject required',
                    ], 400);
                }

                if (empty($html) && empty($text)) {
                    return new WP_REST_Response([
                        'ok' => false,
                        'error' => 'Provide html or text content',
                    ], 400);
                }

                $effectiveFromEmail = $fromEmail ?: get_option('ghl_from_email', 'quotes@cheapalarms.dev');

                $payload = [
                    'contactId' => $contactId,
                    'type' => 'Email',
                    'status' => 'pending',
                    'subject' => $subject,
                    'html' => !empty($html) ? $html : null,
                    'message' => !empty($text) ? $text : null,
                    'emailFrom' => $effectiveFromEmail,
                ];

                if ($config->getLocationId()) {
                    $payload['locationId'] = $config->getLocationId();
                }

                $result = $this->client->post('/conversations/messages', $payload);
                
                if (is_wp_error($result)) {
                    return new WP_REST_Response([
                        'ok' => false,
                        'error' => $result->get_error_message(),
                    ], $result->get_error_data()['code'] ?? 500);
                }

                return new WP_REST_Response([
                    'ok' => true,
                    'message' => $result,
                ], 200);
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

    private function isDevBypass(): bool
    {
        return defined('WP_DEBUG') && WP_DEBUG && isset($_SERVER['HTTP_X_CA_DEV']) && $_SERVER['HTTP_X_CA_DEV'] === '1';
    }
}

