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
        $allowPortalOrInvite = function (WP_REST_Request $request) {
            // Allow if inviteToken is present (handled in callback with validateInviteToken)
            $inviteToken = sanitize_text_field($request->get_param('inviteToken') ?? $request->get_json_params()['inviteToken'] ?? '');
            if (!empty($inviteToken)) {
                return true;
            }
            // Otherwise require portal or admin capability
            $this->auth->ensureUserLoaded();
            $portalCheck = $this->auth->requireCapability('ca_access_portal');
            if (!is_wp_error($portalCheck)) {
                return true;
            }
            $adminCheck = $this->auth->requireCapability('ca_manage_portal');
            return is_wp_error($adminCheck) ? $portalCheck : true;
        };

        $requireCsrf = function (WP_REST_Request $request) {
            // Basic CSRF check for cookie-auth POSTs: require X-WP-Nonce header when no inviteToken is used
            $inviteToken = sanitize_text_field($request->get_param('inviteToken') ?? $request->get_json_params()['inviteToken'] ?? '');
            if (!empty($inviteToken)) {
                return true; // invite links act as bearer tokens
            }
            $nonce = $request->get_header('x-wp-nonce');
            if (empty($nonce)) {
                return $this->respond(new WP_Error(
                    'missing_csrf_token',
                    __('Missing CSRF token.', 'cheapalarms'),
                    ['status' => 403]
                ));
            }
            if (!wp_verify_nonce($nonce, 'wp_rest')) {
                return $this->respond(new WP_Error(
                    'invalid_csrf_token',
                    __('Invalid CSRF token.', 'cheapalarms'),
                    ['status' => 403]
                ));
            }
            return true;
        };

        register_rest_route('ca/v1', '/portal/status', [
            'methods'             => 'GET',
            'permission_callback' => function () {
                // Always return true - we'll validate authentication in the callback
                // This allows the request to proceed, and the callback will check if user is authenticated
                // This approach works better with JWT authentication where determine_current_user filter
                // runs after permission_callback, so wp_get_current_user() might not be set yet here
                return true;
            },
            'callback'            => function (WP_REST_Request $request) {
                try {
                    $estimateId  = sanitize_text_field($request->get_param('estimateId'));
                    $locationId  = sanitize_text_field($request->get_param('locationId'));
                    $inviteToken = sanitize_text_field($request->get_param('inviteToken'));
                    
                    if (!$estimateId) {
                        return new WP_REST_Response(['ok' => false, 'err' => 'estimateId required'], 400);
                    }
                    
                    // Force refresh of current user - clear cache to ensure JWT filter has run
                    global $current_user;
                    $current_user = null;
                    
                    // Try to get user again
                    $user = wp_get_current_user();
                    
                    // If still no user, manually check for JWT token and authenticate
                    if (!$user || 0 === $user->ID) {
                        // Check if Authorization header exists
                        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['Authorization'] ?? null;
                        if (!$authHeader && function_exists('apache_request_headers')) {
                            $headers = apache_request_headers();
                            $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? null;
                        }
                        
                        // Also check cookies for JWT token
                        $token = null;
                        if ($authHeader && stripos($authHeader, 'Bearer ') === 0) {
                            $token = trim(substr($authHeader, 7));
                        } elseif (isset($_COOKIE['ca_jwt']) && !empty($_COOKIE['ca_jwt'])) {
                            $token = $_COOKIE['ca_jwt'];
                        }
                        
                        if ($token) {
                            // Token exists - manually trigger determine_current_user filter
                            $userId = apply_filters('determine_current_user', 0);
                            if ($userId > 0) {
                                wp_set_current_user($userId);
                                $user = wp_get_current_user();
                            }
                        }
                    }
                    
                    // If user is authenticated, allow access
                    if ($user && $user->ID > 0) {
                        $result = $this->service->getStatus($estimateId, $locationId, $inviteToken, $user);
                        return $this->respond($result, $request);
                    }
                    
                    // Fallback: check invite token if no authenticated user
                    if ($inviteToken) {
                        $validationResult = $this->service->validateInviteToken($estimateId, $inviteToken);
                        if ($validationResult['valid']) {
                            $result = $this->service->getStatus($estimateId, $locationId, $inviteToken, null);
                            return $this->respond($result, $request);
                        }
                        
                        // Invalid or expired invite token - return 403 (Forbidden) not 401 (Unauthorized)
                        return new WP_REST_Response([
                            'ok' => false,
                            'err' => $validationResult['message'] ?? 'This invite link is invalid or has expired.',
                            'error' => $validationResult['message'] ?? 'This invite link is invalid or has expired.',
                            'code' => $validationResult['reason'] === 'expired' ? 'expired_invite' : 'invalid_invite',
                        ], 403);
                    }
                    
                    // No invite token AND no authentication - return 401 (Unauthorized)
                    return new WP_REST_Response([
                        'ok' => false,
                        'err' => 'You need a valid invite link or must log in with a WordPress account that has portal access.',
                        'error' => 'You need a valid invite link or must log in with a WordPress account that has portal access.',
                    ], 401);
                } catch (\Exception $e) {
                    // Log the error and return a proper response
                    error_log('Portal status endpoint error: ' . $e->getMessage());
                    return new WP_REST_Response([
                        'ok' => false,
                        'err' => 'An error occurred while fetching portal status. Please try again.',
                        'code' => 'internal_error',
                    ], 500);
                }
            },
        ]);

        register_rest_route('ca/v1', '/portal/dashboard', [
            'methods'             => 'GET',
            'permission_callback' => function () {
                // Always return true - we'll validate authentication in the callback
                // This allows the request to proceed, and the callback will check if user is authenticated
                // This approach works better with JWT authentication where determine_current_user filter
                // runs after permission_callback, so wp_get_current_user() might not be set yet here
                return true;
            },
            'callback'            => function (WP_REST_Request $request) {
                // Force refresh of current user - clear cache to ensure JWT filter has run
                global $current_user;
                $current_user = null;
                
                // Try to get user again
                $user = wp_get_current_user();
                
                // If still no user, manually check for JWT token and authenticate
                if (!$user || 0 === $user->ID) {
                    // Check if Authorization header exists
                    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['Authorization'] ?? null;
                    if (!$authHeader && function_exists('apache_request_headers')) {
                        $headers = apache_request_headers();
                        $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? null;
                    }
                    
                    if ($authHeader && stripos($authHeader, 'Bearer ') === 0) {
                        // Token exists - manually trigger determine_current_user filter
                        $userId = apply_filters('determine_current_user', 0);
                        if ($userId > 0) {
                            wp_set_current_user($userId);
                            $user = wp_get_current_user();
                        }
                    }
                }
                
                if (!$user || 0 === $user->ID) {
                    return new WP_REST_Response(['ok' => false, 'err' => 'Authentication required'], 401);
                }

                $result = $this->service->getDashboardData($user);
                return $this->respond($result, $request);
            },
        ]);

        register_rest_route('ca/v1', '/portal/accept', [
            'methods'             => 'POST',
            'permission_callback' => fn (WP_REST_Request $request) => $allowPortalOrInvite($request) && $requireCsrf($request),
            'callback'            => function (WP_REST_Request $request) {
                $payload    = $request->get_json_params();
                $estimateId = sanitize_text_field($payload['estimateId'] ?? '');
                $locationId = sanitize_text_field($payload['locationId'] ?? '');
                $inviteToken = sanitize_text_field($payload['inviteToken'] ?? '');
                
                // Input validation
                if (empty($estimateId)) {
                    return $this->respond(new WP_Error('bad_request', __('estimateId is required', 'cheapalarms'), ['status' => 400]));
                }
                if (!preg_match('/^[a-zA-Z0-9]+$/', $estimateId)) {
                    return $this->respond(new WP_Error('bad_request', __('Invalid estimateId format', 'cheapalarms'), ['status' => 400]));
                }
                
                // Block guest mode (read-only access)
                global $current_user;
                $current_user = null;
                $user = wp_get_current_user();
                if ($inviteToken && (!$user || 0 === $user->ID)) {
                    return $this->respond(new WP_Error(
                        'guest_mode_blocked',
                        __('Please create an account to accept this estimate. Guest access is read-only.', 'cheapalarms'),
                        ['status' => 403, 'requiresAccount' => true]
                    ));
                }
                
                // SECURITY: Verify user has access to this estimate before allowing acceptance
                // This prevents IDOR - users can only accept estimates they have access to
                $status = $this->service->getStatus($estimateId, $locationId, $inviteToken, $user);
                if (is_wp_error($status)) {
                    return $this->respond($status); // Returns 403 if not authorized
                }
                
                $result = $this->service->acceptEstimate($estimateId, $locationId);
                return $this->respond($result);
            },
        ]);

        register_rest_route('ca/v1', '/portal/request-review', [
            'methods'             => 'POST',
            'permission_callback' => fn (WP_REST_Request $request) => $allowPortalOrInvite($request) && $requireCsrf($request),
            'callback'            => function (WP_REST_Request $request) {
                $payload    = $request->get_json_params();
                $estimateId = sanitize_text_field($payload['estimateId'] ?? '');
                $locationId = sanitize_text_field($payload['locationId'] ?? '');
                $inviteToken = sanitize_text_field($payload['inviteToken'] ?? '');
                
                // Input validation
                if (empty($estimateId)) {
                    return $this->respond(new WP_Error('bad_request', __('estimateId is required', 'cheapalarms'), ['status' => 400]));
                }
                if (!preg_match('/^[a-zA-Z0-9]+$/', $estimateId)) {
                    return $this->respond(new WP_Error('bad_request', __('Invalid estimateId format', 'cheapalarms'), ['status' => 400]));
                }
                
                // Block guest mode (read-only access)
                global $current_user;
                $current_user = null;
                $user = wp_get_current_user();
                if ($inviteToken && (!$user || 0 === $user->ID)) {
                    return $this->respond(new WP_Error(
                        'guest_mode_blocked',
                        __('Please create an account to request review. Guest access is read-only.', 'cheapalarms'),
                        ['status' => 403, 'requiresAccount' => true]
                    ));
                }
                
                // SECURITY: Verify user has access to this estimate
                $status = $this->service->getStatus($estimateId, $locationId, $inviteToken, $user);
                if (is_wp_error($status)) {
                    return $this->respond($status);
                }
                
                $result = $this->service->requestReview($estimateId, $locationId);
                return $this->respond($result);
            },
        ]);

        register_rest_route('ca/v1', '/portal/create-invoice', [
            'methods'             => 'POST',
            'permission_callback' => fn (WP_REST_Request $request) => $allowPortalOrInvite($request) && $requireCsrf($request),
            'callback'            => function (WP_REST_Request $request) {
                $payload     = $request->get_json_params();
                $estimateId  = sanitize_text_field($payload['estimateId'] ?? '');
                $locationId  = sanitize_text_field($payload['locationId'] ?? '');
                $inviteToken = sanitize_text_field($payload['inviteToken'] ?? '');
                $force       = !empty($payload['force']);

                // Input validation
                if (empty($estimateId)) {
                    return $this->respond(new WP_Error('bad_request', __('estimateId is required', 'cheapalarms'), ['status' => 400]));
                }
                if (!preg_match('/^[a-zA-Z0-9]+$/', $estimateId)) {
                    return $this->respond(new WP_Error('bad_request', __('Invalid estimateId format', 'cheapalarms'), ['status' => 400]));
                }

                // Force refresh of current user so JWT filters can run
                global $current_user;
                $current_user = null;
                $user = wp_get_current_user();

                // Block guest mode (read-only access)
                if ($inviteToken && (!$user || 0 === $user->ID)) {
                    return $this->respond(new WP_Error(
                        'guest_mode_blocked',
                        __('Please create an account to create an invoice. Guest access is read-only.', 'cheapalarms'),
                        ['status' => 403, 'requiresAccount' => true]
                    ));
                }

                $status = $this->service->getStatus($estimateId, $locationId, $inviteToken, $user);
                if (is_wp_error($status)) {
                    return $this->respond($status);
                }

                $effectiveLocation = $status['locationId'] ?? $locationId;
                $result = $this->service->createInvoiceForEstimate($estimateId, $effectiveLocation, [
                    'force' => $force,
                ]);

                return $this->respond($result);
            },
        ]);

        register_rest_route('ca/v1', '/portal/reject', [
            'methods'             => 'POST',
            'permission_callback' => fn (WP_REST_Request $request) => $allowPortalOrInvite($request) && $requireCsrf($request),
            'callback'            => function (WP_REST_Request $request) {
                $payload    = $request->get_json_params();
                $estimateId = sanitize_text_field($payload['estimateId'] ?? '');
                $locationId = sanitize_text_field($payload['locationId'] ?? '');
                $inviteToken = sanitize_text_field($payload['inviteToken'] ?? '');
                $reason     = sanitize_text_field($payload['reason'] ?? '');
                
                // Input validation
                if (empty($estimateId)) {
                    return $this->respond(new WP_Error('bad_request', __('estimateId is required', 'cheapalarms'), ['status' => 400]));
                }
                
                if (!preg_match('/^[a-zA-Z0-9]+$/', $estimateId)) {
                    return $this->respond(new WP_Error('bad_request', __('Invalid estimateId format', 'cheapalarms'), ['status' => 400]));
                }
                
                // Block guest mode (read-only access)
                global $current_user;
                $current_user = null;
                $user = wp_get_current_user();
                if ($inviteToken && (!$user || 0 === $user->ID)) {
                    return $this->respond(new WP_Error(
                        'guest_mode_blocked',
                        __('Please create an account to reject this estimate. Guest access is read-only.', 'cheapalarms'),
                        ['status' => 403, 'requiresAccount' => true]
                    ));
                }
                
                // SECURITY: Verify user has access to this estimate before allowing rejection
                // This prevents IDOR - users can only reject estimates they have access to
                $status = $this->service->getStatus($estimateId, $locationId, $inviteToken, $user);
                if (is_wp_error($status)) {
                    return $this->respond($status); // Will return 403 if not authorized
                }
                
                $result = $this->service->rejectEstimate($estimateId, $locationId, $reason);
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

        register_rest_route('ca/v1', '/portal/invite-ghl-contact', [
            'methods'             => 'POST',
            'permission_callback' => fn () => $this->auth->requireCapability('ca_manage_portal'),
            'callback'            => function (WP_REST_Request $request) {
                $payload = $request->get_json_params();
                $ghlContactId = sanitize_text_field($payload['ghlContactId'] ?? '');
                
                if (!$ghlContactId) {
                    return new WP_REST_Response(['ok' => false, 'error' => 'ghlContactId required'], 400);
                }

                // Get GHL client and fetch contact details
                $ghlClient = $this->container->get(\CheapAlarms\Plugin\Services\GhlClient::class);
                $config = $this->container->get(\CheapAlarms\Plugin\Config\Config::class);
                
                if (empty($config->getLocationId())) {
                    return new WP_REST_Response([
                        'ok' => false,
                        'error' => 'Missing GHL_LOCATION_ID in environment',
                    ], 500);
                }

                // Fetch GHL contact details
                // GHL API: GET /contacts/{contactId} with LocationId header
                $locationId = $config->getLocationId();
                $ghlContact = $ghlClient->get("/contacts/{$ghlContactId}", [], 25, $locationId);
                
                if (is_wp_error($ghlContact)) {
                    return $this->respond($ghlContact);
                }

                // Get CustomerService and invite
                $customerService = $this->container->get(\CheapAlarms\Plugin\Services\CustomerService::class);
                $result = $customerService->inviteGhlContactToPortal($ghlContactId, $ghlContact);
                
                return $this->respond($result);
            },
        ]);

        register_rest_route('ca/v1', '/portal/submit-photos', [
            'methods'             => 'POST',
            'permission_callback' => fn (WP_REST_Request $request) => $allowPortalOrInvite($request) && $requireCsrf($request),
            'callback'            => function (WP_REST_Request $request) {
                $payload     = $request->get_json_params();
                $estimateId  = sanitize_text_field($payload['estimateId'] ?? '');
                $locationId  = sanitize_text_field($payload['locationId'] ?? '');
                
                // Input validation
                if (empty($estimateId)) {
                    return $this->respond(new WP_Error('bad_request', __('estimateId is required', 'cheapalarms'), ['status' => 400]));
                }
                
                if (!preg_match('/^[a-zA-Z0-9]+$/', $estimateId)) {
                    return $this->respond(new WP_Error('bad_request', __('Invalid estimateId format', 'cheapalarms'), ['status' => 400]));
                }
                
                $result = $this->service->submitPhotos($estimateId, $locationId);
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
                if (!$estimateId || !$inviteToken) {
                    return false;
                }
                $validationResult = $this->service->validateInviteToken($estimateId, $inviteToken);
                return $validationResult['valid'];
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

        register_rest_route('ca/v1', '/portal/book-job', [
            'methods'             => 'POST',
            'permission_callback' => fn (WP_REST_Request $request) => $allowPortalOrInvite($request) && $requireCsrf($request),
            'callback'            => function (WP_REST_Request $request) {
                $payload     = $request->get_json_params();
                $estimateId  = sanitize_text_field($payload['estimateId'] ?? '');
                $locationId  = sanitize_text_field($payload['locationId'] ?? '');
                $inviteToken = sanitize_text_field($payload['inviteToken'] ?? '');

                if (empty($estimateId)) {
                    return $this->respond(new WP_Error('bad_request', __('estimateId is required', 'cheapalarms'), ['status' => 400]));
                }
                if (!preg_match('/^[a-zA-Z0-9]+$/', $estimateId)) {
                    return $this->respond(new WP_Error('bad_request', __('Invalid estimateId format', 'cheapalarms'), ['status' => 400]));
                }

                // Validate estimate access (includes locationId validation via getStatus)
                global $current_user;
                $current_user = null;
                $user = wp_get_current_user();
                $status = $this->service->getStatus($estimateId, $locationId, $inviteToken, $user);
                if (is_wp_error($status)) {
                    return $this->respond($status); // Will return 403 if not authorized or invalid locationId
                }

                $bookingData = [
                    'date' => sanitize_text_field($payload['date'] ?? ''),
                    'time' => sanitize_text_field($payload['time'] ?? ''),
                    'notes' => sanitize_text_field($payload['notes'] ?? ''),
                ];

                // Use validated locationId from status (getStatus always returns locationId)
                $effectiveLocationId = $status['locationId'] ?? null;
                if (empty($effectiveLocationId)) {
                    return $this->respond(new WP_Error(
                        'missing_location_id',
                        __('Location ID could not be determined for this estimate.', 'cheapalarms'),
                        ['status' => 400]
                    ));
                }
                $result = $this->service->bookJob($estimateId, $effectiveLocationId, $bookingData);
                return $this->respond($result);
            },
        ]);

        register_rest_route('ca/v1', '/portal/confirm-payment', [
            'methods'             => 'POST',
            'permission_callback' => fn (WP_REST_Request $request) => $allowPortalOrInvite($request) && $requireCsrf($request),
            'callback'            => function (WP_REST_Request $request) {
                $payload     = $request->get_json_params();
                $estimateId  = sanitize_text_field($payload['estimateId'] ?? '');
                $locationId  = sanitize_text_field($payload['locationId'] ?? '');
                $inviteToken = sanitize_text_field($payload['inviteToken'] ?? '');

                if (empty($estimateId)) {
                    return $this->respond(new WP_Error('bad_request', __('estimateId is required', 'cheapalarms'), ['status' => 400]));
                }
                if (!preg_match('/^[a-zA-Z0-9]+$/', $estimateId)) {
                    return $this->respond(new WP_Error('bad_request', __('Invalid estimateId format', 'cheapalarms'), ['status' => 400]));
                }

                // Validate estimate access (includes locationId validation via getStatus)
                global $current_user;
                $current_user = null;
                $user = wp_get_current_user();
                $status = $this->service->getStatus($estimateId, $locationId, $inviteToken, $user);
                if (is_wp_error($status)) {
                    return $this->respond($status); // Will return 403 if not authorized or invalid locationId
                }

                $paymentData = [
                    'amount' => isset($payload['amount']) ? (float) $payload['amount'] : null,
                    'provider' => sanitize_text_field($payload['provider'] ?? 'mock'),
                    'transactionId' => sanitize_text_field($payload['transactionId'] ?? null),
                ];

                // Use validated locationId from status (getStatus always returns locationId)
                $effectiveLocationId = $status['locationId'] ?? null;
                if (empty($effectiveLocationId)) {
                    return $this->respond(new WP_Error(
                        'missing_location_id',
                        __('Location ID could not be determined for this estimate.', 'cheapalarms'),
                        ['status' => 400]
                    ));
                }
                $result = $this->service->confirmPayment($estimateId, $effectiveLocationId, $paymentData);
                return $this->respond($result);
            },
        ]);
    }

    /**
     * Universal helper to validate estimate access (authenticated user or valid invite token)
     * 
     * @param string $estimateId
     * @param string $inviteToken
     * @return true|WP_Error
     */
    private function validateEstimateAccess(string $estimateId, string $inviteToken = ''): bool|WP_Error
    {
        // Force refresh of current user so JWT filters can run
        global $current_user;
        $current_user = null;
        $user = wp_get_current_user();

        // If user is authenticated, allow access
        if ($user && $user->ID > 0) {
            return true;
        }

        // Fallback: check invite token if no authenticated user
        if ($inviteToken) {
            $validationResult = $this->service->validateInviteToken($estimateId, $inviteToken);
            if ($validationResult['valid']) {
                return true;
            }
            return new WP_Error(
                'invalid_invite',
                $validationResult['message'] ?: __('Invalid or expired invite token.', 'cheapalarms'),
                ['status' => 403]
            );
        }

        return new WP_Error(
            'unauthorized',
            __('Authentication required. Please log in or use a valid invite link.', 'cheapalarms'),
            ['status' => 401]
        );
    }

    /**
     * @param array|WP_Error $result
     */
    private function respond($result, ?WP_REST_Request $request = null): WP_REST_Response
    {
        if (is_wp_error($result)) {
            return $this->errorResponse($result);
        }

        if (!isset($result['ok'])) {
            $result['ok'] = true;
        }

        $response = new WP_REST_Response($result, 200);
        
        // Add cache headers for GET requests (improve performance)
        if ($request && $request->get_method() === 'GET') {
            // Cache for 2 minutes, allow stale-while-revalidate for 5 minutes
            $response->header('Cache-Control', 'public, max-age=120, stale-while-revalidate=300');
            $response->header('Vary', 'Authorization, Cookie');
        }
        
        $this->addSecurityHeaders($response);
        return $response;
    }

    /**
     * Create standardized error response with sanitization
     *
     * @param WP_Error $error
     * @return WP_REST_Response
     */
    private function errorResponse(WP_Error $error): WP_REST_Response
    {
        $status = $error->get_error_data()['status'] ?? 500;
        $code = $error->get_error_code();
        $message = $error->get_error_message();
        $errorData = $error->get_error_data();
        
        // SECURITY: Sanitize error messages in production
        $isDebug = defined('WP_DEBUG') && WP_DEBUG;
        
        if (!$isDebug) {
            // Generic messages for production to prevent information disclosure
            $genericMessages = [
                'rest_forbidden' => 'Access denied.',
                'unauthorized' => 'Authentication required.',
                'invalid_token' => 'Invalid authentication token.',
                'rate_limited' => 'Too many requests. Please try again later.',
                'bad_request' => 'Invalid request.',
                'not_found' => 'Resource not found.',
                'server_error' => 'An error occurred. Please try again.',
                'invalid_invite' => 'Invalid or expired invite link.',
                'guest_mode_blocked' => 'Please create an account to perform this action.',
            ];
            
            $message = $genericMessages[$code] ?? 'An error occurred. Please try again.';
        }
        
        $response = [
            'ok'   => false,
            'error' => $message,
            'code' => $code,
            // Include 'err' for backward compatibility
            'err'  => $message,
        ];
        
        // Only include detailed error information in debug mode
        if ($isDebug && !empty($errorData) && is_array($errorData)) {
            $sanitized = $this->sanitizeErrorData($errorData);
            if (!empty($sanitized)) {
                $response['details'] = $sanitized;
            }
        }
        
        $restResponse = new WP_REST_Response($response, $status);
        $this->addSecurityHeaders($restResponse);
        return $restResponse;
    }

    /**
     * Remove sensitive data from error details
     *
     * @param array<string, mixed> $data
     * @return array<string, mixed>
     */
    private function sanitizeErrorData(array $data): array
    {
        $sensitive = ['password', 'token', 'secret', 'key', 'authorization', 'cookie', 'api_key'];
        $sanitized = [];
        
        foreach ($data as $key => $value) {
            $keyLower = strtolower($key);
            $isSensitive = false;
            
            foreach ($sensitive as $sensitiveKey) {
                if (str_contains($keyLower, $sensitiveKey)) {
                    $isSensitive = true;
                    break;
                }
            }
            
            if ($isSensitive) {
                $sanitized[$key] = '[REDACTED]';
            } elseif (is_array($value)) {
                $sanitized[$key] = $this->sanitizeErrorData($value);
            } else {
                $sanitized[$key] = $value;
            }
        }
        
        return $sanitized;
    }

    /**
     * Add security headers to response
     *
     * @param WP_REST_Response $response
     * @return void
     */
    private function addSecurityHeaders(WP_REST_Response $response): void
    {
        // Prevent MIME type sniffing
        $response->header('X-Content-Type-Options', 'nosniff');
        
        // XSS protection (legacy but still useful)
        $response->header('X-XSS-Protection', '1; mode=block');
        
        // Prevent clickjacking
        $response->header('X-Frame-Options', 'DENY');
        
        // Referrer policy
        $response->header('Referrer-Policy', 'strict-origin-when-cross-origin');
    }
}

