<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\PortalService;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

use function is_wp_error;
use function json_decode;
use function wp_authenticate;
use function register_rest_route;
use function wp_create_nonce;
use function is_user_logged_in;
use function get_current_user_id;
use function apply_filters;
use function wp_set_current_user;
use function wp_get_current_user;
use function sanitize_text_field;
use function current_user_can;

class AuthController implements ControllerInterface
{
    private Authenticator $authenticator;

    public function __construct(private Container $container)
    {
        $this->authenticator = $this->container->get(Authenticator::class);
    }

    public function register(): void
    {
        // Auth nonce for CSRF protection (logged-in users)
        register_rest_route('ca/v1', '/auth/nonce', [
            'methods'             => 'GET',
            'permission_callback' => function () {
                // Support JWT-authenticated sessions by resolving current user if needed
                $userId = get_current_user_id();
                if ($userId <= 0) {
                    $userId = (int) apply_filters('determine_current_user', 0);
                    if ($userId > 0) {
                        wp_set_current_user($userId);
                    }
                }
                return $userId > 0;
            },
            'callback'            => function () {
                $user = wp_get_current_user();
                if (!$user || 0 === $user->ID) {
                    return new WP_REST_Response([
                        'ok' => false,
                        'err' => 'not_authenticated',
                    ], 401);
                }
                return new WP_REST_Response([
                    'ok' => true,
                    'nonce' => wp_create_nonce('wp_rest'),
                ], 200);
            },
        ]);

        // Auth/me endpoint - source of truth for authn/authz
        register_rest_route('ca/v1', '/auth/me', [
            'methods'             => 'GET',
            'permission_callback' => [$this, 'checkAuthentication'],
            'callback'            => [$this, 'getCurrentUser'],
        ]);

        // Invite-token nonce (no auth required; invite token must be valid)
        register_rest_route('ca/v1', '/auth/nonce-invite', [
            'methods'             => 'GET',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $estimateId = sanitize_text_field($request->get_param('estimateId') ?? '');
                $inviteToken = sanitize_text_field($request->get_param('inviteToken') ?? '');

                if ($estimateId === '' || $inviteToken === '') {
                    return new WP_REST_Response([
                        'ok' => false,
                        'err' => 'missing_params',
                    ], 400);
                }

                $portalService = $this->container->get(PortalService::class);
                $validation = $portalService->validateInviteToken($estimateId, $inviteToken);
                if (empty($validation['valid'])) {
                    return new WP_REST_Response([
                        'ok' => false,
                        'err' => $validation['message'] ?? 'invalid_invite',
                        'code' => $validation['reason'] ?? 'invalid_invite',
                    ], 403);
                }

                return new WP_REST_Response([
                    'ok' => true,
                    'nonce' => wp_create_nonce('wp_rest'),
                ], 200);
            },
        ]);

        register_rest_route('ca/v1', '/auth/token', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $rateCheck = $this->authenticator->enforceRateLimit('auth_token');
                if (is_wp_error($rateCheck)) {
                    return $this->respond($rateCheck);
                }

                $payload  = $request->get_json_params();
                if (!is_array($payload)) {
                    $payload = json_decode($request->get_body(), true);
                }
                if (!is_array($payload)) {
                    $payload = [];
                }

                $username = sanitize_text_field($payload['username'] ?? '');
                $password = $payload['password'] ?? '';

                if ($username === '' || $password === '') {
                    return $this->respond(new WP_Error(
                        'bad_request',
                        __('Username and password required.', 'cheapalarms'),
                        ['status' => 400]
                    ));
                }

                $user = wp_authenticate($username, $password);
                if (is_wp_error($user)) {
                    return $this->respond(new WP_Error(
                        'invalid_credentials',
                        __('Invalid username or password.', 'cheapalarms'),
                        ['status' => 401]
                    ));
                }

                if (!$user instanceof \WP_User) {
                    return $this->respond(new WP_Error(
                        'server_error',
                        __('Authentication returned an unexpected result.', 'cheapalarms'),
                        ['status' => 500]
                    ));
                }

                $token = $this->authenticator->issueToken($user);

                return new WP_REST_Response([
                    'ok'          => true,
                    'token'       => $token['token'],
                    'expiresAt'   => $token['expires_at'],
                    'expiresIn'   => $token['expires_in'],
                    'user'        => $token['user'],
                ], 200);
            },
        ]);
    }

    /**
     * Permission callback: enforce authentication.
     * Note: permission_callback runs before determine_current_user in some cases,
     * so we attempt manual JWT resolution if needed.
     */
    public function checkAuthentication(): bool|WP_Error
    {
        $userId = get_current_user_id();
        if ($userId > 0) {
            return true;
        }

        // Workaround: manually trigger JWT resolution
        global $current_user;
        $current_user = null;
        $userId = (int) apply_filters('determine_current_user', 0);
        if ($userId > 0) {
            wp_set_current_user($userId);
            return true;
        }

        return new WP_Error(
            'rest_forbidden',
            __('Authentication required.', 'cheapalarms'),
            ['status' => 401]
        );
    }

    /**
     * Return authenticated user with computed flags
     */
    public function getCurrentUser(WP_REST_Request $request): WP_REST_Response
    {
        $user = wp_get_current_user();
        if (!$user || 0 === $user->ID) {
            return new WP_REST_Response([
                'ok' => false,
                'err' => 'User not found',
            ], 401);
        }

        $roles = $user->roles ?? [];

        $hasAdminRole = in_array('administrator', $roles, true)
            || in_array('ca_admin', $roles, true)
            || in_array('ca_superadmin', $roles, true);
        $hasAdminCap = current_user_can('ca_manage_portal');
        $isAdmin = $hasAdminRole || $hasAdminCap;

        $hasCustomerRole = in_array('ca_customer', $roles, true) || in_array('customer', $roles, true);
        $isCustomer = $hasCustomerRole && !$isAdmin;

        $allCaps = $user->allcaps ?? [];
        $caCaps = [];
        foreach ($allCaps as $cap => $granted) {
            if (str_starts_with($cap, 'ca_') && $granted === true) {
                $caCaps[] = $cap;
            }
        }

        $response = new WP_REST_Response([
            'ok'           => true,
            'id'           => $user->ID,
            'email'        => $user->user_email,
            'displayName'  => $user->display_name,
            'roles'        => array_values($roles),
            'capabilities' => array_values($caCaps),
            'is_admin'     => $isAdmin,
            'is_customer'  => $isCustomer,
        ]);

        $response->header('Cache-Control', 'no-store, private');
        $response->header('Pragma', 'no-cache');
        $response->header('Vary', 'Cookie');

        return $response;
    }

    /**
     * Respond with WP_REST_Response
     */
    private function respond(WP_Error|array $result): WP_REST_Response
    {
        if (is_wp_error($result)) {
            $status = $result->get_error_data()['status'] ?? 500;
            $errorData = $result->get_error_data();
            $response = [
                'ok'   => false,
                'err'  => $result->get_error_message(),
                'code' => $result->get_error_code(),
            ];
            
            // SECURITY: Only include detailed error information in debug mode
            // In production, avoid leaking internal system details
            if (defined('WP_DEBUG') && WP_DEBUG && !empty($errorData['body'])) {
                $body = is_string($errorData['body']) ? json_decode($errorData['body'], true) : $errorData['body'];
                if (is_array($body)) {
                    $response['details'] = $body;
                } else {
                    $response['details'] = ['raw' => substr($errorData['body'], 0, 500)];
                }
            }
            
            return new WP_REST_Response($response, $status);
        }

        if (!isset($result['ok'])) {
            $result['ok'] = true;
        }

        return new WP_REST_Response($result, 200);
    }
}
