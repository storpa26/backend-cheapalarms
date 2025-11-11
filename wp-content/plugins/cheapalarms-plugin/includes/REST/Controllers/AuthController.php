<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\Services\Container;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_User;

use function is_wp_error;
use function json_decode;
use function sanitize_text_field;
use function wp_authenticate;
use function register_rest_route;

class AuthController implements ControllerInterface
{
    private Authenticator $authenticator;

    public function __construct(private Container $container)
    {
        $this->authenticator = $this->container->get(Authenticator::class);
    }

    public function register(): void
    {
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

                if (!$user instanceof WP_User) {
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

    private function respond(WP_Error $error): WP_REST_Response
    {
        $status = $error->get_error_data()['status'] ?? 500;
        return new WP_REST_Response([
            'ok'   => false,
            'err'  => $error->get_error_message(),
            'code' => $error->get_error_code(),
        ], $status);
    }
}

