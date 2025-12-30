<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\Services\Container;
use WP_REST_Request;
use WP_REST_Response;

use function get_users;
use function get_user_meta;
use function user_can;

class UsersController implements ControllerInterface
{
    private Authenticator $auth;

    public function __construct(private Container $container)
    {
        $this->auth = $this->container->get(Authenticator::class);
    }

    public function register(): void
    {
        register_rest_route('ca/v1', '/users', [
            [
                'methods'             => 'GET',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_view_estimates'),
                'callback'            => [$this, 'listUsers'],
            ],
        ]);
    }

    /**
     * GET /ca/v1/users
     * Returns WordPress users with customer or ca_customer role
     * Includes: id, email, name, roles, ghlContactId, hasPortal
     */
    public function listUsers(WP_REST_Request $request): WP_REST_Response
    {
        $limit = (int) ($request->get_param('limit') ?: 100);
        $limit = min($limit, 200); // Cap at 200 for performance

        $users = get_users([
            'role__in' => ['customer', 'ca_customer'], // Include both customer roles
            'number' => $limit,
            'orderby' => 'registered',
            'order' => 'DESC',
        ]);

        $formatted = [];
        foreach ($users as $user) {
            $ghlContactId = get_user_meta($user->ID, 'ghl_contact_id', true);
            $hasPortal = user_can($user, 'ca_access_portal');

            $formatted[] = [
                'id' => $user->ID,
                'email' => $user->user_email,
                'name' => trim(($user->first_name ?? '') . ' ' . ($user->last_name ?? '')) ?: $user->display_name,
                'firstName' => $user->first_name ?? '',
                'lastName' => $user->last_name ?? '',
                'roles' => is_array($user->roles) ? $user->roles : [],
                'ghlContactId' => $ghlContactId ?: null,
                'hasPortal' => $hasPortal,
                'registered' => $user->user_registered,
            ];
        }

        $response = new WP_REST_Response([
            'ok' => true,
            'users' => $formatted,
            'total' => count($formatted),
        ], 200);
        $this->addSecurityHeaders($response);
        return $response;
    }

    private function isDevBypass(): bool
    {
        return defined('WP_DEBUG') && WP_DEBUG && isset($_SERVER['HTTP_X_CA_DEV']) && $_SERVER['HTTP_X_CA_DEV'] === '1';
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

