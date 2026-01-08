<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\Services\Container;
use WP_REST_Request;
use WP_REST_Response;

use function get_users;
use function get_user_meta;
use function user_can;
use function wp_delete_user;
use function get_user_by;
use function wp_get_current_user;
use function wp_generate_password;
use function sanitize_text_field;
use function rawurlencode;
use WP_Error;

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

        // Bulk delete users - MUST be registered BEFORE the parameterized route
        register_rest_route('ca/v1', '/admin/users/bulk-delete', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                // Ensure user is loaded before capability checks (JWT timing)
                global $current_user;
                $current_user = null;
                wp_get_current_user();

                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->errorResponse($authCheck);
                }

                return $this->bulkDelete($request);
            },
        ]);

        register_rest_route('ca/v1', '/admin/users/(?P<userId>[0-9]+)/delete', [
            'methods'             => 'POST',
            // IMPORTANT: permission_callback runs before callback. We need the current user loaded
            // first (JWT timing), so we do auth inside callback after forcing wp_get_current_user().
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                // Ensure user is loaded before capability checks (JWT timing)
                global $current_user;
                $current_user = null;
                wp_get_current_user();

                $authCheck = $this->auth->requireCapability('ca_manage_portal');
                if (is_wp_error($authCheck)) {
                    return $this->errorResponse($authCheck);
                }

                return $this->deleteUser($request);
            },
            'args'                => [
                'userId' => [
                    'required' => true,
                    'type'     => 'integer',
                ],
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

        // PHASE 1: Collect all user IDs
        $userIds = array_map(fn($user) => $user->ID, $users);
        
        // PHASE 2: Batch fetch ghl_contact_id for all users in ONE query (prevents N+1)
        $ghlContactIdMap = [];
        if (!empty($userIds)) {
            global $wpdb;
            $placeholders = implode(',', array_fill(0, count($userIds), '%d'));
            $query = $wpdb->prepare(
                "SELECT user_id, meta_value FROM {$wpdb->usermeta} 
                 WHERE user_id IN ($placeholders) AND meta_key = 'ghl_contact_id'",
                ...$userIds
            );
            $results = $wpdb->get_results($query, ARRAY_A);
            
            // Check for database errors
            if ($wpdb->last_error) {
                if (function_exists('error_log')) {
                    error_log(sprintf(
                        '[CheapAlarms] Database error in listUsers: %s',
                        $wpdb->last_error
                    ));
                }
                // Continue with empty map - users will have null ghl_contact_id
            } elseif (is_array($results)) {
                foreach ($results as $row) {
                    if (!empty($row['user_id']) && !empty($row['meta_value'])) {
                        $ghlContactIdMap[(int)$row['user_id']] = $row['meta_value'];
                    }
                }
            }
        }

        // PHASE 3: Process users with pre-fetched data
        $formatted = [];
        foreach ($users as $user) {
            // Use pre-fetched ghl_contact_id instead of get_user_meta()
            $ghlContactId = $ghlContactIdMap[$user->ID] ?? null;
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

    /**
     * Delete user/contact with scope support (local, ghl, both).
     * Fail-closed: if scope=both and GHL delete fails, local delete is skipped.
     */
    public function deleteUser(WP_REST_Request $request): WP_REST_Response
    {
        // Ensure user is loaded before capability checks (JWT timing)
        global $current_user;
        $current_user = null;
        wp_get_current_user();

        // Ensure wp_delete_user is available in REST context
        if (!function_exists('wp_delete_user')) {
            require_once ABSPATH . 'wp-admin/includes/user.php';
        }

        // Safety gate (check environment variable)
        $enabled = getenv('CA_ENABLE_DESTRUCTIVE_ACTIONS');
        if ($enabled === false) {
            $enabled = defined('CA_ENABLE_DESTRUCTIVE_ACTIONS') ? CA_ENABLE_DESTRUCTIVE_ACTIONS : false;
        }
        
        if ($enabled !== 'true' && $enabled !== true) {
            $error = new WP_Error(
                'destructive_actions_disabled',
                __('Destructive actions are disabled. Set CA_ENABLE_DESTRUCTIVE_ACTIONS=true to enable.', 'cheapalarms'),
                ['status' => 403]
            );
            return $this->errorResponse($error);
        }

        $userId = (int) $request->get_param('userId');
        $body = $request->get_json_params() ?? [];
        $scope = sanitize_text_field($body['scope'] ?? 'both');
        $confirm = sanitize_text_field($body['confirm'] ?? '');
        $locationId = sanitize_text_field($body['locationId'] ?? '');

        // Validation
        if ($userId <= 0) {
            return $this->errorResponse(new WP_Error('bad_request', __('Invalid user ID.', 'cheapalarms'), ['status' => 400]));
        }

        if (!in_array($scope, ['local', 'ghl', 'both'], true)) {
            return $this->errorResponse(new WP_Error('bad_request', __('Invalid scope. Must be: local, ghl, or both.', 'cheapalarms'), ['status' => 400]));
        }

        if ($confirm !== 'DELETE') {
            return $this->errorResponse(new WP_Error('bad_request', __('Confirmation required. Set confirm="DELETE" in request body.', 'cheapalarms'), ['status' => 400]));
        }

        // Get user and validate
        $user = get_user_by('id', $userId);
        if (!$user) {
            return $this->errorResponse(new WP_Error('not_found', __('User not found.', 'cheapalarms'), ['status' => 404]));
        }

        // Safety: Never delete admin users
        if (user_can($user, 'manage_options')) {
            return $this->errorResponse(new WP_Error('forbidden', __('Cannot delete administrator accounts.', 'cheapalarms'), ['status' => 403]));
        }

        $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
        $currentUser = wp_get_current_user();
        $correlationId = wp_generate_password(12, false);

        $logger->info('User delete initiated', [
            'correlationId' => $correlationId,
            'userId' => $userId,
            'userEmail' => $user->user_email,
            'scope' => $scope,
            'deletedByUserId' => $currentUser->ID ?? null,
            'deletedByUserEmail' => $currentUser->user_email ?? null,
        ]);

        $result = [
            'ok' => true,
            'scope' => $scope,
            'correlationId' => $correlationId,
            'local' => ['ok' => false, 'skipped' => true],
            'ghl' => ['ok' => false, 'skipped' => true],
        ];

        // Get GHL contact ID from user meta
        $ghlContactId = get_user_meta($userId, 'ghl_contact_id', true);
        $ghlContactId = $ghlContactId ?: null;

        $wantsGhl = ($scope === 'ghl' || $scope === 'both');
        $wantsLocal = ($scope === 'local' || $scope === 'both');

        if ($wantsGhl && empty($ghlContactId)) {
            return $this->errorResponse(new WP_Error('missing_ghl_contact_id', __('User has no linked GHL contact ID.', 'cheapalarms'), ['status' => 400]));
        }

        if ($wantsGhl && empty($locationId)) {
            return $this->errorResponse(new WP_Error('missing_location', __('locationId is required for GHL delete.', 'cheapalarms'), ['status' => 400]));
        }

        // Determine execution order: for "both", do GHL first (fail-closed)
        $doGhl = $wantsGhl;
        $doLocal = $wantsLocal;

        // Step 1: GHL delete (if needed, and first for fail-closed)
        if ($doGhl) {
            $ghlClient = $this->container->get(\CheapAlarms\Plugin\Services\GhlClient::class);
            $ghlResult = $ghlClient->delete(
                '/contacts/' . rawurlencode($ghlContactId),
                [],
                $locationId,
                10,
                0
            );

            if (is_wp_error($ghlResult)) {
                $errorData = $ghlResult->get_error_data();
                $result['ghl'] = [
                    'ok' => false,
                    'error' => $ghlResult->get_error_message(),
                    'code' => $ghlResult->get_error_code(),
                    'httpCode' => $errorData['code'] ?? null,
                ];

                // Fail-closed: if GHL fails and scope=both, skip local delete
                if ($scope === 'both') {
                    $result['local']['skipped'] = true;
                    $result['ok'] = false;
                    $logger->warning('User delete failed (fail-closed)', [
                        'correlationId' => $correlationId,
                        'userId' => $userId,
                        'ghlContactId' => $ghlContactId,
                        'ghlError' => $ghlResult->get_error_message(),
                    ]);
                    return $this->errorResponse(new WP_Error('ghl_delete_failed', 'GHL contact deletion failed. Local deletion skipped (fail-closed).', ['status' => 500, 'details' => $result]));
                }
            } else {
                $result['ghl'] = [
                    'ok' => true,
                    'alreadyDeleted' => $ghlResult['alreadyDeleted'] ?? false,
                ];
                $logger->info('Contact deleted from GHL', [
                    'correlationId' => $correlationId,
                    'userId' => $userId,
                    'ghlContactId' => $ghlContactId,
                    'alreadyDeleted' => $result['ghl']['alreadyDeleted'],
                ]);
            }
        }

        // Step 2: Local delete (if needed, and GHL succeeded or scope=local)
        if ($doLocal && !($scope === 'both' && isset($result['ghl']['ok']) && !$result['ghl']['ok'])) {
            $deleted = wp_delete_user($userId);

            if ($deleted) {
                $result['local'] = [
                    'ok' => true,
                    'alreadyDeleted' => false,
                ];
                $logger->info('User deleted from WordPress', [
                    'correlationId' => $correlationId,
                    'userId' => $userId,
                    'userEmail' => $user->user_email,
                ]);
            } else {
                $result['local'] = [
                    'ok' => false,
                    'error' => 'Failed to delete user (wp_delete_user returned false)',
                ];
                $result['ok'] = false;
                $logger->error('Failed to delete user from WordPress', [
                    'correlationId' => $correlationId,
                    'userId' => $userId,
                ]);
            }
        }

        // Build response
        if (!$result['ok']) {
            return $this->errorResponse(new WP_Error('delete_partial_failure', 'Delete operation completed with errors.', ['status' => 500, 'details' => $result]));
        }

        $response = new WP_REST_Response($result, 200);
        $this->addSecurityHeaders($response);
        return $response;
    }

    /**
     * POST /ca/v1/admin/users/bulk-delete
     * Permanently delete multiple users/contacts
     */
    public function bulkDelete(WP_REST_Request $request): WP_REST_Response
    {
        // Safety gate (check environment variable)
        $enabled = getenv('CA_ENABLE_DESTRUCTIVE_ACTIONS');
        if ($enabled === false) {
            $enabled = defined('CA_ENABLE_DESTRUCTIVE_ACTIONS') ? CA_ENABLE_DESTRUCTIVE_ACTIONS : false;
        }
        
        if ($enabled !== 'true' && $enabled !== true) {
            $error = new WP_Error(
                'destructive_actions_disabled',
                __('Destructive actions are disabled. Set CA_ENABLE_DESTRUCTIVE_ACTIONS=true to enable.', 'cheapalarms'),
                ['status' => 403]
            );
            return $this->errorResponse($error);
        }

        $body = $request->get_json_params() ?? [];
        $confirm = sanitize_text_field($body['confirm'] ?? '');
        $userIds = $body['userIds'] ?? [];
        $scope = sanitize_text_field($body['scope'] ?? 'both');
        $requestLocationId = !empty($body['locationId']) ? sanitize_text_field($body['locationId']) : null;

        if ($confirm !== 'BULK_DELETE') {
            return $this->errorResponse(new WP_Error('bad_request', __('Confirmation required. Set confirm="BULK_DELETE"', 'cheapalarms'), ['status' => 400]));
        }

        if (!is_array($userIds) || empty($userIds)) {
            return $this->errorResponse(new WP_Error('bad_request', __('userIds array is required', 'cheapalarms'), ['status' => 400]));
        }

        if (!in_array($scope, ['local', 'ghl', 'both'], true)) {
            return $this->errorResponse(new WP_Error('bad_request', __('Invalid scope. Must be: local, ghl, or both.', 'cheapalarms'), ['status' => 400]));
        }

        // Validate each ID is a valid integer
        foreach ($userIds as $id) {
            if (!is_numeric($id) || (int)$id <= 0) {
                return $this->errorResponse(new WP_Error('bad_request', __('Invalid user ID format. All IDs must be positive integers.', 'cheapalarms'), ['status' => 400]));
            }
        }

        // Limit batch size for performance
        $maxBatchSize = 1000;
        if (count($userIds) > $maxBatchSize) {
            return $this->errorResponse(new WP_Error('bad_request', sprintf(__('Maximum %d users per batch', 'cheapalarms'), $maxBatchSize), ['status' => 400]));
        }

        $originalTimeLimit = ini_get('max_execution_time');
        @set_time_limit(300); // 5 minutes for large batches

        try {
            $currentUser = wp_get_current_user();
            $deleted = 0;
            $errors = [];

            // Process in batches of 100 for better performance
            $batchSize = 100;
            $batches = array_chunk($userIds, $batchSize);

            foreach ($batches as $batch) {
                foreach ($batch as $userId) {
                    $userId = (int)$userId;
                    if ($userId <= 0) {
                        continue;
                    }

                    // Safety: Never delete admin users
                    $user = get_user_by('id', $userId);
                    if (!$user) {
                        $errors[] = ['userId' => $userId, 'error' => 'User not found'];
                        continue;
                    }

                    if (user_can($user, 'manage_options')) {
                        $errors[] = ['userId' => $userId, 'error' => 'Cannot delete administrator accounts'];
                        continue;
                    }

                    // Prevent deleting current user
                    if ($userId === ($currentUser->ID ?? 0)) {
                        $errors[] = ['userId' => $userId, 'error' => 'Cannot delete your own account'];
                        continue;
                    }

                    // Create a mock request for deleteUser logic
                    $deleteRequest = new WP_REST_Request('POST', '/ca/v1/admin/users/' . $userId . '/delete');
                    $deleteRequest->set_param('userId', $userId);
                    $deleteRequest->set_body_params([
                        'confirm' => 'DELETE',
                        'scope' => $scope,
                        'locationId' => $requestLocationId,
                    ]);

                    // Call the existing deleteUser method
                    $result = $this->deleteUser($deleteRequest);
                    
                    // deleteUser always returns WP_REST_Response (never raw WP_Error)
                    $responseData = $result->get_data();
                    if (isset($responseData['ok']) && $responseData['ok'] === true) {
                        $deleted++;
                    } else {
                        $errors[] = ['userId' => $userId, 'error' => $responseData['error'] ?? 'Delete failed'];
                    }
                }
            }

            $response = new WP_REST_Response([
                'ok' => true,
                'deleted' => $deleted,
                'errors' => $errors,
                'scope' => $scope,
            ], 200);
            $this->addSecurityHeaders($response);
            return $response;
        } finally {
            // Always restore original time limit
            if ($originalTimeLimit !== false && $originalTimeLimit !== '0') {
                @set_time_limit((int)$originalTimeLimit);
            }
        }
    }

    /**
     * Create standardized error response
     *
     * @param WP_Error $error
     * @return WP_REST_Response
     */
    private function errorResponse(WP_Error $error): WP_REST_Response
    {
        $data = $error->get_error_data();
        $status = (is_array($data) && isset($data['status'])) ? (int)$data['status'] : 500;
        $response = new WP_REST_Response([
            'ok' => false,
            'error' => $error->get_error_message(),
            'code' => $error->get_error_code(),
            'details' => $data,
        ], $status);
        $this->addSecurityHeaders($response);
        return $response;
    }
}

