<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\Estimate\EstimateSnapshotRepository;
use CheapAlarms\Plugin\Services\EstimateService;
use CheapAlarms\Plugin\Services\PortalService;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

use function get_option;
use function get_user_meta;
use function sanitize_email;
use function sanitize_text_field;
use function email_exists;
use function wp_get_attachment_url;
use function wp_get_current_user;
use function get_transient;
use function set_transient;
use Throwable;

class EstimateController implements ControllerInterface
{
    private EstimateService $service;
    private PortalService $portalService;
    private Authenticator $auth;
    private EstimateSnapshotRepository $snapshotRepo;

    public function __construct(private Container $container)
    {
        $this->service = $this->container->get(EstimateService::class);
        $this->portalService = $this->container->get(PortalService::class);
        $this->auth    = $this->container->get(Authenticator::class);
        $this->snapshotRepo = $this->container->get(EstimateSnapshotRepository::class);
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
            'permission_callback' => function () {
                // Always return true - we'll validate authentication in the callback
                // This allows the request to proceed, and the callback will check if user is authenticated
                // This approach works better with JWT authentication where determine_current_user filter
                // runs after permission_callback, so wp_get_current_user() might not be set yet here
                return true;
            },
            'callback'            => function (WP_REST_Request $request) {
                $this->auth->ensureConfigured();
                
                $estimateId = sanitize_text_field($request->get_param('estimateId'));
                if (!$estimateId) {
                    return new WP_REST_Response(['ok' => false, 'err' => 'estimateId required'], 400);
                }
                
                // Allow admins (SECURITY: Check for WP_Error, not just truthy value)
                $adminCheck = $this->auth->requireCapability('ca_view_estimates');
                if (!is_wp_error($adminCheck)) {
                    $result = $this->service->getEstimate($request->get_params());
                    return $this->respond($result, $request);
                }
                
                // FIX: Use direct JWT authentication instead of resetting user context
                // This ensures JWT cookies are properly authenticated (same fix as /portal/dashboard)
                $userId = $this->auth->authenticateViaJwt();
                if ($userId && $userId > 0) {
                    wp_set_current_user($userId);
                    $user = wp_get_current_user();
                } else {
                    $user = wp_get_current_user();
                }
                
                // Check if user is authenticated and linked to estimate
                if ($user && $user->ID > 0) {
                    $linkedEstimateIds = get_user_meta($user->ID, 'ca_estimate_ids', true);
                    if (!is_array($linkedEstimateIds)) {
                        $linkedEstimateIds = array_filter([$linkedEstimateIds]);
                    }
                    
                    // FIX: Normalize estimate IDs to strings for comparison (matches dashboard logic)
                    // This prevents type mismatch failures (string vs int) that cause 401 errors
                    $normalizedLinkedIds = array_map('strval', $linkedEstimateIds);
                    $normalizedEstimateId = (string) $estimateId;
                    
                    if (in_array($normalizedEstimateId, $normalizedLinkedIds, true)) {
                        // User is linked to this estimate - allow access
                        $result = $this->service->getEstimate($request->get_params());
                        return $this->respond($result, $request);
                    }
                    
                    // FIX: Also check if estimate is linked to user via portal metadata
                    // This handles cases where ca_estimate_ids might be out of sync
                    // or where the estimate appears in the user's dashboard
                    if (current_user_can('ca_access_portal')) {
                        $portalMetaRepo = $this->container->get(\CheapAlarms\Plugin\Services\Shared\PortalMetaRepository::class);
                        $meta = $portalMetaRepo->get($estimateId);
                        
                        if (is_array($meta) && !empty($meta)) {
                            // Check if estimate is explicitly linked to this user
                            if (isset($meta['account']['userId']) && (int) $meta['account']['userId'] === $user->ID) {
                                // Estimate is linked to this user via portal metadata - allow access
                                $result = $this->service->getEstimate($request->get_params());
                                return $this->respond($result, $request);
                            }
                            
                            // FALLBACK: If estimate has portal metadata and user has portal access,
                            // and the estimate would appear in their dashboard (is in ca_estimate_ids),
                            // allow access even if userId check failed (handles edge cases)
                            // This is safe because if it's in ca_estimate_ids, it should be accessible
                            // Note: We already checked ca_estimate_ids above, so this is just a safety net
                        }
                    }
                }
                
                // Check invite token if provided (for unauthenticated access via portal link - read-only)
                $inviteToken = sanitize_text_field($request->get_param('inviteToken') ?? '');
                if ($inviteToken) {
                    $validationResult = $this->portalService->validateInviteToken($estimateId, $inviteToken);
                    if ($validationResult['valid']) {
                        // Valid invite token - read-only access
                        $result = $this->service->getEstimate($request->get_params());
                        return $this->respond($result, $request);
                    }
                }
                
                // No valid permission
                return new WP_REST_Response([
                    'ok' => false,
                    'err' => 'You do not have permission to view this estimate. Please log in or use a valid invite link.',
                ], 401);
            },
        ]);

        register_rest_route('ca/v1', '/estimate/list', [
            'methods'             => 'GET',
            'permission_callback' => fn () => $this->auth->requireCapability('ca_view_estimates'),
            'callback'            => function (WP_REST_Request $request) {
                $this->auth->ensureConfigured();
                
                $locationId = sanitize_text_field($request->get_param('locationId'));
                $limit = (int)$request->get_param('limit') ?: 20;
                $raw = (int)$request->get_param('raw');
                
                // Prefer snapshot table (fast + scalable). Fall back to transient-cached GHL list if snapshots are empty/unavailable.
                $items = null;
                $snapshotItems = $this->snapshotRepo->listByLocation($locationId);

                if (!is_wp_error($snapshotItems) && is_array($snapshotItems) && count($snapshotItems) > 0) {
                    $items = $snapshotItems;

                    // Best-effort background refresh if snapshots are stale.
                    $lastSyncedAt = $this->snapshotRepo->lastSyncedAt($locationId);
                    $stale = false;
                    if (!is_wp_error($lastSyncedAt) && is_string($lastSyncedAt) && $lastSyncedAt) {
                        $stale = (time() - (int)strtotime($lastSyncedAt)) > (3 * MINUTE_IN_SECONDS);
                    }
                    if ($stale && !wp_next_scheduled('ca_sync_estimate_snapshots', [$locationId])) {
                        wp_schedule_single_event(time() + 1, 'ca_sync_estimate_snapshots', [$locationId]);
                    }
                } else {
                    // If snapshots are missing/empty, schedule a background sync and fall back to the current transient cache path.
                    if (!wp_next_scheduled('ca_sync_estimate_snapshots', [$locationId])) {
                        wp_schedule_single_event(time() + 1, 'ca_sync_estimate_snapshots', [$locationId]);
                    }

                    // Build cache key for the GHL list
                    $cacheKey = "ca_estimate_list_ghl_{$locationId}_{$limit}_{$raw}";

                    $result   = get_transient($cacheKey);
                    $cacheHit = ($result !== false);

                    if (!$cacheHit) {
                        $result = $this->service->listEstimates($locationId, $limit, $raw);
                        if (is_wp_error($result)) {
                            return $this->respond($result, $request);
                        }
                        set_transient($cacheKey, $result, 3 * MINUTE_IN_SECONDS);
                    }

                    $items = $result['items'] ?? [];
                }

                if (!is_array($items)) {
                    $items = [];
                }

                // Apply limit (snapshots return all, we need to limit)
                if ($limit > 0 && count($items) > $limit) {
                    $items = array_slice($items, 0, $limit);
                }

                // Format response to match EstimateService::listEstimates() structure
                $result = [
                    'ok'         => true,
                    'locationId' => $locationId,
                    'count'      => count($items),
                    'items'      => $items,
                ];
                
                // Note: raw parameter is ignored when using snapshots (snapshots always have full data in raw_json)
                // If raw data is needed, it can be fetched via getEstimateById() which uses snapshots
                
                return $this->respond($result, $request);
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
                return $this->respond($result, $request);
            },
        ]);

        register_rest_route('ca/v1', '/estimate/create', [
            'methods'             => 'POST',
            'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_manage_portal'),
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
                    
                    // Check if estimate creation was successful
                    if (is_wp_error($result) || !($result['ok'] ?? false)) {
                        return $this->respond($result);
                    }
                    
                    // Extract estimate ID and email from response
                    $estimateId = $result['result']['estimate']['id'] ?? 
                                  $result['result']['id'] ?? 
                                  $result['result']['_id'] ?? null;
                    
                    // Extract email from payload (check multiple possible locations)
                    $email = sanitize_email(
                        $body['contactDetails']['email'] ?? 
                        $body['contact']['email'] ?? 
                        $body['email'] ?? ''
                    );
                    
                    $locationId = $body['altId'] ?? $this->container->get(\CheapAlarms\Plugin\Config\Config::class)->getLocationId();
                    $accountExists = false;
                    
                    // Check if account exists and link estimate if it does, or create new account
                    if ($email && $estimateId) {
                        $userId = email_exists($email);
                        if ($userId) {
                            // Link estimate to existing account
                            $linkResult = $this->portalService->linkEstimateToExistingAccount(
                                $estimateId,
                                $userId,
                                $locationId
                            );
                            
                            if (!is_wp_error($linkResult)) {
                                $accountExists = true;
                            }
                        } else {
                            // Account doesn't exist → Create account & send invite
                            $contactDetails = $body['contactDetails'] ?? $body['contact'] ?? [];
                            $contact = [
                                'email' => $email,
                                'firstName' => sanitize_text_field($contactDetails['firstName'] ?? $contactDetails['name'] ?? ''),
                                'lastName' => sanitize_text_field($contactDetails['lastName'] ?? ''),
                                'name' => sanitize_text_field($contactDetails['name'] ?? $contactDetails['firstName'] ?? ''),
                            ];
                            
                            $provisionResult = $this->portalService->provisionAccount(
                                $estimateId,
                                $contact,
                                $locationId
                            );
                            
                            if (!is_wp_error($provisionResult)) {
                                $accountExists = false; // New account was created
                                $result['accountCreated'] = true;
                                $result['account'] = $provisionResult['account'] ?? null;
                            } else {
                                // Log error but don't fail estimate creation
                                if (function_exists('error_log')) {
                                    error_log('[CheapAlarms][WARNING] Failed to provision account: ' . $provisionResult->get_error_message());
                                }
                                $result['accountProvisionError'] = $provisionResult->get_error_message();
                            }
                        }
                    }
                    
                    // Add account status to response
                    $result['accountExists'] = $accountExists;
                    $result['estimateId'] = $estimateId;
                    if ($email) {
                        $result['email'] = $email;
                    }
                    
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
                'permission_callback' => function (WP_REST_Request $request) {
                    // Allow admins
                    if ($this->auth->requireCapability('ca_manage_portal')) {
                        return true;
                    }
                    
                    // Get estimate ID from request body
                    $body = $request->get_json_params();
                    if (!is_array($body)) {
                        $body = json_decode($request->get_body(), true);
                    }
                    if (!is_array($body)) {
                        $body = [];
                    }
                    $estimateId = sanitize_text_field($body['estimateId'] ?? '');
                    
                    if (!$estimateId) {
                        return false; // No estimate ID provided
                    }
                    
                    // FIX: Use direct JWT authentication instead of resetting user context
                    $userId = $this->auth->authenticateViaJwt();
                    if ($userId && $userId > 0) {
                        wp_set_current_user($userId);
                        $user = wp_get_current_user();
                    } else {
                        $user = wp_get_current_user();
                    }
                    
                    // Check if user is authenticated and linked to estimate
                    if ($user && $user->ID > 0) {
                        $linkedEstimateIds = get_user_meta($user->ID, 'ca_estimate_ids', true);
                        if (!is_array($linkedEstimateIds)) {
                            $linkedEstimateIds = array_filter([$linkedEstimateIds]);
                        }
                        
                        // FIX: Normalize estimate IDs to strings for comparison (matches dashboard logic)
                        // This prevents type mismatch failures (string vs int)
                        $normalizedLinkedIds = array_map('strval', $linkedEstimateIds);
                        $normalizedEstimateId = (string) $estimateId;
                        
                        if (in_array($normalizedEstimateId, $normalizedLinkedIds, true)) {
                            return true; // User is logged in and linked to this estimate
                        }
                    }
                    
                    // Login is required for photo uploads - no inviteToken bypass
                    return false; // No valid permission - login required
                },
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
                'permission_callback' => function (WP_REST_Request $request) {
                    // FIX: Authenticate via JWT first, then check capabilities
                    // This ensures JWT-authenticated users can access photos
                    $userId = $this->auth->authenticateViaJwt();
                    if ($userId && $userId > 0) {
                        wp_set_current_user($userId);
                        return current_user_can('ca_access_portal') || current_user_can('ca_manage_portal');
                    }
                    // Allow public access - photos are linked to estimateId, not sensitive data
                    return true;
                },
                'callback'            => function (WP_REST_Request $request) {
                    $estimateId = sanitize_text_field($request->get_param('estimateId'));
                    if (!$estimateId) {
                        return new WP_REST_Response(['ok' => false, 'err' => 'estimateId required'], 400);
                    }
                    $raw = get_option('ca_estimate_uploads_' . $estimateId, '');
                    if (!$raw) {
                        return new WP_REST_Response([
                            'ok'     => true,
                            'stored' => null,
                        ], 200);
                    }
                    
                    $data = json_decode($raw, true);
                    if (!is_array($data) || empty($data['uploads'])) {
                        return new WP_REST_Response([
                            'ok'     => true,
                            'stored' => $data,
                        ], 200);
                    }
                    
                    // Filter out deleted attachments - verify each attachment still exists
                    $validUploads = [];
                    $needsUpdate = false;
                    
                    foreach ($data['uploads'] as $upload) {
                        $attachmentId = $upload['attachmentId'] ?? null;
                        if (!$attachmentId) {
                            // If no attachmentId, check if URL is still accessible
                            $url = $upload['url'] ?? $upload['urls'][0] ?? null;
                            if ($url && $this->isUrlAccessible($url)) {
                                $validUploads[] = $upload;
                            } else {
                                $needsUpdate = true; // Mark for cleanup
                            }
                            continue;
                        }
                        
                        // Check if attachment exists
                        $attachmentUrl = wp_get_attachment_url($attachmentId);
                        if ($attachmentUrl) {
                            // Attachment exists, update URL if needed
                            if (empty($upload['url']) || $upload['url'] !== $attachmentUrl) {
                                $upload['url'] = $attachmentUrl;
                                $needsUpdate = true;
                            }
                            $validUploads[] = $upload;
                        } else {
                            // Attachment was deleted, skip it
                            $needsUpdate = true;
                        }
                    }
                    
                    // Update stored data if any attachments were removed
                    if ($needsUpdate && count($validUploads) !== count($data['uploads'])) {
                        $data['uploads'] = $validUploads;
                        $encoded = wp_json_encode($data);
                        if ($encoded === false) {
                            // Log error but don't fail the request (data is already cleaned up)
                            if (function_exists('error_log')) {
                                error_log(sprintf(
                                    '[CheapAlarms] Failed to encode upload data JSON for estimate %s: %s',
                                    $estimateId,
                                    json_last_error_msg()
                                ));
                            }
                        } else {
                            update_option('ca_estimate_uploads_' . $estimateId, $encoded, false);
                        }
                    }
                    
                    return new WP_REST_Response([
                        'ok'     => true,
                        'stored' => $data,
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
     * Check if a URL is accessible (file exists)
     * @param string $url
     * @return bool
     */
    private function isUrlAccessible(string $url): bool
    {
        // For local URLs, check if file exists
        $uploadDir = wp_upload_dir();
        $uploadBaseUrl = $uploadDir['baseurl'];
        
        // Use strpos for PHP 7.x compatibility instead of str_starts_with (PHP 8.0+)
        if (strpos($url, $uploadBaseUrl) === 0) {
            $uploadBasePath = $uploadDir['basedir'];
            $relativePath = str_replace($uploadBaseUrl, '', $url);
            $filePath = $uploadBasePath . $relativePath;
            return file_exists($filePath);
        }
        
        // For external URLs, we can't easily check, so assume accessible
        // In production, you might want to do a HEAD request
        return true;
    }

    private function isDevBypass(): bool
    {
        $header = isset($_SERVER['HTTP_X_CA_DEV']) ? trim((string) $_SERVER['HTTP_X_CA_DEV']) : '';
        $query  = isset($_GET['__dev']) ? trim((string) $_GET['__dev']) : '';
        $addr = $_SERVER['REMOTE_ADDR'] ?? '';
        // SECURITY: Never trust Host headers for "local" detection (can be spoofed behind proxies).
        // Local bypass is ONLY allowed from loopback addresses and ONLY in WP_DEBUG.
        $isLocal = in_array($addr, ['127.0.0.1', '::1'], true);
        $isDebug = defined('WP_DEBUG') && WP_DEBUG;
        
        // Allow if header or query param is set from localhost
        if ($isLocal && $isDebug && ($header === '1' || $query === '1')) {
            return true;
        }
        
        // Also allow if CA_DEV_BYPASS constant is set (from wp-config.php)
        if ($isLocal && $isDebug && defined('CA_DEV_BYPASS') && CA_DEV_BYPASS) {
            return true;
        }
        
        return false;
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
                'ghl_api_error' => 'Service temporarily unavailable. Please try again.',
                'missing_location' => 'Location ID is required.',
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


