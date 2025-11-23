<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\EstimateService;
use CheapAlarms\Plugin\Services\PortalService;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

use function get_option;
use function sanitize_email;
use function sanitize_text_field;
use function email_exists;
use function wp_get_attachment_url;
use Throwable;

class EstimateController implements ControllerInterface
{
    private EstimateService $service;
    private PortalService $portalService;
    private Authenticator $auth;

    public function __construct(private Container $container)
    {
        $this->service = $this->container->get(EstimateService::class);
        $this->portalService = $this->container->get(PortalService::class);
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
                    
                    // Check if account exists and link estimate if it does
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
                'permission_callback' => function (WP_REST_Request $request) {
                    // Allow logged-in users with portal access
                    if (is_user_logged_in()) {
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
                        update_option('ca_estimate_uploads_' . $estimateId, wp_json_encode($data), false);
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
        $isLocal = in_array($addr, ['127.0.0.1', '::1'], true);
        // Also allow when Host header targets localhost
        $host = $_SERVER['HTTP_HOST'] ?? '';
        $isLocal = $isLocal || strpos($host, 'localhost') !== false || strpos($host, '127.0.0.1') !== false;
        
        // Allow if header or query param is set from localhost
        if ($isLocal && ($header === '1' || $query === '1')) {
            return true;
        }
        
        // Also allow if CA_DEV_BYPASS constant is set (from wp-config.php)
        if ($isLocal && defined('CA_DEV_BYPASS') && CA_DEV_BYPASS) {
            return true;
        }
        
        return false;
    }
}

