<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\JobLinkService;
use CheapAlarms\Plugin\Services\ServiceM8Service;
use CheapAlarms\Plugin\Services\Shared\LocationResolver;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

use function current_time;
use function sanitize_email;
use function sanitize_text_field;
use function sanitize_textarea_field;

class ServiceM8Controller implements ControllerInterface
{
    private ServiceM8Service $service;
    private JobLinkService $linkService;
    private Authenticator $auth;
    private LocationResolver $locationResolver;

    public function __construct(private Container $container)
    {
        $this->service = $this->container->get(ServiceM8Service::class);
        $this->linkService = $this->container->get(JobLinkService::class);
        $this->auth    = $this->container->get(Authenticator::class);
        $this->locationResolver = $this->container->get(LocationResolver::class);
    }

    /**
     * Validate UUID format (alphanumeric and hyphens only)
     *
     * @param string $uuid UUID to validate
     * @return bool True if valid format
     */
    private function validateUuid(string $uuid): bool
    {
        return (bool) preg_match('/^[a-zA-Z0-9\-]+$/', $uuid);
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

        // Staff endpoints
        register_rest_route('ca/v1', '/servicem8/staff', [
            [
                'methods'             => 'GET',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_view_estimates'),
                'callback'            => function (WP_REST_Request $request) {
                    $params = [
                        'uuid' => $request->get_param('uuid'),
                        'name' => $request->get_param('name'),
                        'email' => $request->get_param('email'),
                    ];
                    $result = $this->service->getStaff($params);
                    return $this->respond($result);
                },
            ],
        ]);

        // Single staff member endpoint
        register_rest_route('ca/v1', '/servicem8/staff/(?P<uuid>[a-zA-Z0-9\-]+)', [
            [
                'methods'             => 'GET',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_view_estimates'),
                'callback'            => function (WP_REST_Request $request) {
                    $uuid = sanitize_text_field($request->get_param('uuid'));
                    $result = $this->service->getStaffMember($uuid);
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

        // Job linking endpoints (MUST be registered BEFORE single job endpoints to avoid route conflict)
        register_rest_route('ca/v1', '/servicem8/jobs/link', [
            [
                'methods'             => 'POST',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_manage_portal'),
                'callback'            => function (WP_REST_Request $request) {
                    $body = $request->get_json_params();
                    if (!is_array($body)) {
                        $body = json_decode($request->get_body(), true);
                    }
                    if (!is_array($body)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'Invalid request body',
                        ], 400);
                    }

                    $estimateId = sanitize_text_field($body['estimateId'] ?? '');
                    $jobUuid = sanitize_text_field($body['jobUuid'] ?? '');
                    $metadata = is_array($body['metadata'] ?? null) ? $body['metadata'] : null;

                    if (empty($estimateId) || empty($jobUuid)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'estimateId and jobUuid are required',
                        ], 400);
                    }

                    $result = $this->linkService->linkEstimateToJob($estimateId, $jobUuid, $metadata);
                    
                    if (is_wp_error($result)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => $result->get_error_message(),
                            'code' => $result->get_error_code(),
                        ], $result->get_error_data()['status'] ?? 500);
                    }

                    $linkData = $this->linkService->getLinkByEstimateId($estimateId);
                    return new WP_REST_Response([
                        'ok' => true,
                        'link' => $linkData,
                    ], 200);
                },
            ],
            [
                'methods'             => 'GET',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_view_estimates'),
                'callback'            => function (WP_REST_Request $request) {
                    $estimateId = sanitize_text_field($request->get_param('estimateId') ?? '');
                    $jobUuid = sanitize_text_field($request->get_param('jobUuid') ?? '');

                    // SECURITY: Require at least one parameter
                    if (empty($estimateId) && empty($jobUuid)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'estimateId or jobUuid is required',
                        ], 400);
                    }

                    // SECURITY: Validate UUID format if provided
                    if (!empty($jobUuid) && !$this->validateUuid($jobUuid)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'Invalid job UUID format',
                        ], 400);
                    }

                    // SECURITY: Validate estimateId format (alphanumeric, hyphens, underscores)
                    if (!empty($estimateId) && !preg_match('/^[a-zA-Z0-9\-_]+$/', $estimateId)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'Invalid estimate ID format',
                        ], 400);
                    }

                    if (!empty($estimateId)) {
                        $linkData = $this->linkService->getLinkByEstimateId($estimateId);
                        if (!$linkData) {
                            return new WP_REST_Response([
                                'ok' => false,
                                'error' => 'Link not found',
                            ], 404);
                        }
                        return new WP_REST_Response([
                            'ok' => true,
                            'link' => $linkData,
                        ], 200);
                    }

                    if (!empty($jobUuid)) {
                        $linkData = $this->linkService->getLinkByJobUuid($jobUuid);
                        if (!$linkData) {
                            return new WP_REST_Response([
                                'ok' => false,
                                'error' => 'Link not found',
                            ], 404);
                        }
                        return new WP_REST_Response([
                            'ok' => true,
                            'link' => $linkData,
                        ], 200);
                    }

                    return new WP_REST_Response([
                        'ok' => false,
                        'error' => 'estimateId or jobUuid is required',
                    ], 400);
                },
            ],
            [
                'methods'             => 'DELETE',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_manage_portal'),
                'callback'            => function (WP_REST_Request $request) {
                    $estimateId = sanitize_text_field($request->get_param('estimateId') ?? '');

                    if (empty($estimateId)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'estimateId is required',
                        ], 400);
                    }

                    $result = $this->linkService->unlinkEstimateFromJob($estimateId);
                    
                    return new WP_REST_Response([
                        'ok' => $result,
                        'message' => $result ? 'Link removed' : 'Link not found',
                    ], $result ? 200 : 404);
                },
            ],
        ]);

        // List all links (admin only)
        register_rest_route('ca/v1', '/servicem8/jobs/links', [
            [
                'methods'             => 'GET',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_manage_portal'),
                'callback'            => function (WP_REST_Request $request) {
                    $limit = (int) ($request->get_param('limit') ?: 100);
                    $limit = min($limit, 500); // Cap at 500
                    
                    $links = $this->linkService->getAllLinks($limit);
                    
                    return new WP_REST_Response([
                        'ok' => true,
                        'links' => $links,
                        'count' => count($links),
                    ], 200);
                },
            ],
        ]);

        // Update job from estimate
        register_rest_route('ca/v1', '/servicem8/jobs/update-from-estimate', [
            [
                'methods'             => 'POST',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_manage_portal'),
                'callback'            => function (WP_REST_Request $request) {
                    $body = $request->get_json_params();
                    if (!is_array($body)) {
                        $body = json_decode($request->get_body(), true);
                    }
                    if (!is_array($body)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'Invalid request body',
                        ], 400);
                    }

                    $estimateId = sanitize_text_field($body['estimateId'] ?? '');
                    $locationId = sanitize_text_field($body['locationId'] ?? '');
                    $jobUuid = sanitize_text_field($body['jobUuid'] ?? '');
                    $options = is_array($body['options'] ?? null) ? $body['options'] : [];

                    if (empty($estimateId)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'estimateId is required',
                        ], 400);
                    }

                    if (empty($locationId)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'locationId is required',
                        ], 400);
                    }

                    if (empty($jobUuid)) {
                        // Try to get job UUID from existing link
                        $existingLink = $this->linkService->getLinkByEstimateId($estimateId);
                        if (!$existingLink || empty($existingLink['jobUuid'])) {
                            return new WP_REST_Response([
                                'ok' => false,
                                'error' => 'jobUuid is required or estimate must be linked to a job',
                            ], 400);
                        }
                        $jobUuid = $existingLink['jobUuid'];
                    }

                    // Update job from estimate
                    $result = $this->service->updateJobFromEstimate($estimateId, $locationId, $jobUuid, $options);
                    
                    if (is_wp_error($result)) {
                        return $this->respond($result);
                    }

                    return new WP_REST_Response([
                        'ok' => true,
                        'job' => $result['job'],
                        'jobUuid' => $result['jobUuid'],
                        'company' => $result['company'],
                        'updated' => true,
                    ], 200);
                },
            ],
        ]);

        // Create job from estimate
        register_rest_route('ca/v1', '/servicem8/jobs/create-from-estimate', [
            [
                'methods'             => 'POST',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_manage_portal'),
                'callback'            => function (WP_REST_Request $request) {
                    $body = $request->get_json_params();
                    if (!is_array($body)) {
                        $body = json_decode($request->get_body(), true);
                    }
                    if (!is_array($body)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'Invalid request body',
                        ], 400);
                    }

                    $estimateId = sanitize_text_field($body['estimateId'] ?? '');
                    $locationIdParam = sanitize_text_field($body['locationId'] ?? '');
                    $options = is_array($body['options'] ?? null) ? $body['options'] : [];

                    if (empty($estimateId)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'estimateId is required',
                        ], 400);
                    }

                    // Resolve locationId from request body or config default (like other admin endpoints)
                    $locationId = !empty($locationIdParam) 
                        ? $locationIdParam 
                        : $this->locationResolver->resolve(null);
                    
                    if (empty($locationId)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'locationId is required. Please provide it in the request or configure it in settings.',
                        ], 400);
                    }

                    // Check if estimate is already linked
                    $existingLink = $this->linkService->getLinkByEstimateId($estimateId);
                    $updateIfExists = filter_var($body['updateIfExists'] ?? $request->get_param('updateIfExists') ?? false, FILTER_VALIDATE_BOOLEAN);
                    
                    if ($existingLink && $updateIfExists) {
                        // Update existing job instead of creating new one
                        $jobUuid = $existingLink['jobUuid'] ?? null;
                        if (empty($jobUuid)) {
                            return new WP_REST_Response([
                                'ok' => false,
                                'error' => 'Existing link found but job UUID is missing',
                                'existingLink' => $existingLink,
                            ], 400);
                        }

                        $result = $this->service->updateJobFromEstimate($estimateId, $locationId, $jobUuid, $options);
                        
                        if (is_wp_error($result)) {
                            return $this->respond($result);
                        }

                        return new WP_REST_Response([
                            'ok' => true,
                            'job' => $result['job'],
                            'jobUuid' => $result['jobUuid'],
                            'company' => $result['company'],
                            'updated' => true,
                            'linked' => true,
                        ], 200);
                    } elseif ($existingLink) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'Estimate is already linked to a job',
                            'existingLink' => $existingLink,
                            'hint' => 'Use updateIfExists=true to update the existing job',
                        ], 409); // Conflict
                    }

                    // Create job from estimate (with idempotency check via linkService)
                    $result = $this->service->createJobFromEstimate($estimateId, $locationId, $options, $this->linkService);
                    
                    if (is_wp_error($result)) {
                        return $this->respond($result);
                    }

                    // Auto-link the job
                    // Try multiple possible UUID locations in the response
                    $jobUuid = $result['jobUuid'] ?? $result['job']['uuid'] ?? $result['job']['job_uuid'] ?? $result['job']['id'] ?? null;
                    
                    if ($jobUuid) {
                        $linkMetadata = [
                            'companyUuid' => $result['company']['uuid'] ?? null,
                            'companyCreated' => $result['companyCreated'] ?? false,
                            'createdFrom' => 'estimate',
                            'createdAt' => current_time('mysql'),
                        ];
                        
                        $linkResult = $this->linkService->linkEstimateToJob($estimateId, $jobUuid, $linkMetadata);
                        if (is_wp_error($linkResult)) {
                            // Log error but don't fail the request - job was created successfully
                            error_log('Failed to link job after creation: ' . $linkResult->get_error_message());
                        }
                    } else {
                        // Log warning if UUID not found
                        error_log('Job UUID not found in response, cannot create link. Response keys: ' . implode(', ', array_keys($result)));
                    }

                    return new WP_REST_Response([
                        'ok' => true,
                        'job' => $result['job'],
                        'jobUuid' => $jobUuid, // Explicitly include UUID
                        'company' => $result['company'],
                        'companyCreated' => $result['companyCreated'] ?? false,
                        'linked' => !empty($jobUuid),
                    ], 200);
                },
            ],
        ]);

        // Job Activities endpoints (scheduling)
        register_rest_route('ca/v1', '/servicem8/jobs/(?P<jobUuid>[a-zA-Z0-9\-]+)/activities', [
            [
                'methods'             => 'GET',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_view_estimates'),
                'callback'            => function (WP_REST_Request $request) {
                    $jobUuid = sanitize_text_field($request->get_param('jobUuid'));
                    
                    // SECURITY: Validate UUID format
                    if (!$this->validateUuid($jobUuid)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'Invalid job UUID format',
                        ], 400);
                    }
                    
                    $result = $this->service->getJobActivities($jobUuid);
                    return $this->respond($result);
                },
            ],
        ]);

        // Schedule job endpoint (creates Job Activity)
        register_rest_route('ca/v1', '/servicem8/jobs/(?P<jobUuid>[a-zA-Z0-9\-]+)/schedule', [
            [
                'methods'             => 'POST',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_manage_portal'),
                'callback'            => function (WP_REST_Request $request) {
                    $jobUuid = sanitize_text_field($request->get_param('jobUuid'));
                    
                    // SECURITY: Validate UUID format
                    if (!$this->validateUuid($jobUuid)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'Invalid job UUID format',
                        ], 400);
                    }
                    
                    $body = $request->get_json_params();
                    if (!is_array($body)) {
                        $body = json_decode($request->get_body(), true);
                    }
                    if (!is_array($body)) {
                        $body = [];
                    }

                    $staffUuid = sanitize_text_field($body['staffUuid'] ?? '');
                    $startDate = sanitize_text_field($body['startDate'] ?? '');
                    $endDate = sanitize_text_field($body['endDate'] ?? '');

                    // SECURITY: Validate staffUuid format
                    if (!empty($staffUuid) && !$this->validateUuid($staffUuid)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'Invalid staff UUID format',
                        ], 400);
                    }

                    if (empty($staffUuid)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'staffUuid is required',
                        ], 400);
                    }
                    if (empty($startDate) || empty($endDate)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'startDate and endDate are required',
                        ], 400);
                    }

                    $result = $this->service->scheduleJob($jobUuid, $staffUuid, $startDate, $endDate, $this->linkService);
                    return $this->respond($result);
                },
            ],
        ]);

        // Single job endpoints (MUST be registered AFTER job linking endpoints to avoid route conflict)
        register_rest_route('ca/v1', '/servicem8/jobs/(?P<uuid>[a-zA-Z0-9\-]+)', [
            [
                'methods'             => 'GET',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_view_estimates'),
                'callback'            => function (WP_REST_Request $request) {
                    $uuid = sanitize_text_field($request->get_param('uuid'));
                    
                    // SECURITY: Validate UUID format
                    if (!$this->validateUuid($uuid)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'Invalid job UUID format',
                        ], 400);
                    }
                    
                    $result = $this->service->getJob($uuid);
                    return $this->respond($result);
                },
            ],
            [
                'methods'             => 'DELETE',
                'permission_callback' => fn () => $this->isDevBypass() ?: $this->auth->requireCapability('ca_manage_portal'),
                'callback'            => function (WP_REST_Request $request) {
                    $uuid = sanitize_text_field($request->get_param('uuid'));
                    
                    // SECURITY: Validate UUID format
                    if (!$this->validateUuid($uuid)) {
                        return new WP_REST_Response([
                            'ok' => false,
                            'error' => 'Invalid job UUID format',
                        ], 400);
                    }
                    
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
            
            $response = [
                'ok'  => false,
                'err' => $errorMessage,
                'error' => $errorMessage, // Standardized field
                'code'=> $result->get_error_code(),
            ];
            
            // SECURITY: Only include detailed error information in debug mode
            if (defined('WP_DEBUG') && WP_DEBUG && !empty($errorDetails)) {
                $response['details'] = $errorDetails;
            }
            
            $restResponse = new WP_REST_Response($response, $status);
            $this->addSecurityHeaders($restResponse);
            return $restResponse;
        }

        if (!isset($result['ok'])) {
            $result['ok'] = true;
        }

        $response = new WP_REST_Response($result, 200);
        $this->addSecurityHeaders($response);
        return $response;
    }

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

    private function isDevBypass(): bool
    {
        return defined('WP_DEBUG') && WP_DEBUG && isset($_SERVER['HTTP_X_CA_DEV']) && $_SERVER['HTTP_X_CA_DEV'] === '1';
    }
}

