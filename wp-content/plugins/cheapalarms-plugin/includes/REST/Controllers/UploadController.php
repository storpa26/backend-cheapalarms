<?php

namespace CheapAlarms\Plugin\REST\Controllers;

use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\UploadService;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

class UploadController implements ControllerInterface
{
    private UploadService $service;
    private Authenticator $auth;

    public function __construct(private Container $container)
    {
        $this->service = $this->container->get(UploadService::class);
        $this->auth    = $this->container->get(Authenticator::class);
    }

    public function register(): void
    {
        register_rest_route('ca/v1', '/upload/start', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->auth->ensureConfigured();
                $payload = $request->get_json_params();
                if (!is_array($payload)) {
                    $payload = json_decode($request->get_body(), true);
                }
                if (!is_array($payload)) {
                    $payload = [];
                }
                $result = $this->service->start($payload);
                return $this->respond($result);
            },
        ]);

        register_rest_route('ca/v1', '/upload', [
            'methods'             => 'POST',
            'permission_callback' => fn () => true,
            'callback'            => function (WP_REST_Request $request) {
                $this->auth->ensureConfigured();
                $result = $this->service->handle($request);
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
            return $this->errorResponse($result);
        }

        if (!isset($result['ok'])) {
            $result['ok'] = true;
        }

        $response = new WP_REST_Response($result, 200);
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
                'upload_error' => 'File upload failed. Please try again.',
                'invalid_signature' => 'Invalid request signature.',
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

