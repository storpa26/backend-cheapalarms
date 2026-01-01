<?php

namespace CheapAlarms\Plugin\Services;

use CheapAlarms\Plugin\Config\Config;
use WP_Error;

class GhlClient
{
    private const BASE_URL = 'https://services.leadconnectorhq.com';
    private const API_VERSION = '2021-07-28';

    public function __construct(
        private Config $config,
        private Logger $logger
    ) {
    }

    /**
     * Perform a GET request with retry logic for transient errors.
     *
     * @param array<string, mixed> $query
     * @param string|null $locationId Optional location ID to pass as header
     * @param int $maxRetries Maximum number of retry attempts for transient errors
     */
    public function get(string $path, array $query = [], int $timeout = 10, ?string $locationId = null, int $maxRetries = 1)
    {
        $url = self::BASE_URL . $path;
        if ($query) {
            $url .= '?' . http_build_query($query);
        }

        $headers = $this->headers($locationId);
        
        // Debug logging in development
        if (defined('WP_DEBUG') && WP_DEBUG) {
            $this->logger->info('GHL API Request', [
                'url' => $url,
                'headers' => array_keys($headers), // Log header names only (not values for security)
                'hasLocationIdHeader' => isset($headers['LocationId']),
            ]);
        }

        $attempt = 0;
        $lastError = null;

        while ($attempt <= $maxRetries) {
            $response = wp_remote_get($url, [
                'headers' => $headers,
                'timeout' => $timeout,
                'sslverify' => true, // Keep SSL verification enabled for security
                'redirection' => 5,
            ]);

            // If successful or non-transient error, return immediately
            if (!is_wp_error($response)) {
                return $this->processResponse($response, $url);
            }

            $errorCode = $response->get_error_code();
            $errorMessage = $response->get_error_message();

            // Check if this is a transient network error that might benefit from retry
            // Note: SSL errors are NOT retried - they're usually persistent network/configuration issues
            $isTransientError = (
                strpos($errorMessage, 'Connection timed out') !== false ||
                strpos($errorMessage, 'cURL error 28') !== false ||
                ($errorCode === 'http_request_failed' && strpos($errorMessage, 'SSL') === false)
            );

            $lastError = $response;

            // If not a transient error or max retries reached, return error
            if (!$isTransientError || $attempt >= $maxRetries) {
                break;
            }

            // Wait before retry (exponential backoff: 1s, 2s)
            $waitTime = pow(2, $attempt) * 1000000; // microseconds
            usleep($waitTime);
            $attempt++;

            $this->logger->warning('GHL API retry attempt', [
                'url' => $url,
                'attempt' => $attempt,
                'error' => $errorMessage,
            ]);
        }

        // All retries failed - return user-friendly error
        return $this->handleSslError($lastError, $url);
    }

    /**
     * Perform a POST request with retry logic for transient errors.
     *
     * @param array<string, mixed> $body
     * @param string|null $locationId Optional location ID to pass as header
     * @param int $maxRetries Maximum number of retry attempts for transient errors
     */
    public function post(string $path, array $body, int $timeout = 10, ?string $locationId = null, int $maxRetries = 1)
    {
        $url = self::BASE_URL . $path;
        $attempt = 0;
        $lastError = null;

        while ($attempt <= $maxRetries) {
            $response = wp_remote_post($url, [
                'headers' => $this->headers($locationId),
                'timeout' => $timeout,
                'body'    => wp_json_encode($body),
                'sslverify' => true,
                'redirection' => 5,
            ]);

            if (!is_wp_error($response)) {
                return $this->processResponse($response, $url, $body);
            }

            $errorMessage = $response->get_error_message();
            // Note: SSL errors are NOT retried - they're usually persistent network/configuration issues
            $isTransientError = (
                strpos($errorMessage, 'Connection timed out') !== false ||
                strpos($errorMessage, 'cURL error 28') !== false
            );

            $lastError = $response;

            if (!$isTransientError || $attempt >= $maxRetries) {
                break;
            }

            usleep(pow(2, $attempt) * 1000000);
            $attempt++;
        }

        return $this->handleSslError($lastError, $url);
    }

    /**
     * Perform a PUT request with retry logic for transient errors.
     *
     * @param array<string, mixed> $body
     * @param string|null $locationId Optional location ID to pass as header
     * @param int $maxRetries Maximum number of retry attempts for transient errors
     */
    public function put(string $path, array $body, array $query = [], int $timeout = 10, ?string $locationId = null, int $maxRetries = 1)
    {
        $url = self::BASE_URL . $path;
        if ($query) {
            $url .= '?' . http_build_query($query);
        }

        $attempt = 0;
        $lastError = null;

        while ($attempt <= $maxRetries) {
            $response = wp_remote_request($url, [
                'method'  => 'PUT',
                'headers' => $this->headers($locationId),
                'timeout' => $timeout,
                'body'    => wp_json_encode($body),
                'sslverify' => true,
                'redirection' => 5,
            ]);

            if (!is_wp_error($response)) {
                return $this->processResponse($response, $url, $body);
            }

            $errorMessage = $response->get_error_message();
            // Note: SSL errors are NOT retried - they're usually persistent network/configuration issues
            $isTransientError = (
                strpos($errorMessage, 'Connection timed out') !== false ||
                strpos($errorMessage, 'cURL error 28') !== false
            );

            $lastError = $response;

            if (!$isTransientError || $attempt >= $maxRetries) {
                break;
            }

            usleep(pow(2, $attempt) * 1000000);
            $attempt++;
        }

        return $this->handleSslError($lastError, $url);
    }

    /**
     * Perform a DELETE request.
     * Returns success for 200-299 and 404 (already deleted = idempotent success).
     *
     * @param string $path API path (e.g. '/contacts/{id}' or '/invoices/estimate/{id}')
     * @param array<string, mixed> $query Optional query parameters
     * @param string|null $locationId Optional location ID to pass as header
     * @param int $timeout Request timeout in seconds
     * @param int $maxRetries Maximum number of retry attempts for transient errors
     * @return array|WP_Error Response data or WP_Error
     */
    public function delete(string $path, array $query = [], ?string $locationId = null, int $timeout = 10, int $maxRetries = 1)
    {
        $url = self::BASE_URL . $path;
        if ($query) {
            $url .= '?' . http_build_query($query);
        }

        $headers = $this->headers($locationId);

        // Some GHL DELETE endpoints validate altId/altType from the request body (not querystring).
        // If present in $query, also include them in JSON body.
        $deleteBody = [];
        if (isset($query['altId'])) {
            $deleteBody['altId'] = (string)$query['altId'];
        }
        if (isset($query['altType'])) {
            $deleteBody['altType'] = (string)$query['altType'];
        }
        
        // Debug logging in development
        if (defined('WP_DEBUG') && WP_DEBUG) {
            $this->logger->info('GHL API DELETE Request', [
                'url' => $url,
                'headers' => array_keys($headers),
                'hasLocationIdHeader' => isset($headers['LocationId']),
                'hasBodyAlt' => !empty($deleteBody),
            ]);
        }

        $attempt = 0;
        $lastError = null;

        while ($attempt <= $maxRetries) {
            $requestArgs = [
                'method'  => 'DELETE',
                'headers' => $headers,
                'timeout' => $timeout,
                'sslverify' => true,
                'redirection' => 5,
            ];

            if (!empty($deleteBody)) {
                $requestArgs['body'] = wp_json_encode($deleteBody);
            }

            $response = wp_remote_request($url, $requestArgs);

            if (!is_wp_error($response)) {
                return $this->processDeleteResponse($response, $url);
            }

            $errorMessage = $response->get_error_message();
            // Note: SSL errors are NOT retried - they're usually persistent network/configuration issues
            $isTransientError = (
                strpos($errorMessage, 'Connection timed out') !== false ||
                strpos($errorMessage, 'cURL error 28') !== false ||
                ($response->get_error_code() === 'http_request_failed' && strpos($errorMessage, 'SSL') === false)
            );

            $lastError = $response;

            if (!$isTransientError || $attempt >= $maxRetries) {
                break;
            }

            usleep(pow(2, $attempt) * 1000000);
            $attempt++;
        }

        return $this->handleSslError($lastError, $url);
    }

    /**
     * Process DELETE response - treats 404 as success (idempotent: already deleted).
     *
     * @param array $response WordPress HTTP response
     * @param string $url Request URL for logging
     * @return array|WP_Error
     */
    private function processDeleteResponse($response, string $url): array|WP_Error
    {
        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);

        // 404 = already deleted (idempotent success)
        if ($code === 404) {
            $this->logger->info('GHL DELETE: Resource already deleted (404)', [
                'url' => $url,
                'code' => $code,
            ]);
            return ['ok' => true, 'alreadyDeleted' => true];
        }

        // 200-299 = success
        if ($code >= 200 && $code < 300) {
            $decoded = json_decode($body, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                // Empty body is fine for DELETE
                if (empty($body)) {
                    return ['ok' => true, 'alreadyDeleted' => false];
                }
                $this->logger->warning('GHL DELETE: Invalid JSON response', [
                    'url' => $url,
                    'body' => $body,
                ]);
                // Still treat as success if HTTP code was 2xx
                return ['ok' => true, 'alreadyDeleted' => false];
            }
            return array_merge(['ok' => true, 'alreadyDeleted' => false], is_array($decoded) ? $decoded : []);
        }

        // Other status codes = error
        $this->logger->warning('GHL DELETE: Non-2xx/404 response', [
            'url' => $url,
            'code' => $code,
            'body' => $body,
        ]);
        return new WP_Error('ghl_http_error', sprintf('GHL DELETE responded with status %d', $code), [
            'code' => $code,
            'body' => $body,
        ]);
    }

    /**
     * @return array<string, string>
     */
    private function headers(?string $locationId = null): array
    {
        $headers = [
            'Authorization' => 'Bearer ' . $this->config->getGhlToken(),
            'Accept'        => 'application/json',
            'Content-Type'  => 'application/json',
            'Version'       => self::API_VERSION,
        ];

        // Add LocationId header if provided
        if ($locationId !== null && $locationId !== '') {
            $headers['LocationId'] = $locationId;
        }

        return $headers;
    }

    /**
     * Handle SSL/connection errors with user-friendly messages.
     */
    private function handleSslError(WP_Error $error, string $url): WP_Error
    {
        $errorMessage = $error->get_error_message();
        $errorCode = $error->get_error_code();

        $this->logger->error('GHL SSL/Connection error', [
            'url' => $url,
            'error_code' => $errorCode,
            'error_message' => $errorMessage,
        ]);

        // Provide user-friendly error messages
        if (strpos($errorMessage, 'SSL') !== false || strpos($errorMessage, 'SSL_ERROR') !== false) {
            return new WP_Error(
                'ghl_ssl_error',
                'Unable to connect to GoHighLevel API due to SSL certificate issue. Please check your server\'s SSL configuration or contact your hosting provider.',
                [
                    'original_error' => $errorMessage,
                    'error_code' => $errorCode,
                    'help' => 'This is usually caused by: 1) Outdated SSL certificates on your server, 2) Firewall blocking the connection, 3) Network connectivity issues. Contact your hosting provider for assistance.',
                ]
            );
        }

        if (strpos($errorMessage, 'Connection timed out') !== false || strpos($errorMessage, 'cURL error 28') !== false) {
            return new WP_Error(
                'ghl_timeout',
                'Connection to GoHighLevel API timed out. The service may be temporarily unavailable. Please try again in a few moments.',
                [
                    'original_error' => $errorMessage,
                    'error_code' => $errorCode,
                ]
            );
        }

        // Generic connection error
        return new WP_Error(
            'ghl_connection_error',
            'Unable to connect to GoHighLevel API. Please check your internet connection and try again.',
            [
                'original_error' => $errorMessage,
                'error_code' => $errorCode,
            ]
        );
    }

    /**
     * @param array<string, mixed>|false $requestBody
     */
    private function processResponse($response, string $url, array $requestBody = []): array|WP_Error
    {
        if (is_wp_error($response)) {
            $this->logger->error('GHL HTTP error', [
                'url' => $url,
                'error' => $response->get_error_message(),
            ]);
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);

        if ($code < 200 || $code >= 300) {
            $this->logger->warning('GHL non-2xx response', [
                'url' => $url,
                'code' => $code,
                'body' => $body,
                'request' => $requestBody,
            ]);
            return new WP_Error('ghl_http_error', sprintf('GHL responded with status %d', $code), [
                'code' => $code,
                'body' => $body,
            ]);
        }

        $decoded = json_decode($body, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->logger->error('GHL invalid JSON', [
                'url' => $url,
                'body' => $body,
            ]);
            return new WP_Error('ghl_invalid_json', 'Unable to decode GHL response.');
        }

        return $decoded;
    }
}

