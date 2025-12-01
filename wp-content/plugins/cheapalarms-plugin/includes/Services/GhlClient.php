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
    public function get(string $path, array $query = [], int $timeout = 25, ?string $locationId = null, int $maxRetries = 2)
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

            // Check if this is a transient SSL/network error that might benefit from retry
            $isTransientError = (
                strpos($errorMessage, 'SSL') !== false ||
                strpos($errorMessage, 'SSL_ERROR') !== false ||
                strpos($errorMessage, 'SSL_connect') !== false ||
                strpos($errorMessage, 'Connection timed out') !== false ||
                strpos($errorMessage, 'cURL error 35') !== false ||
                strpos($errorMessage, 'cURL error 28') !== false ||
                $errorCode === 'http_request_failed'
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
    public function post(string $path, array $body, int $timeout = 30, ?string $locationId = null, int $maxRetries = 2)
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
            $isTransientError = (
                strpos($errorMessage, 'SSL') !== false ||
                strpos($errorMessage, 'SSL_ERROR') !== false ||
                strpos($errorMessage, 'Connection timed out') !== false ||
                strpos($errorMessage, 'cURL error 35') !== false ||
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
    public function put(string $path, array $body, array $query = [], int $timeout = 30, ?string $locationId = null, int $maxRetries = 2)
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
            $isTransientError = (
                strpos($errorMessage, 'SSL') !== false ||
                strpos($errorMessage, 'SSL_ERROR') !== false ||
                strpos($errorMessage, 'Connection timed out') !== false ||
                strpos($errorMessage, 'cURL error 35') !== false ||
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

