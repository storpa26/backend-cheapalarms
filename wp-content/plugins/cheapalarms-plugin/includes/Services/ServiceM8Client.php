<?php

namespace CheapAlarms\Plugin\Services;

use CheapAlarms\Plugin\Config\Config;
use WP_Error;

class ServiceM8Client
{
    private const BASE_URL = 'https://api.servicem8.com/api_1.0';

    public function __construct(
        private Config $config,
        private Logger $logger
    ) {
    }

    /**
     * Perform a GET request.
     *
     * @param string $path API endpoint path (e.g., '/company.json')
     * @param array<string, mixed> $query Query parameters
     * @param int $timeout Request timeout in seconds
     * @return array|WP_Error
     */
    public function get(string $path, array $query = [], int $timeout = 25)
    {
        $url = self::BASE_URL . $path;
        if ($query) {
            $url .= '?' . http_build_query($query);
        }

        $response = wp_remote_get($url, [
            'headers' => $this->headers(),
            'timeout' => $timeout,
        ]);

        return $this->processResponse($response, $url);
    }

    /**
     * Perform a POST request.
     *
     * @param string $path API endpoint path
     * @param array<string, mixed> $body Request body
     * @param int $timeout Request timeout in seconds
     * @return array|WP_Error
     */
    public function post(string $path, array $body, int $timeout = 30)
    {
        $url = self::BASE_URL . $path;
        $response = wp_remote_post($url, [
            'headers' => $this->headers(),
            'timeout' => $timeout,
            'body'    => wp_json_encode($body),
        ]);

        return $this->processResponse($response, $url, $body);
    }

    /**
     * Perform a PUT request.
     *
     * @param string $path API endpoint path
     * @param array<string, mixed> $body Request body
     * @param int $timeout Request timeout in seconds
     * @return array|WP_Error
     */
    public function put(string $path, array $body, int $timeout = 30)
    {
        $url = self::BASE_URL . $path;
        $response = wp_remote_request($url, [
            'method'  => 'PUT',
            'headers' => $this->headers(),
            'timeout' => $timeout,
            'body'    => wp_json_encode($body),
        ]);

        return $this->processResponse($response, $url, $body);
    }

    /**
     * Perform a DELETE request.
     *
     * @param string $path API endpoint path
     * @param int $timeout Request timeout in seconds
     * @return array|WP_Error
     */
    public function delete(string $path, int $timeout = 30)
    {
        $url = self::BASE_URL . $path;
        $response = wp_remote_request($url, [
            'method'  => 'DELETE',
            'headers' => $this->headers(),
            'timeout' => $timeout,
        ]);

        return $this->processResponse($response, $url);
    }

    /**
     * @return array<string, string>
     */
    private function headers(): array
    {
        $headers = [
            'X-API-Key'     => $this->config->getServiceM8ApiKey(),
            'Accept'        => 'application/json',
            'Content-Type'  => 'application/json',
        ];
        
        // Log header verification (debug only - remove in production or use logger level)
        // Verify X-API-Key is present (value masked for security)
        if (empty($headers['X-API-Key'])) {
            $this->logger->error('ServiceM8 API key is missing in headers');
        } else {
            $this->logger->debug('ServiceM8 request headers prepared', [
                'hasApiKey' => !empty($headers['X-API-Key']),
                'headerKeys' => array_keys($headers),
            ]);
        }
        
        return $headers;
    }

    /**
     * @param array<string, mixed>|false|WP_Error $requestBody
     */
    private function processResponse($response, string $url, array $requestBody = []): array|WP_Error
    {
        if (is_wp_error($response)) {
            $this->logger->error('ServiceM8 HTTP error', [
                'url' => $url,
                'error' => $response->get_error_message(),
            ]);
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);

        if ($code < 200 || $code >= 300) {
            $this->logger->warning('ServiceM8 non-2xx response', [
                'url' => $url,
                'code' => $code,
                'body' => $body,
                'request' => $requestBody,
            ]);
            // Log the actual request payload for debugging
            $this->logger->error('ServiceM8 request payload', [
                'url' => $url,
                'payload' => $requestBody,
            ]);
            return new WP_Error('servicem8_http_error', sprintf('ServiceM8 responded with status %d', $code), [
                'code' => $code,
                'body' => $body,
            ]);
        }

        $decoded = json_decode($body, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->logger->error('ServiceM8 invalid JSON', [
                'url' => $url,
                'body' => $body,
            ]);
            return new WP_Error('servicem8_invalid_json', 'Unable to decode ServiceM8 response.');
        }

        return $decoded;
    }
}

