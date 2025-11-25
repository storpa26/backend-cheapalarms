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
     * Perform a GET request.
     *
     * @param array<string, mixed> $query
     * @param string|null $locationId Optional location ID to pass as header
     */
    public function get(string $path, array $query = [], int $timeout = 25, ?string $locationId = null)
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

        $response = wp_remote_get($url, [
            'headers' => $headers,
            'timeout' => $timeout,
        ]);

        return $this->processResponse($response, $url);
    }

    /**
     * Perform a POST request.
     *
     * @param array<string, mixed> $body
     * @param string|null $locationId Optional location ID to pass as header
     */
    public function post(string $path, array $body, int $timeout = 30, ?string $locationId = null)
    {
        $url = self::BASE_URL . $path;
        $response = wp_remote_post($url, [
            'headers' => $this->headers($locationId),
            'timeout' => $timeout,
            'body'    => wp_json_encode($body),
        ]);

        return $this->processResponse($response, $url, $body);
    }

    /**
     * Perform a PUT request.
     *
     * @param array<string, mixed> $body
     * @param string|null $locationId Optional location ID to pass as header
     */
    public function put(string $path, array $body, array $query = [], int $timeout = 30, ?string $locationId = null)
    {
        $url = self::BASE_URL . $path;
        if ($query) {
            $url .= '?' . http_build_query($query);
        }

        $response = wp_remote_request($url, [
            'method'  => 'PUT',
            'headers' => $this->headers($locationId),
            'timeout' => $timeout,
            'body'    => wp_json_encode($body),
        ]);

        return $this->processResponse($response, $url, $body);
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

