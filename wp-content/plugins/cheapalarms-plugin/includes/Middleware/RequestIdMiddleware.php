<?php

namespace CheapAlarms\Plugin\Middleware;

use CheapAlarms\Plugin\Services\Logger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Request ID Middleware
 * 
 * Generates a unique request ID for each API request and includes it in:
 * - All log entries
 * - API responses (X-Request-ID header)
 * - Sentry context
 * - GHL API calls (for correlation)
 */
class RequestIdMiddleware
{
    private static ?string $requestId = null;
    private Logger $logger;

    public function __construct(Logger $logger)
    {
        $this->logger = $logger;
    }

    /**
     * Initialize request ID (call early in request lifecycle)
     * 
     * @param \CheapAlarms\Plugin\Services\Container|null $container Optional container for Sentry integration
     */
    public function init($container = null): void
    {
        if (self::$requestId !== null) {
            return; // Already initialized
        }

        // Check if request ID is provided in header (for correlation across services)
        $headerId = $this->getRequestIdFromHeader();
        if ($headerId) {
            self::$requestId = $headerId;
        } else {
            // Generate new UUID v4
            self::$requestId = $this->generateUuid();
        }

        // Set request ID in logger
        $this->logger->setRequestId(self::$requestId);

        // Set request ID in Sentry if available
        $this->setSentryRequestId(self::$requestId, $container);
    }

    /**
     * Get current request ID
     */
    public static function getRequestId(): ?string
    {
        return self::$requestId;
    }

    /**
     * Get request ID from X-Request-ID header
     */
    private function getRequestIdFromHeader(): ?string
    {
        // Check various header formats
        $headers = [
            'HTTP_X_REQUEST_ID',
            'HTTP_X_CORRELATION_ID',
            'X-Request-ID',
            'X-Correlation-ID',
        ];

        foreach ($headers as $header) {
            $value = $_SERVER[$header] ?? null;
            if ($value && is_string($value) && !empty(trim($value))) {
                // Validate it looks like a UUID v4 or valid ID
                $trimmed = trim($value);
                // UUID v4 format: 8-4-4-4-12 hex digits with version 4 and variant bits
                if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $trimmed)) {
                    return $trimmed;
                }
                // Fallback: accept any 8+ character alphanumeric ID (for correlation IDs)
                if (preg_match('/^[a-z0-9\-_]{8,}$/i', $trimmed)) {
                    return $trimmed;
                }
            }
        }

        return null;
    }

    /**
     * Generate UUID v4 using cryptographically secure random_bytes()
     */
    private function generateUuid(): string
    {
        // Try to use PHP's built-in function first (PHP 7.2+, requires PECL uuid extension)
        if (function_exists('uuid_create')) {
            return uuid_create(UUID_TYPE_RANDOM);
        }

        // Use cryptographically secure random_bytes() for UUID v4 generation
        try {
            $data = random_bytes(16);
            // Set version (4) and variant bits according to RFC 4122
            $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // Version 4
            $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // Variant bits (10)
            
            return sprintf(
                '%08s-%04s-%04s-%04s-%12s',
                bin2hex(substr($data, 0, 4)),
                bin2hex(substr($data, 4, 2)),
                bin2hex(substr($data, 6, 2)),
                bin2hex(substr($data, 8, 2)),
                bin2hex(substr($data, 10, 6))
            );
        } catch (\Exception $e) {
            // Fallback to less secure method only if random_bytes fails
            // This should rarely happen, but provides backward compatibility
            return sprintf(
                '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
                mt_rand(0, 0xffff),
                mt_rand(0, 0xffff),
                mt_rand(0, 0xffff),
                mt_rand(0, 0x0fff) | 0x4000, // Version 4
                mt_rand(0, 0x3fff) | 0x8000, // Variant bits
                mt_rand(0, 0xffff),
                mt_rand(0, 0xffff),
                mt_rand(0, 0xffff)
            );
        }
    }

    /**
     * Set request ID in Sentry context
     * 
     * @param \CheapAlarms\Plugin\Services\Container|null $container
     */
    public function setSentryRequestId(string $requestId, $container = null): void
    {
        // Check if SentryService is available
        if (!class_exists('\CheapAlarms\Plugin\Services\SentryService')) {
            return;
        }

        if (!$container) {
            return;
        }

        try {
            // Try to get SentryService from container (if available)
            if ($container->has(\CheapAlarms\Plugin\Services\SentryService::class)) {
                $sentry = $container->get(\CheapAlarms\Plugin\Services\SentryService::class);
                if (method_exists($sentry, 'setRequestId')) {
                    $sentry->setRequestId($requestId);
                }
            }
        } catch (\Throwable $e) {
            // Silently fail - don't break request if Sentry fails
        }
    }

    /**
     * Add request ID to REST API response headers
     * 
     * This should be called as a filter on rest_pre_serve_request
     */
    public function addRequestIdHeader($served, $result, $request, $server)
    {
        if (!self::$requestId) {
            return $served;
        }

        // Use WordPress REST API header method if available
        if ($result instanceof \WP_REST_Response) {
            $result->header('X-Request-ID', self::$requestId);
        } else {
            // Fallback for non-REST responses
            header('X-Request-ID: ' . self::$requestId);
        }
        
        return $served;
    }
}

