<?php

namespace CheapAlarms\Plugin\Services;

use CheapAlarms\Plugin\Config\Config;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Sentry service wrapper for error tracking
 * 
 * Note: This requires the Sentry PHP SDK to be installed via Composer:
 * composer require sentry/sentry
 */
class SentryService
{
    private bool $initialized = false;
    private ?string $dsn = null;

    public function __construct(private Config $config)
    {
        $this->dsn = $this->getDsn();
    }

    /**
     * Initialize Sentry if DSN is configured
     */
    public function init(): void
    {
        if ($this->initialized) {
            return;
        }

        if (empty($this->dsn)) {
            return; // Sentry not configured
        }

        // Check if Sentry SDK is available
        if (!class_exists('\Sentry\SentrySdk')) {
            // Log warning but don't fail - Sentry is optional
            if (function_exists('error_log')) {
                error_log('[CheapAlarms] Sentry SDK not found. Install via: composer require sentry/sentry');
            }
            return;
        }

        try {
            \Sentry\init([
                'dsn' => $this->dsn,
                'environment' => $this->getEnvironment(),
                'traces_sample_rate' => $this->getTracesSampleRate(),
                'before_send' => function (\Sentry\Event $event): ?\Sentry\Event {
                    return $this->filterSensitiveData($event);
                },
            ]);

            $this->initialized = true;
        } catch (\Throwable $e) {
            // Don't fail if Sentry initialization fails
            if (function_exists('error_log')) {
                error_log('[CheapAlarms] Sentry initialization failed: ' . $e->getMessage());
            }
        }
    }

    /**
     * Capture an exception
     */
    public function captureException(\Throwable $exception, ?array $context = null): void
    {
        if (!$this->initialized || !class_exists('\Sentry\SentrySdk')) {
            return;
        }

        try {
            // Use withScope to avoid overwriting global scope
            \Sentry\withScope(function (\Sentry\State\Scope $scope) use ($exception, $context): void {
                if ($context) {
                    foreach ($context as $key => $value) {
                        $scope->setContext($key, $value);
                    }
                }
                \Sentry\captureException($exception);
            });
        } catch (\Throwable $e) {
            // Silently fail - don't break application if Sentry fails
        }
    }

    /**
     * Capture a message
     */
    public function captureMessage(string $message, string $level = 'error', ?array $context = null): void
    {
        if (!$this->initialized || !class_exists('\Sentry\SentrySdk')) {
            return;
        }

        try {
            $sentryLevel = $this->mapLogLevel($level);

            // Use withScope to avoid overwriting global scope
            \Sentry\withScope(function (\Sentry\State\Scope $scope) use ($message, $sentryLevel, $context): void {
                if ($context) {
                    foreach ($context as $key => $value) {
                        $scope->setContext($key, $value);
                    }
                }
                \Sentry\captureMessage($message, $sentryLevel);
            });
        } catch (\Throwable $e) {
            // Silently fail - don't break application if Sentry fails
        }
    }

    /**
     * Set user context
     */
    public function setUser(?int $userId, ?string $email = null, ?array $metadata = null): void
    {
        if (!$this->initialized || !class_exists('\Sentry\SentrySdk')) {
            return;
        }

        try {
            \Sentry\configureScope(function (\Sentry\State\Scope $scope) use ($userId, $email, $metadata): void {
                $scope->setUser([
                    'id' => $userId,
                    'email' => $email,
                ] + ($metadata ?? []));
            });
        } catch (\Throwable $e) {
            // Silently fail
        }
    }

    /**
     * Set request ID context
     */
    public function setRequestId(string $requestId): void
    {
        if (!$this->initialized || !class_exists('\Sentry\SentrySdk')) {
            return;
        }

        try {
            \Sentry\configureScope(function (\Sentry\State\Scope $scope) use ($requestId): void {
                $scope->setTag('request_id', $requestId);
                $scope->setContext('request', ['id' => $requestId]);
            });
        } catch (\Throwable $e) {
            // Silently fail
        }
    }

    /**
     * Get Sentry DSN from config
     */
    private function getDsn(): ?string
    {
        // Check environment variable first
        $dsn = getenv('CA_SENTRY_DSN');
        if ($dsn !== false && !empty($dsn)) {
            return $dsn;
        }

        // Check wp-config.php constant
        if (defined('CA_SENTRY_DSN') && !empty(CA_SENTRY_DSN)) {
            return CA_SENTRY_DSN;
        }

        return null;
    }

    /**
     * Get environment name
     */
    private function getEnvironment(): string
    {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            return 'development';
        }

        $env = getenv('CA_ENVIRONMENT');
        if ($env !== false) {
            return $env;
        }

        if (defined('CA_ENVIRONMENT')) {
            return CA_ENVIRONMENT;
        }

        return 'production';
    }

    /**
     * Get traces sample rate (0.0 to 1.0)
     */
    private function getTracesSampleRate(): float
    {
        $rate = getenv('CA_SENTRY_TRACES_SAMPLE_RATE');
        if ($rate !== false) {
            $floatRate = (float) $rate;
            if ($floatRate >= 0.0 && $floatRate <= 1.0) {
                return $floatRate;
            }
        }

        if (defined('CA_SENTRY_TRACES_SAMPLE_RATE')) {
            $floatRate = (float) CA_SENTRY_TRACES_SAMPLE_RATE;
            if ($floatRate >= 0.0 && $floatRate <= 1.0) {
                return $floatRate;
            }
        }

        // Default: 10% in production, 100% in development
        return (defined('WP_DEBUG') && WP_DEBUG) ? 1.0 : 0.1;
    }

    /**
     * Filter sensitive data from Sentry events
     */
    private function filterSensitiveData(\Sentry\Event $event): ?\Sentry\Event
    {
        // Remove sensitive data from request data
        if ($event->getRequest()) {
            $request = $event->getRequest();
            $data = $request->getData();

            if (is_array($data)) {
                $data = $this->redactSensitiveFields($data);
                $request->setData($data);
            }
        }

        // Remove sensitive data from extra context
        $extra = $event->getExtra();
        if (!empty($extra)) {
            $extra = $this->redactSensitiveFields($extra);
            $event->setExtra($extra);
        }

        return $event;
    }

    /**
     * Redact sensitive fields from array
     * 
     * @param array<string, mixed> $data
     * @return array<string, mixed>
     */
    private function redactSensitiveFields(array $data): array
    {
        $sensitive = ['password', 'token', 'secret', 'key', 'authorization', 'cookie', 'api_key', 'email', 'phone'];
        $redacted = [];

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
                $redacted[$key] = '[REDACTED]';
            } elseif (is_array($value)) {
                $redacted[$key] = $this->redactSensitiveFields($value);
            } else {
                $redacted[$key] = $value;
            }
        }

        return $redacted;
    }

    /**
     * Map log level to Sentry level
     */
    private function mapLogLevel(string $level): \Sentry\Severity
    {
        return match (strtolower($level)) {
            'debug' => \Sentry\Severity::debug(),
            'info' => \Sentry\Severity::info(),
            'warning' => \Sentry\Severity::warning(),
            'error' => \Sentry\Severity::error(),
            default => \Sentry\Severity::error(),
        };
    }
}

