<?php

namespace CheapAlarms\Plugin\Services;

class Logger
{
    private ?SentryService $sentry = null;
    private ?string $requestId = null;

    public function __construct(?SentryService $sentry = null)
    {
        $this->sentry = $sentry;
    }

    /**
     * Set request ID for correlation tracking
     */
    public function setRequestId(string $requestId): void
    {
        $this->requestId = $requestId;
        if ($this->sentry) {
            $this->sentry->setRequestId($requestId);
        }
    }

    public function debug(string $message, array $context = [], array $options = []): void
    {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            $this->log('DEBUG', $message, $context, $options);
        }
    }

    public function info(string $message, array $context = [], array $options = []): void
    {
        $this->log('INFO', $message, $context, $options);
    }

    public function warning(string $message, array $context = [], array $options = []): void
    {
        $this->log('WARNING', $message, $context, $options);
    }

    public function error(string $message, array $context = [], array $options = []): void
    {
        $this->log('ERROR', $message, $context, $options);
    }

    /**
     * Log an exception to Sentry and error_log
     */
    public function exception(\Throwable $exception, array $context = []): void
    {
        // Always log to error_log as fallback
        $formatted = sprintf(
            '[CheapAlarms][EXCEPTION] %s: %s in %s:%d',
            get_class($exception),
            $exception->getMessage(),
            $exception->getFile(),
            $exception->getLine()
        );
        error_log($formatted);

        // Send to Sentry if available
        if ($this->sentry) {
            $sentryContext = $context;
            if ($this->requestId) {
                $sentryContext['request_id'] = $this->requestId;
            }
            $this->sentry->captureException($exception, $sentryContext);
        }
    }

    private function log(string $level, string $message, array $context = [], array $options = []): void
    {
        // Get whitelist from options (fields explicitly allowed)
        $allowedFields = $options['allowFields'] ?? [];
        
        // SECURITY: Redact all fields by default, only allow whitelisted fields
        $context = $this->redactPii($context, $allowedFields);
        
        // Build structured log entry
        $logEntry = [
            'timestamp' => gmdate('c'), // ISO 8601 format
            'level' => strtolower($level),
            'message' => $message,
            'context' => $context,
        ];
        
        // Add request ID if available
        if ($this->requestId) {
            $logEntry['request_id'] = $this->requestId;
        }
        
        // Add user ID if available
        $userId = get_current_user_id();
        if ($userId > 0) {
            $logEntry['user_id'] = $userId;
        }
        
        // Convert to JSON
        $jsonLog = wp_json_encode($logEntry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        
        // Always write to error_log as fallback (both JSON and plain text for compatibility)
        error_log($jsonLog);
        
        // Also write plain text format for backward compatibility
        $plainText = sprintf(
            '[CheapAlarms][%s] %s',
            $level,
            $message
        );
        if (!empty($context)) {
            $plainText .= ' ' . wp_json_encode($context);
        }
        error_log($plainText);

        // Send errors and warnings to Sentry
        if ($this->sentry && in_array($level, ['ERROR', 'WARNING'], true)) {
            $this->sentry->captureMessage($message, strtolower($level), $context);
        }
    }

    /**
     * Redact PII using whitelist approach
     * 
     * Default behavior: Redact ALL fields by default (safer than blacklist)
     * Only fields explicitly whitelisted will be logged
     * 
     * @param array<string, mixed> $data
     * @param array<string> $allowedFields Fields explicitly allowed (whitelist)
     * @return array<string, mixed>
     */
    private function redactPii(array $data, array $allowedFields = []): array
    {
        // Common safe fields that are always allowed (non-PII)
        $alwaysAllowed = [
            'user_id',
            'estimate_id',
            'invoice_id',
            'status',
            'code',
            'type',
            'action',
            'endpoint',
            'method',
            'request_id',
            'timestamp',
            'duration',
            'count',
            'total',
            'limit',
            'offset',
            'page',
        ];
        
        // Merge always allowed with explicitly allowed
        $whitelist = array_merge($alwaysAllowed, $allowedFields);
        // Normalize to lowercase for case-insensitive comparison
        $whitelistLower = array_map('strtolower', $whitelist);
        
        $redacted = [];
        
        foreach ($data as $key => $value) {
            $keyLower = strtolower($key);
            
            // Use exact match first, then check if key starts with whitelisted term
            // This prevents false positives like "user_id_old" matching "user_id"
            $isAllowed = in_array($keyLower, $whitelistLower, true);
            
            if (!$isAllowed) {
                // Check if key starts with a whitelisted term (for nested keys like "user_id_meta")
                // Only allow if it's a prefix match with underscore separator
                foreach ($whitelistLower as $allowed) {
                    if ($keyLower === $allowed || str_starts_with($keyLower, $allowed . '_')) {
                        $isAllowed = true;
                        break;
                    }
                }
            }
            
            if ($isAllowed) {
                // Field is whitelisted - log it
                if (is_array($value)) {
                    $redacted[$key] = $this->redactPii($value, $allowedFields);
                } else {
                    $redacted[$key] = $value;
                }
            } else {
                // Field is NOT whitelisted - redact it
                $redacted[$key] = '[REDACTED]';
            }
        }
        
        return $redacted;
    }
}

