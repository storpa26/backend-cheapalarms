<?php

namespace CheapAlarms\Plugin\Services;

class Logger
{
    public function debug(string $message, array $context = []): void
    {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            $this->log('DEBUG', $message, $context);
        }
    }

    public function info(string $message, array $context = []): void
    {
        $this->log('INFO', $message, $context);
    }

    public function warning(string $message, array $context = []): void
    {
        $this->log('WARNING', $message, $context);
    }

    public function error(string $message, array $context = []): void
    {
        $this->log('ERROR', $message, $context);
    }

    private function log(string $level, string $message, array $context = []): void
    {
        // SECURITY: Filter sensitive data from logs
        $context = $this->filterSensitiveData($context);
        
        $formatted = sprintf(
            '[CheapAlarms][%s] %s %s',
            $level,
            $message,
            $context ? wp_json_encode($context) : ''
        );
        error_log($formatted);
    }

    /**
     * Remove sensitive data from log context
     *
     * @param array<string, mixed> $data
     * @return array<string, mixed>
     */
    private function filterSensitiveData(array $data): array
    {
        $sensitive = ['password', 'token', 'secret', 'key', 'authorization', 'cookie', 'api_key'];
        $filtered = [];
        
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
                $filtered[$key] = '[REDACTED]';
            } elseif (is_array($value)) {
                $filtered[$key] = $this->filterSensitiveData($value);
            } else {
                $filtered[$key] = $value;
            }
        }
        
        return $filtered;
    }
}

