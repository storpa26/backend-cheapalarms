<?php

namespace CheapAlarms\Plugin\Services;

class Logger
{
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
        $formatted = sprintf(
            '[CheapAlarms][%s] %s %s',
            $level,
            $message,
            $context ? wp_json_encode($context) : ''
        );
        error_log($formatted);
    }
}

