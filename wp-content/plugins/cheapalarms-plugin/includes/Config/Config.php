<?php

namespace CheapAlarms\Plugin\Config;

use function wp_salt;

class Config
{
    private array $defaults = [
        'ghl_token'              => '',
        'ghl_location_id'        => '',
        'upload_shared_secret'   => '',
        'upload_max_mb'          => 10,
        'upload_allowed_origins' => [],
        'api_allowed_origins'    => [],
        'jwt_secret'             => '',
        'jwt_ttl_seconds'        => 3600,
    ];

    private array $overrides = [];

    public function __construct()
    {
        $secretsFile = CA_PLUGIN_PATH . 'config/secrets.php';
        if (file_exists($secretsFile)) {
            $data = include $secretsFile;
            if (is_array($data)) {
                $this->overrides = $data;
            }
        }
    }

    public function getGhlToken(): string
    {
        return $this->fromOverrides('ghl_token') ?: $this->getEnv('CA_GHL_TOKEN', $this->defaults['ghl_token']);
    }

    public function getLocationId(): string
    {
        return $this->fromOverrides('ghl_location_id') ?: $this->getEnv('CA_LOCATION_ID', $this->defaults['ghl_location_id']);
    }

    public function getUploadSharedSecret(): string
    {
        return $this->fromOverrides('upload_shared_secret') ?: $this->getEnv('CA_UPLOAD_SHARED_SECRET', $this->defaults['upload_shared_secret']);
    }

    public function getUploadMaxBytes(): int
    {
        $value = $this->fromOverrides('upload_max_mb');
        if ($value !== null) {
            $mb = (int) $value;
        } else {
            $mb = (int) $this->getEnv('CA_UPLOAD_MAX_MB', $this->defaults['upload_max_mb']);
        }
        return $mb * 1024 * 1024;
    }

    /**
     * @return string[]
     */
    public function getAllowedOrigins(): array
    {
        $override = $this->fromOverrides('upload_allowed_origins');
        if (is_array($override) && !empty($override)) {
            return $override;
        }

        $value = $this->getEnv('CA_UPLOAD_ALLOWED_ORIGINS', '');
        if (is_array($value)) {
            return $value;
        }
        if (is_string($value) && $value !== '') {
            return array_map('trim', explode(',', $value));
        }
        return [site_url()];
    }

    /**
     * @return string[]
     */
    public function getApiAllowedOrigins(): array
    {
        $override = $this->fromOverrides('api_allowed_origins');
        if (is_array($override) && !empty($override)) {
            return $override;
        }

        $value = $this->getEnv('CA_API_ALLOWED_ORIGINS', '');
        if (is_array($value)) {
            return $value;
        }
        if (is_string($value) && $value !== '') {
            return array_map('trim', explode(',', $value));
        }
        return [site_url()];
    }

    public function getJwtSecret(): string
    {
        $override = $this->fromOverrides('jwt_secret');
        if (is_string($override) && $override !== '') {
            return $override;
        }

        $env = (string) $this->getEnv('CA_JWT_SECRET', '');
        if ($env !== '') {
            return $env;
        }

        if (defined('AUTH_KEY') && AUTH_KEY !== '') {
            return AUTH_KEY;
        }

        if (defined('SECURE_AUTH_KEY') && SECURE_AUTH_KEY !== '') {
            return SECURE_AUTH_KEY;
        }

        return hash('sha256', wp_salt('auth'));
    }

    public function getJwtTtlSeconds(): int
    {
        $override = $this->fromOverrides('jwt_ttl_seconds');
        if ($override !== null) {
            return max(60, (int) $override);
        }

        $env = (int) $this->getEnv('CA_JWT_TTL_SECONDS', $this->defaults['jwt_ttl_seconds']);
        return max(60, $env);
    }

    /**
     * @return string[]
     */
    public function getUploadAllowedOrigins(): array
    {
        return $this->getAllowedOrigins();
    }

    public function isConfigured(): bool
    {
        return $this->getGhlToken() !== '' && $this->getLocationId() !== '' && $this->getUploadSharedSecret() !== '';
    }

    private function getEnv(string $key, $default = '')
    {
        if (defined($key)) {
            return constant($key);
        }

        $mapped = getenv($key);
        if ($mapped !== false) {
            return $mapped;
        }

        return $default;
    }

    private function fromOverrides(string $key)
    {
        return $this->overrides[$key] ?? null;
    }
}

