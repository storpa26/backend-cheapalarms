<?php

namespace CheapAlarms\Plugin\Config;

use function sanitize_text_field;
use function wp_salt;

class Config
{
    private array $defaults = [
        'ghl_token'              => '',
        'ghl_location_id'        => '',
        'servicem8_api_key'      => '',
        'upload_shared_secret'   => '',
        'upload_max_mb'          => 10,
        'upload_allowed_origins' => [],
        'api_allowed_origins'    => [],
        'jwt_secret'             => '',
        'jwt_ttl_seconds'        => 3600,
        'xero_client_id'         => '',
        'xero_client_secret'     => '',
        'xero_redirect_uri'      => '',
        'xero_sales_account_code' => '200',
        'xero_bank_account_code' => '090',
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

    public function getServiceM8ApiKey(): string
    {
        return $this->fromOverrides('servicem8_api_key') ?: $this->getEnv('CA_SERVICEM8_API_KEY', $this->defaults['servicem8_api_key']);
    }

    public function getFrontendUrl(): string
    {
        return $this->fromOverrides('frontend_url') ?: $this->getEnv('CA_FRONTEND_URL', 'https://headless-cheapalarms.vercel.app');
    }

    public function isConfigured(): bool
    {
        return $this->getGhlToken() !== '' && $this->getLocationId() !== '' && $this->getUploadSharedSecret() !== '';
    }

    public function getUserId(): ?string
    {
        // Check secrets.php first, then environment variable, then WordPress option
        $secrets = $this->fromOverrides('ghl_user_id');
        if ($secrets !== null && $secrets !== '') {
            return sanitize_text_field($secrets);
        }
        
        if (defined('CA_GHL_USER_ID') && CA_GHL_USER_ID) {
            return sanitize_text_field(CA_GHL_USER_ID);
        }
        
        $option = get_option('ca_ghl_user_id', null);
        if ($option) {
            return sanitize_text_field($option);
        }
        
        return null;
    }

    public function getXeroClientId(): string
    {
        return $this->fromOverrides('xero_client_id') ?: $this->getEnv('CA_XERO_CLIENT_ID', $this->defaults['xero_client_id']);
    }

    public function getXeroClientSecret(): string
    {
        return $this->fromOverrides('xero_client_secret') ?: $this->getEnv('CA_XERO_CLIENT_SECRET', $this->defaults['xero_client_secret']);
    }

    public function getXeroRedirectUri(): string
    {
        return $this->fromOverrides('xero_redirect_uri') ?: $this->getEnv('CA_XERO_REDIRECT_URI', $this->defaults['xero_redirect_uri']);
    }

    public function getXeroSalesAccountCode(): string
    {
        return $this->fromOverrides('xero_sales_account_code') ?: $this->getEnv('CA_XERO_SALES_ACCOUNT_CODE', $this->defaults['xero_sales_account_code']);
    }

    public function getXeroBankAccountCode(): string
    {
        return $this->fromOverrides('xero_bank_account_code') ?: $this->getEnv('CA_XERO_BANK_ACCOUNT_CODE', $this->defaults['xero_bank_account_code']);
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

