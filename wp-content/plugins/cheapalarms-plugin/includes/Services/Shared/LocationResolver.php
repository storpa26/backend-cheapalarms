<?php

namespace CheapAlarms\Plugin\Services\Shared;

use CheapAlarms\Plugin\Config\Config;

/**
 * Resolves locationId from request or config default.
 */
class LocationResolver
{
    public function __construct(
        private Config $config
    ) {
    }

    /**
     * Resolve locationId from provided value or config default.
     *
     * @param string|null $locationId Optional locationId from request
     * @return string|null Resolved locationId or null if not configured
     */
    public function resolve(?string $locationId = null): ?string
    {
        if (!empty($locationId)) {
            return $locationId;
        }

        $default = $this->config->getLocationId();
        return !empty($default) ? $default : null;
    }

    /**
     * Resolve locationId and return it, or return WP_Error if missing.
     *
     * @param string|null $locationId Optional locationId from request
     * @return string|WP_Error
     */
    public function resolveOrError(?string $locationId = null)
    {
        $resolved = $this->resolve($locationId);
        if (!$resolved) {
            return new \WP_Error('missing_location', __('Location ID is required.', 'cheapalarms'), ['status' => 400]);
        }
        return $resolved;
    }
}

