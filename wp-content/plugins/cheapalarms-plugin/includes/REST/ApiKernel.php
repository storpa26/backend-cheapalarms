<?php

namespace CheapAlarms\Plugin\REST;

use CheapAlarms\Plugin\REST\Controllers\AuthController;
use CheapAlarms\Plugin\REST\Controllers\EstimateController;
use CheapAlarms\Plugin\REST\Controllers\PortalController;
use CheapAlarms\Plugin\REST\Controllers\UploadController;
use CheapAlarms\Plugin\REST\Controllers\ProductsController;
use CheapAlarms\Plugin\Services\Container;

class ApiKernel
{
    public function __construct(private Container $container)
    {
    }

    public function register(): void
    {
        $controllers = [
            new AuthController($this->container),
            new EstimateController($this->container),
            new UploadController($this->container),
            new PortalController($this->container),
            new ProductsController($this->container),
        ];

        foreach ($controllers as $controller) {
            $controller->register();
        }
    }
}

