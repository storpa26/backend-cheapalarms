<?php

namespace CheapAlarms\Plugin\REST;

use CheapAlarms\Plugin\REST\Controllers\AuthController;
use CheapAlarms\Plugin\REST\Controllers\PasswordResetController;
use CheapAlarms\Plugin\REST\Controllers\EstimateController;
use CheapAlarms\Plugin\REST\Controllers\PortalController;
use CheapAlarms\Plugin\REST\Controllers\UploadController;
use CheapAlarms\Plugin\REST\Controllers\ProductsController;
use CheapAlarms\Plugin\REST\Controllers\ServiceM8Controller;
use CheapAlarms\Plugin\REST\Controllers\GhlController;
use CheapAlarms\Plugin\REST\Controllers\UsersController;
use CheapAlarms\Plugin\REST\Controllers\AdminEstimateController;
use CheapAlarms\Plugin\REST\Controllers\AdminInvoiceController;
use CheapAlarms\Plugin\REST\Controllers\QuoteRequestController;
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
            new PasswordResetController($this->container),
            new EstimateController($this->container),
            new UploadController($this->container),
            new PortalController($this->container),
            new ProductsController($this->container),
            new ServiceM8Controller($this->container),
            new GhlController($this->container),
            new UsersController($this->container),
            new AdminEstimateController($this->container),
            new AdminInvoiceController($this->container),
            new QuoteRequestController($this->container),
        ];

        foreach ($controllers as $controller) {
            $controller->register();
        }
    }
}

