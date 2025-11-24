<?php

namespace CheapAlarms\Plugin;

use CheapAlarms\Plugin\Admin\Menu;
use CheapAlarms\Plugin\Config\Config;
use CheapAlarms\Plugin\Frontend\PortalPage;
use CheapAlarms\Plugin\REST\ApiKernel;
use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\Logger;
use CheapAlarms\Plugin\Services\ProductRepository;

use function add_action;
use function add_filter;
use function add_role;
use function get_role;
use function header;
use function in_array;
use function status_header;

class Plugin
{
    private static ?Plugin $instance = null;

    private Container $container;

    /**
     * @var array<string, array{label:string, capabilities:array<string,bool>}>
     */
    private const ROLE_DEFINITIONS = [
        'ca_superadmin' => [
            'label'        => 'CheapAlarms Superadmin',
            'capabilities' => [
                'read'                => true,
                'ca_manage_portal'    => true,
                'ca_manage_support'   => true,
                'ca_view_estimates'   => true,
                'ca_invite_customers' => true,
                'ca_access_portal'    => true,
            ],
        ],
        'ca_admin' => [
            'label'        => 'CheapAlarms Admin',
            'capabilities' => [
                'read'                => true,
                'ca_manage_portal'    => true,
                'ca_manage_support'   => true,
                'ca_view_estimates'   => true,
                'ca_invite_customers' => true,
                'ca_access_portal'    => true,
            ],
        ],
        'ca_moderator' => [
            'label'        => 'CheapAlarms Moderator',
            'capabilities' => [
                'read'              => true,
                'ca_view_estimates' => true,
                'ca_access_portal'  => true,
            ],
        ],
        'ca_support' => [
            'label'        => 'CheapAlarms Support',
            'capabilities' => [
                'read'                => true,
                'ca_manage_support'   => true,
                'ca_access_portal'    => true,
            ],
        ],
        'ca_customer' => [
            'label'        => 'CheapAlarms Customer',
            'capabilities' => [
                'read'             => true,
                'ca_access_portal' => true,
            ],
        ],
    ];

    private const ADMIN_GRANTED_CAPS = [
        'ca_manage_portal',
        'ca_manage_support',
        'ca_view_estimates',
        'ca_invite_customers',
        'ca_access_portal',
    ];

    private function __construct()
    {
        $this->container = new Container();
    }

    public static function instance(): Plugin
    {
        if (!self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function boot(): void
    {
        add_action('init', [$this, 'bootstrap']);
    }

    public function bootstrap(): void
    {
        if (function_exists('error_log')) {
            error_log('[CheapAlarms Plugin] bootstrap executing');
        }
        $this->registerRoles();
        $this->registerServices();
        $this->container->get(Authenticator::class)->boot();
        $this->registerCors();
        $this->registerRestEndpoints();
        $this->registerFrontend();
        $this->registerAdminUi();
    }

    private function registerServices(): void
    {
        $this->container->set(Config::class, fn () => new Config());
        $this->container->set(Logger::class, fn () => new Logger());
        $this->container->set(Authenticator::class, fn () => new Authenticator($this->container->get(Config::class)));
        $this->container->set(ProductRepository::class, fn () => new ProductRepository());
        $this->container->set(\CheapAlarms\Plugin\Services\GhlClient::class, fn () => new \CheapAlarms\Plugin\Services\GhlClient(
            $this->container->get(Config::class),
            $this->container->get(Logger::class)
        ));
        $this->container->set(\CheapAlarms\Plugin\Services\EstimateService::class, fn () => new \CheapAlarms\Plugin\Services\EstimateService(
            $this->container->get(Config::class),
            $this->container->get(\CheapAlarms\Plugin\Services\GhlClient::class),
            $this->container->get(Logger::class)
        ));
        $this->container->set(\CheapAlarms\Plugin\Services\UploadService::class, fn () => new \CheapAlarms\Plugin\Services\UploadService(
            $this->container->get(Config::class),
            $this->container->get(\CheapAlarms\Plugin\Services\EstimateService::class),
            $this->container->get(Logger::class)
        ));
        $this->container->set(\CheapAlarms\Plugin\Services\PortalService::class, fn () => new \CheapAlarms\Plugin\Services\PortalService(
            $this->container->get(\CheapAlarms\Plugin\Services\EstimateService::class),
            $this->container->get(Logger::class)
        ));
        $this->container->set(\CheapAlarms\Plugin\Services\ServiceM8Client::class, fn () => new \CheapAlarms\Plugin\Services\ServiceM8Client(
            $this->container->get(Config::class),
            $this->container->get(Logger::class)
        ));
        $this->container->set(\CheapAlarms\Plugin\Services\ServiceM8Service::class, fn () => new \CheapAlarms\Plugin\Services\ServiceM8Service(
            $this->container->get(\CheapAlarms\Plugin\Services\ServiceM8Client::class),
            $this->container->get(Config::class),
            $this->container->get(Logger::class)
        ));
        $this->container->set(\CheapAlarms\Plugin\Services\CustomerService::class, fn () => new \CheapAlarms\Plugin\Services\CustomerService(
            $this->container->get(\CheapAlarms\Plugin\Services\GhlClient::class),
            $this->container->get(Logger::class)
        ));
    }

    private function registerRestEndpoints(): void
    {
        add_action('rest_api_init', function () {
            if (function_exists('error_log')) {
                error_log('[CheapAlarms Plugin] rest_api_init register controllers');
            }
            $kernel = new ApiKernel($this->container);
            $kernel->register();
        });
    }

    private function registerCors(): void
    {
        add_action('rest_api_init', function () {
            add_filter('rest_pre_serve_request', [$this, 'sendCorsHeaders'], 0, 4);
        });

        add_action('init', function () {
            if (isset($_SERVER['REQUEST_METHOD']) && strtoupper((string) $_SERVER['REQUEST_METHOD']) === 'OPTIONS') {
                $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
                if ($origin && $this->isOriginAllowed($origin)) {
                    $this->applyCorsHeaders($origin);
                    status_header(204);
                    exit;
                }
            }
        });
    }

    /**
     * @param mixed $served
     * @param mixed $result
     * @param mixed $request
     * @param mixed $server
     */
    public function sendCorsHeaders($served, $result, $request, $server)
    {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        if ($origin && $this->isOriginAllowed($origin)) {
            $this->applyCorsHeaders($origin);
        }

        return $served;
    }

    private function applyCorsHeaders(string $origin): void
    {
        header('Access-Control-Allow-Origin: ' . $origin);
        header('Access-Control-Allow-Credentials: true');
        header('Access-Control-Allow-Headers: Authorization, Content-Type, X-WP-Nonce');
        header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');
        header('Vary: Origin');
    }

    private function isOriginAllowed(string $origin): bool
    {
        $origins = $this->container->get(Config::class)->getApiAllowedOrigins();
        return in_array($origin, $origins, true);
    }

    private function registerAdminUi(): void
    {
        new Menu();
    }

    private function registerFrontend(): void
    {
        new PortalPage();
    }

    public function container(): Container
    {
        return $this->container;
    }

    public function activate(): void
    {
        $this->registerRoles();
        PortalPage::activate();
        flush_rewrite_rules();
    }

    private function registerRoles(): void
    {
        foreach (self::ROLE_DEFINITIONS as $roleKey => $definition) {
            $roleObject = get_role($roleKey);
            if (!$roleObject) {
                add_role($roleKey, $definition['label'], $definition['capabilities']);
                continue;
            }

            foreach ($definition['capabilities'] as $cap => $grant) {
                if ($grant) {
                    $roleObject->add_cap($cap);
                } else {
                    $roleObject->remove_cap($cap);
                }
            }
        }

        $adminRole = get_role('administrator');
        if ($adminRole) {
            foreach (self::ADMIN_GRANTED_CAPS as $cap) {
                $adminRole->add_cap($cap);
            }
        }
    }
}

