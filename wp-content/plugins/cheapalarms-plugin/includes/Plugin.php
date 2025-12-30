<?php

namespace CheapAlarms\Plugin;

use CheapAlarms\Plugin\Admin\Menu;
use CheapAlarms\Plugin\Admin\UserCapabilities;
use CheapAlarms\Plugin\Config\Config;
use CheapAlarms\Plugin\Db\Schema;
use CheapAlarms\Plugin\Frontend\PortalPage;
use CheapAlarms\Plugin\REST\ApiKernel;
use CheapAlarms\Plugin\REST\Auth\Authenticator;
use CheapAlarms\Plugin\Services\Container;
use CheapAlarms\Plugin\Services\Logger;
use CheapAlarms\Plugin\Services\ProductRepository;
use CheapAlarms\Plugin\Services\Estimate\EstimateSnapshotRepository;
use CheapAlarms\Plugin\Services\Estimate\EstimateSnapshotSyncService;

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
        
        // SECURITY: Validate configuration before proceeding
        // Instantiate Config directly since it has no dependencies and needs to be validated early
        $config = new Config();
        if (!$config->isConfigured()) {
            $missing = [];
            if (empty($config->getGhlToken())) {
                $missing[] = 'ghl_token';
            }
            if (empty($config->getLocationId())) {
                $missing[] = 'ghl_location_id';
            }
            if (empty($config->getUploadSharedSecret())) {
                $missing[] = 'upload_shared_secret';
            }
            
            $message = sprintf(
                __('CheapAlarms plugin is not configured. Missing required secrets: %s. Please configure secrets.php or set environment variables.', 'cheapalarms'),
                implode(', ', $missing)
            );
            
            if (defined('WP_DEBUG') && WP_DEBUG) {
                wp_die($message, __('Plugin Configuration Error', 'cheapalarms'), ['response' => 500]);
            } else {
                // In production, log error but don't expose details
                error_log('[CheapAlarms] Configuration error: Missing required secrets');
                wp_die(
                    __('CheapAlarms plugin is not properly configured. Please contact the administrator.', 'cheapalarms'),
                    __('Plugin Configuration Error', 'cheapalarms'),
                    ['response' => 500]
                );
            }
        }
        
        // Run schema upgrades only when needed (versioned).
        Schema::maybeMigrate();
        $this->registerRoles();
        $this->registerServices();
        $this->container->get(Authenticator::class)->boot();

        // Background sync hook for estimate snapshots (WP-Cron).
        add_action('ca_sync_estimate_snapshots', function (string $locationId) {
            $this->container->get(EstimateSnapshotSyncService::class)->syncLocation($locationId);
        }, 10, 1);

        $this->registerCors();
        $this->registerRestEndpoints();
        $this->registerFrontend();
        $this->registerAdminUi();
        $this->registerAdmin();
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
            $this->container->get(Logger::class),
            $this->container
        ));
        $this->container->set(\CheapAlarms\Plugin\Services\InvoiceService::class, fn () => new \CheapAlarms\Plugin\Services\InvoiceService(
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
            $this->container->get(\CheapAlarms\Plugin\Services\Logger::class),
            $this->container,
            $this->container->get(\CheapAlarms\Plugin\Config\Config::class)
        ));
        $this->container->set(\CheapAlarms\Plugin\Services\ServiceM8Client::class, fn () => new \CheapAlarms\Plugin\Services\ServiceM8Client(
            $this->container->get(Config::class),
            $this->container->get(Logger::class)
        ));
        $this->container->set(\CheapAlarms\Plugin\Services\ServiceM8Service::class, fn () => new \CheapAlarms\Plugin\Services\ServiceM8Service(
            $this->container->get(\CheapAlarms\Plugin\Services\ServiceM8Client::class),
            $this->container->get(Config::class),
            $this->container->get(Logger::class),
            $this->container->get(\CheapAlarms\Plugin\Services\EstimateService::class)
        ));
        $this->container->set(\CheapAlarms\Plugin\Services\CustomerService::class, fn () => new \CheapAlarms\Plugin\Services\CustomerService(
            $this->container->get(\CheapAlarms\Plugin\Services\GhlClient::class),
            $this->container->get(Logger::class),
            $this->container
        ));
        $this->container->set(\CheapAlarms\Plugin\Services\GhlSignalService::class, fn () => new \CheapAlarms\Plugin\Services\GhlSignalService(
            $this->container->get(\CheapAlarms\Plugin\Services\GhlClient::class),
            $this->container->get(Logger::class),
            $this->container->get(Config::class)
        ));
        $this->container->set(\CheapAlarms\Plugin\Services\JobLinkService::class, fn () => new \CheapAlarms\Plugin\Services\JobLinkService(
            $this->container->get(Logger::class)
        ));
        $this->container->set(\CheapAlarms\Plugin\Services\Shared\LocationResolver::class, fn () => new \CheapAlarms\Plugin\Services\Shared\LocationResolver(
            $this->container->get(Config::class)
        ));
        $this->container->set(\CheapAlarms\Plugin\Services\Shared\PortalMetaRepository::class, fn () => new \CheapAlarms\Plugin\Services\Shared\PortalMetaRepository());
        
        // Estimate sub-services
        $this->container->set(\CheapAlarms\Plugin\Services\Estimate\EstimateNormalizer::class, fn () => new \CheapAlarms\Plugin\Services\Estimate\EstimateNormalizer(
            $this->container->get(Config::class)
        ));
        $this->container->set(\CheapAlarms\Plugin\Services\Estimate\EstimatePhotoService::class, fn () => new \CheapAlarms\Plugin\Services\Estimate\EstimatePhotoService(
            $this->container->get(Config::class),
            $this->container->get(\CheapAlarms\Plugin\Services\EstimateService::class),
            $this->container->get(Logger::class)
        ));
        $this->container->set(\CheapAlarms\Plugin\Services\Estimate\EstimateInvoiceService::class, fn () => new \CheapAlarms\Plugin\Services\Estimate\EstimateInvoiceService(
            $this->container->get(Config::class),
            $this->container->get(\CheapAlarms\Plugin\Services\GhlClient::class),
            $this->container->get(Logger::class),
            $this->container->get(\CheapAlarms\Plugin\Services\Estimate\EstimateNormalizer::class)
        ));

        // Admin performance: snapshot storage for GHL estimates (avoids repeated GHL list calls).
        $this->container->set(EstimateSnapshotRepository::class, fn () => new EstimateSnapshotRepository());
        $this->container->set(EstimateSnapshotSyncService::class, fn () => new EstimateSnapshotSyncService(
            $this->container->get(\CheapAlarms\Plugin\Services\EstimateService::class),
            $this->container->get(EstimateSnapshotRepository::class),
            $this->container->get(Logger::class)
        ));
        $this->container->set(\CheapAlarms\Plugin\Services\XeroService::class, fn () => new \CheapAlarms\Plugin\Services\XeroService(
            $this->container->get(Config::class),
            $this->container->get(Logger::class)
        ));
        $this->container->set(\CheapAlarms\Plugin\Services\StripeService::class, fn () => new \CheapAlarms\Plugin\Services\StripeService(
            $this->container->get(Config::class),
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

    private function registerAdmin(): void
    {
        if (is_admin()) {
            new UserCapabilities();
        }
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
        Schema::maybeMigrate();
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

