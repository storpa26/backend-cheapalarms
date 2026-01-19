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
use CheapAlarms\Plugin\Services\SentryService;
use CheapAlarms\Plugin\Services\ProductRepository;
use CheapAlarms\Plugin\Middleware\RequestIdMiddleware;
use CheapAlarms\Plugin\Middleware\RateLimitHeaderMiddleware;
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
            
            // ✅ FIX: Don't call wp_die() during bootstrap - this prevents plugin upload
            // Log error but allow plugin to load (configuration can be added later)
            $missingStr = implode(', ', $missing);
            error_log('[CheapAlarms] Configuration error: Missing required secrets: ' . $missingStr);
            
            // ✅ Only block API calls, not plugin loading/activation
            // This allows plugin to be uploaded and activated even if not configured
            add_action('rest_api_init', function() use ($missingStr) {
                if (defined('WP_DEBUG') && WP_DEBUG) {
                    $message = sprintf(
                        __('CheapAlarms plugin is not configured. Missing required secrets: %s. Please configure secrets.php or set environment variables.', 'cheapalarms'),
                        $missingStr
                    );
                    wp_die($message, __('Plugin Configuration Error', 'cheapalarms'), ['response' => 500]);
                } else {
                    wp_die(
                        __('CheapAlarms plugin is not properly configured. Please contact the administrator.', 'cheapalarms'),
                        __('Plugin Configuration Error', 'cheapalarms'),
                        ['response' => 500]
                    );
                }
            }, 1); // Priority 1 to run before API endpoints register
            
            // ✅ Don't initialize services if not configured, but don't kill WordPress
            return;
        }
        
        // Initialize Sentry early (before other services)
        $this->initializeSentry();

        // Initialize request ID tracking early (before services that need it)
        $this->initializeRequestId();

        // Run schema upgrades only when needed (versioned).
        Schema::maybeMigrate();
        $this->registerRoles();
        $this->registerServices();
        $this->container->get(Authenticator::class)->boot();

        // Background sync hook for estimate snapshots (WP-Cron).
        add_action('ca_sync_estimate_snapshots', function (string $locationId) {
            $this->container->get(EstimateSnapshotSyncService::class)->syncLocation($locationId);
        }, 10, 1);

        // Retention cleanup job (daily) - permanently delete estimates soft-deleted > 30 days
        add_action('ca_cleanup_expired_deletions', function () {
            $this->container->get(\CheapAlarms\Plugin\Services\Estimate\RetentionCleanupService::class)->cleanup();
        }, 10, 0);

        // Schedule recurring retention cleanup job (if not already scheduled)
        if (!wp_next_scheduled('ca_cleanup_expired_deletions_daily')) {
            wp_schedule_event(time() + (2 * HOUR_IN_SECONDS), 'daily', 'ca_cleanup_expired_deletions_daily');
        }

        add_action('ca_cleanup_expired_deletions_daily', function () {
            wp_schedule_single_event(time() + 1, 'ca_cleanup_expired_deletions');
        });

        // Register webhook processing hooks
        add_action('ca_process_stripe_webhook', function (string $eventId) {
            $this->container->get(\CheapAlarms\Plugin\Services\StripeWebhookProcessor::class)
                ->processEvent($eventId);
        }, 10, 1);

        // Retry failed webhooks (every 5 minutes)
        add_action('ca_retry_failed_webhooks', function () {
            $this->container->get(\CheapAlarms\Plugin\Services\WebhookRetryService::class)
                ->retryPendingEvents();
        }, 10, 0);

        // Schedule retry job (every 5 minutes)
        if (!wp_next_scheduled('ca_retry_failed_webhooks_recurring')) {
            // Register custom schedule if needed
            add_filter('cron_schedules', function ($schedules) {
                if (!isset($schedules['ca_every_5_minutes'])) {
                    $schedules['ca_every_5_minutes'] = [
                        'interval' => 300, // 5 minutes
                        'display' => __('Every 5 Minutes', 'cheapalarms'),
                    ];
                }
                return $schedules;
            });
            
            wp_schedule_event(time() + 300, 'ca_every_5_minutes', 'ca_retry_failed_webhooks_recurring');
        }

        add_action('ca_retry_failed_webhooks_recurring', function () {
            wp_schedule_single_event(time() + 1, 'ca_retry_failed_webhooks');
        });

        // Register Xero sync retry handler
        add_action('ca_retry_xero_sync', function (string $estimateId, string $ghlInvoiceId, string $locationId) {
            try {
                $portalService = $this->container->get(\CheapAlarms\Plugin\Services\PortalService::class);
                // syncInvoiceToXero is now public, can call directly
                $portalService->syncInvoiceToXero($estimateId, $ghlInvoiceId, $locationId);
            } catch (\Exception $e) {
                $logger = $this->container->get(\CheapAlarms\Plugin\Services\Logger::class);
                $logger->error('Failed to execute Xero sync retry', [
                    'estimateId' => $estimateId,
                    'ghlInvoiceId' => $ghlInvoiceId,
                    'error' => $e->getMessage(),
                ]);
            }
        }, 10, 3);

        // Register payment intent expiry cleanup (daily)
        // FIXED: Capture container in closure to avoid $this context issues
        // FIXED: Add batching and better edge case handling
        $container = $this->container;
        add_action('ca_cleanup_expired_payment_intents', function () use ($container) {
            try {
                global $wpdb;
                $optionName = 'ca_portal_meta_%';
                $batchSize = 100; // Process in batches to avoid memory issues
                $offset = 0;
                $cleaned = 0;
                $currentTime = time();
                
                do {
                    // FIXED: Add LIMIT and OFFSET for batching
                    $results = $wpdb->get_results($wpdb->prepare(
                        "SELECT option_name, option_value 
                         FROM {$wpdb->options} 
                         WHERE option_name LIKE %s
                         LIMIT %d OFFSET %d",
                        $optionName,
                        $batchSize,
                        $offset
                    ), ARRAY_A);
                    
                    if (empty($results)) {
                        break;
                    }
                    
                    foreach ($results as $row) {
                        $meta = maybe_unserialize($row['option_value']);
                        if (!is_array($meta)) continue;
                        
                        $payment = $meta['payment'] ?? [];
                        $expiresAt = $payment['paymentIntentExpiresAt'] ?? null;
                        $paymentIntentId = $payment['paymentIntentId'] ?? null;
                        
                        // If payment intent expired and no successful payment recorded, clean it up
                        if ($expiresAt && $currentTime > (int)$expiresAt && !empty($paymentIntentId)) {
                            $hasSuccessfulPayment = false;
                            
                            // Check payments array for successful payments
                            if (!empty($payment['payments']) && is_array($payment['payments'])) {
                                foreach ($payment['payments'] as $p) {
                                    $paymentStatus = $p['status'] ?? '';
                                    if ($paymentStatus === 'succeeded') {
                                        $hasSuccessfulPayment = true;
                                        break;
                                    }
                                }
                            }
                            
                            // FIXED: Extract estimateId from option_name to check for active payment lock
                            // Format: ca_portal_meta_{estimateId}
                            $prefix = 'ca_portal_meta_';
                            $estimateId = str_replace($prefix, '', $row['option_name']);
                            // Safety check: verify prefix was actually removed
                            if ($estimateId === $row['option_name']) {
                                // Prefix not found, skip lock check
                                $estimateId = null;
                            }
                            
                            // FIXED: Check if payment confirmation is currently in progress via lock
                            $hasPaymentInProgress = false;
                            if ($estimateId) {
                                $paymentLockKey = 'ca_payment_lock_' . $estimateId;
                                $lockValue = get_transient($paymentLockKey);
                                if ($lockValue !== false) {
                                    // Check if lock is stale (older than 10 seconds)
                                    $lockAge = $currentTime - (int)$lockValue;
                                    if ($lockAge <= 10) {
                                        $hasPaymentInProgress = true;
                                    }
                                }
                            }
                            
                            // FIXED: Only clean up if no successful payment AND no payment in progress
                            if (!$hasSuccessfulPayment && !$hasPaymentInProgress) {
                                $meta['payment']['paymentIntentId'] = null;
                                $meta['payment']['paymentIntentExpiresAt'] = null;
                                
                                update_option($row['option_name'], $meta);
                                $cleaned++;
                            }
                        }
                    }
                    
                    $offset += $batchSize;
                } while (count($results) === $batchSize);
                
                if ($cleaned > 0) {
                    $logger = $container->get(\CheapAlarms\Plugin\Services\Logger::class);
                    $logger->info('Cleaned up expired payment intents', ['count' => $cleaned]);
                }
            } catch (\Exception $e) {
                $logger = $container->get(\CheapAlarms\Plugin\Services\Logger::class);
                $logger->error('Failed to cleanup expired payment intents', [
                    'error' => $e->getMessage(),
                ]);
            }
        }, 10, 0);

        // Schedule cleanup job (daily at 2 AM)
        if (!wp_next_scheduled('ca_cleanup_expired_payment_intents')) {
            wp_schedule_event(strtotime('tomorrow 2:00'), 'daily', 'ca_cleanup_expired_payment_intents');
        }

        $this->registerCors();
        $this->registerRestEndpoints();
        $this->registerFrontend();
        $this->registerAdminUi();
        $this->registerAdmin();
        $this->registerUserTracking();
    }

    /**
     * Register hooks for tracking user password and login status
     * Used for context-aware email personalization
     */
    private function registerUserTracking(): void
    {
        // Track when password is set (via password reset flow)
        add_action('after_password_reset', function($user, $new_password) {
            if ($user && isset($user->ID)) {
                update_user_meta($user->ID, 'ca_password_set_at', current_time('mysql'));
            }
        }, 10, 2);

        // Track when user logs in
        add_action('wp_login', function($user_login, $user) {
            if ($user && isset($user->ID)) {
                update_user_meta($user->ID, 'ca_last_login', current_time('mysql'));
                // Also set password_set_at if not already set (user logged in = has password)
                if (!get_user_meta($user->ID, 'ca_password_set_at', true)) {
                    update_user_meta($user->ID, 'ca_password_set_at', current_time('mysql'));
                }
            }
        }, 10, 2);

        // Track password set via wp_set_password action (WordPress 6.2+)
        add_action('wp_set_password', function($password, $user_id, $old_user_data) {
            if ($user_id) {
                update_user_meta($user_id, 'ca_password_set_at', current_time('mysql'));
            }
        }, 10, 3);
    }

    /**
     * Initialize Sentry error tracking early
     */
    private function initializeSentry(): void
    {
        try {
            $config = new Config();
            $sentry = new SentryService($config);
            $sentry->init();

            // Register Sentry in container
            $this->container->set(SentryService::class, fn () => $sentry);

            // Set up PHP error handler to catch fatal errors
            $this->registerPhpErrorHandler($sentry);
        } catch (\Throwable $e) {
            // Don't fail if Sentry initialization fails
            if (function_exists('error_log')) {
                error_log('[CheapAlarms] Sentry initialization failed: ' . $e->getMessage());
            }
        }
    }

    /**
     * Initialize request ID middleware
     */
    private function initializeRequestId(): void
    {
        try {
            // Get logger (create temporary instance if needed)
            $logger = $this->container->has(Logger::class) 
                ? $this->container->get(Logger::class)
                : new Logger();

            $middleware = new RequestIdMiddleware($logger);
            $middleware->init($this->container);

            // Register middleware to add request ID header to REST responses
            add_filter('rest_pre_serve_request', [$middleware, 'addRequestIdHeader'], 10, 4);
            
            // Register rate limit header middleware
            $rateLimitMiddleware = new RateLimitHeaderMiddleware();
            add_filter('rest_pre_serve_request', [$rateLimitMiddleware, 'addRateLimitHeaders'], 10, 4);
        } catch (\Throwable $e) {
            // Don't fail if request ID initialization fails
            if (function_exists('error_log')) {
                error_log('[CheapAlarms] Request ID initialization failed: ' . $e->getMessage());
            }
        }
    }

    /**
     * Register PHP error handler to catch fatal errors
     * 
     * Note: This chains with WordPress's error handler by returning false,
     * allowing WordPress to handle errors normally while also sending to Sentry
     */
    private function registerPhpErrorHandler(SentryService $sentry): void
    {
        // Store previous handler in a variable that can be used in closure
        $previousHandlerRef = [null];
        
        // Set our error handler (set_error_handler returns the previous handler)
        $previousHandlerRef[0] = set_error_handler(function (int $errno, string $errstr, string $errfile, int $errline) use ($sentry, &$previousHandlerRef): bool {
            // Only handle errors that are not suppressed with @
            if (!(error_reporting() & $errno)) {
                // Call previous handler if it exists
                if ($previousHandlerRef[0] !== null) {
                    return call_user_func($previousHandlerRef[0], $errno, $errstr, $errfile, $errline);
                }
                return false;
            }

            // Convert error to exception for Sentry (only for errors, not warnings/notices)
            if (in_array($errno, [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR, E_RECOVERABLE_ERROR], true)) {
                try {
                    $exception = new \ErrorException($errstr, 0, $errno, $errfile, $errline);
                    $sentry->captureException($exception, [
                        'error_type' => 'php_error',
                        'error_level' => $errno,
                    ]);
                } catch (\Throwable $e) {
                    // Don't break if Sentry fails
                }
            }

            // Call previous handler if it exists, otherwise return false to let PHP handle it
            if ($previousHandlerRef[0] !== null) {
                return call_user_func($previousHandlerRef[0], $errno, $errstr, $errfile, $errline);
            }
            return false;
        }, E_ALL & ~E_DEPRECATED & ~E_STRICT);

        // Register shutdown handler for fatal errors (runs after WordPress's handler)
        register_shutdown_function(function () use ($sentry): void {
            $error = error_get_last();
            if ($error !== null && in_array($error['type'], [E_ERROR, E_CORE_ERROR, E_COMPILE_ERROR, E_PARSE], true)) {
                try {
                    $exception = new \ErrorException(
                        $error['message'],
                        0,
                        $error['type'],
                        $error['file'],
                        $error['line']
                    );
                    $sentry->captureException($exception, [
                        'error_type' => 'fatal_error',
                    ]);
                } catch (\Throwable $e) {
                    // Don't break if Sentry fails
                }
            }
        });
    }

    private function registerServices(): void
    {
        $this->container->set(Config::class, fn () => new Config());
        
        // Register SentryService if not already registered
        if (!$this->container->has(SentryService::class)) {
            $this->container->set(SentryService::class, fn () => new SentryService($this->container->get(Config::class)));
        }
        
        // Logger gets SentryService if available
        $this->container->set(Logger::class, function () {
            $sentry = $this->container->has(SentryService::class) 
                ? $this->container->get(SentryService::class) 
                : null;
            return new Logger($sentry);
        });
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
        $this->container->set(\CheapAlarms\Plugin\Services\Estimate\RetentionCleanupService::class, fn () => new \CheapAlarms\Plugin\Services\Estimate\RetentionCleanupService(
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
        $this->container->set(\CheapAlarms\Plugin\Services\EmailTemplateService::class, fn () => new \CheapAlarms\Plugin\Services\EmailTemplateService(
            $this->container->get(Config::class)
        ));
        
        // Webhook services
        $this->container->set(\CheapAlarms\Plugin\Services\WebhookEventRepository::class, 
            fn () => new \CheapAlarms\Plugin\Services\WebhookEventRepository()
        );
        
        $this->container->set(\CheapAlarms\Plugin\Services\StripeWebhookProcessor::class, 
            fn (Container $c) => new \CheapAlarms\Plugin\Services\StripeWebhookProcessor(
                $c->get(\CheapAlarms\Plugin\Services\WebhookEventRepository::class),
                $c->get(\CheapAlarms\Plugin\Services\Shared\PortalMetaRepository::class),
                $c->get(Logger::class)
            )
        );
        
        $this->container->set(\CheapAlarms\Plugin\Services\WebhookRetryService::class, 
            fn (Container $c) => new \CheapAlarms\Plugin\Services\WebhookRetryService(
                $c->get(\CheapAlarms\Plugin\Services\WebhookEventRepository::class),
                $c->get(\CheapAlarms\Plugin\Services\StripeWebhookProcessor::class),
                $c->get(Logger::class)
            )
        );
    }

    private function registerRestEndpoints(): void
    {
        add_action('rest_api_init', function () {
            if (function_exists('error_log')) {
                error_log('[CheapAlarms Plugin] rest_api_init register controllers');
            }
            
            // Ensure request ID is initialized before API calls
            if ($this->container->has(Logger::class)) {
                $logger = $this->container->get(Logger::class);
                $middleware = new RequestIdMiddleware($logger);
                $middleware->init($this->container);
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
        try {
            // Check PHP version first
            if (version_compare(PHP_VERSION, '7.4.0', '<')) {
                throw new \RuntimeException(
                    sprintf(
                        'CheapAlarms plugin requires PHP 7.4 or higher. You are running PHP %s.',
                        PHP_VERSION
                    )
                );
            }

            Schema::maybeMigrate();
            $this->registerRoles();
            PortalPage::activate();
            flush_rewrite_rules();
        } catch (\Throwable $e) {
            // Log error for debugging, then re-throw to show error to user
            if (function_exists('error_log')) {
                error_log('[CheapAlarms] Activation error: ' . $e->getMessage());
                error_log('[CheapAlarms] Stack trace: ' . $e->getTraceAsString());
            }
            // Re-throw to show error to user
            throw $e;
        }
    }

    public function deactivate(): void
    {
        // Unschedule all WP-Cron jobs
        $timestamp = wp_next_scheduled('ca_cleanup_expired_deletions_daily');
        if ($timestamp) {
            wp_unschedule_event($timestamp, 'ca_cleanup_expired_deletions_daily');
        }
        
        $timestamp = wp_next_scheduled('ca_cleanup_expired_deletions');
        if ($timestamp) {
            wp_unschedule_event($timestamp, 'ca_cleanup_expired_deletions');
        }
        
        // Clear any scheduled single events (more thorough cleanup)
        wp_clear_scheduled_hook('ca_cleanup_expired_deletions_daily');
        wp_clear_scheduled_hook('ca_cleanup_expired_deletions');
        wp_clear_scheduled_hook('ca_sync_estimate_snapshots');
        
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

