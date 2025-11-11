<?php

namespace CheapAlarms\Plugin\Frontend;

use function add_query_arg;
use function add_rewrite_rule;
use function esc_html__;
use function get_query_var;
use function get_stylesheet_directory;
use function get_stylesheet_directory_uri;
use function get_user_meta;
use function home_url;
use function is_user_logged_in;
use function sanitize_text_field;
use function status_header;
use function file_exists;
use function file_get_contents;
use function json_decode;
use function wp_login_url;
use function wp_die;
use function wp_safe_redirect;
use function wp_unslash;

class PortalPage
{
    private const QUERY_VAR = 'cheapalarms_portal';

    private static array $viewData = [];

    private ?array $manifest = null;
    private string $assetBase = '';

    public static function getViewData(): array
    {
        return self::$viewData;
    }

    public static function activate(): void
    {
        add_rewrite_rule('^portal/?$', 'index.php?' . self::QUERY_VAR . '=1', 'top');
    }

    public function __construct()
    {
        add_action('init', [$this, 'registerRewrite']);
        add_filter('query_vars', [$this, 'registerQueryVar']);
        add_filter('template_include', [$this, 'maybeInterceptTemplate']);
        add_filter('login_redirect', [$this, 'redirectAfterLogin'], 10, 3);
        add_filter('woocommerce_login_redirect', [$this, 'redirectAfterWooLogin'], 999, 2);
        add_filter('woocommerce_customer_login_redirect', [$this, 'redirectAfterWooLogin'], 999, 2);
    }

    public function registerRewrite(): void
    {
        add_rewrite_rule('^portal/?$', 'index.php?' . self::QUERY_VAR . '=1', 'top');
    }

    public function registerQueryVar(array $vars): array
    {
        if (!in_array(self::QUERY_VAR, $vars, true)) {
            $vars[] = self::QUERY_VAR;
        }
        return $vars;
    }

    public function maybeInterceptTemplate(string $template): string
    {
        if (!get_query_var(self::QUERY_VAR)) {
            return $template;
        }

        $queryArgs = $this->collectQueryArgs();
        if (!is_user_logged_in()) {
            $redirect = add_query_arg($queryArgs, home_url('/portal/'));
            wp_safe_redirect(wp_login_url($redirect));
            exit;
        }

        $viewData = $this->prepareViewData();
        if (!$viewData) {
            return $template;
        }

        self::$viewData = $viewData;
        status_header(200);
        return CA_PLUGIN_PATH . 'views/portal-app.php';
    }

    public function redirectAfterLogin($redirectTo, $requestedRedirect, $user)
    {
        if (!($user instanceof \WP_User)) {
            return $redirectTo;
        }

        $roles = (array) $user->roles;
        if (!in_array('customer', $roles, true)) {
            return $redirectTo;
        }

        $portalRedirect = $this->buildPortalRedirectFromUser($user);
        return $portalRedirect ?: home_url('/portal/');
    }

    public function redirectAfterWooLogin($redirect, $user)
    {
        if (!($user instanceof \WP_User)) {
            return $redirect;
        }

        $roles = (array) $user->roles;
        if (!in_array('customer', $roles, true)) {
            return $redirect;
        }

        $portalRedirect = $this->buildPortalRedirectFromUser($user);
        return $portalRedirect ?: $redirect;
    }

    private function prepareViewData(): ?array
    {
        $entry = $this->getManifestEntry();
        if (!$entry) {
            wp_die(
                esc_html__('CheapAlarms portal assets are missing. Build the React app and deploy assets to the theme `react-app` directory.', 'cheapalarms'),
                esc_html__('Portal unavailable', 'cheapalarms'),
                ['response' => 500]
            );
            return null;
        }

        $estimateId = isset($_GET['estimateId']) ? sanitize_text_field(wp_unslash($_GET['estimateId'])) : '';
        $locationId = isset($_GET['locationId']) ? sanitize_text_field(wp_unslash($_GET['locationId'])) : '';
        $inviteToken = isset($_GET['inviteToken']) ? sanitize_text_field(wp_unslash($_GET['inviteToken'])) : '';

        $config = [
            'estimateId' => $estimateId,
            'locationId' => $locationId,
            'inviteToken' => $inviteToken,
            'apiBase'    => home_url(),
        ];

        return [
            'assetBase'    => $this->assetBase,
            'mainJs'       => $entry['file'],
            'mainCss'      => $entry['css'][0] ?? null,
            'portalConfig' => $config,
        ];
    }

    private function getManifestEntry(): ?array
    {
        $manifest = $this->loadManifest();
        if (!$manifest) {
            return null;
        }

        return $manifest['src/main.jsx'] ?? null;
    }

    private function loadManifest(): ?array
    {
        if ($this->manifest !== null) {
            return $this->manifest;
        }

        $themeDir = get_stylesheet_directory();
        $reactDir = $themeDir . '/react-app';
        $manifestPath = $reactDir . '/.vite/manifest.json';

        if (!file_exists($manifestPath)) {
            return $this->manifest = null;
        }

        $decoded = json_decode(file_get_contents($manifestPath), true);
        if (!is_array($decoded)) {
            return $this->manifest = null;
        }

        $this->assetBase = get_stylesheet_directory_uri() . '/react-app';
        $this->manifest = $decoded;

        return $this->manifest;
    }

    private function collectQueryArgs(): array
    {
        $args = [];
        foreach (['estimateId', 'locationId', 'inviteToken'] as $key) {
            if (isset($_GET[$key])) {
                $args[$key] = sanitize_text_field(wp_unslash($_GET[$key]));
            }
        }
        return $args;
    }

    private function buildPortalRedirectFromUser(\WP_User $user): string
    {
        $estimateId = get_user_meta($user->ID, 'ca_estimate_id', true);
        $args       = [];
        $locations  = get_user_meta($user->ID, 'ca_estimate_locations', true);
        $locationId = null;
        if (is_array($locations) && $estimateId && isset($locations[$estimateId])) {
            $locationId = $locations[$estimateId];
        }
        if ($estimateId) {
            $args['estimateId'] = $estimateId;
        }
        if ($locationId) {
            $args['locationId'] = $locationId;
        }
        $redirect = home_url('/portal/');
        if (!empty($args)) {
            $redirect = add_query_arg(array_filter($args), $redirect);
        }
        return $redirect;
    }
}

