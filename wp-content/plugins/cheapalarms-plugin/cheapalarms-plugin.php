<?php
/**
 * Plugin Name: CheapAlarms Platform Bridge
 * Description: Hardened WordPress integration layer for CheapAlarms – exposes secure REST endpoints, admin dashboard loader, and GHL integration.
 * Version: 2.0.0
 * Author: CheapAlarms Engineering
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Text Domain: cheapalarms
 * License: Proprietary
 */

if (!defined('ABSPATH')) {
    exit;
}

define('CA_PLUGIN_PATH', rtrim(__DIR__, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR);
define('CA_PLUGIN_VERSION', '2.0.0');

require_once CA_PLUGIN_PATH . 'autoload.php';

// Add Composer autoloader if vendor/ exists (for Stripe PHP library)
$composerAutoload = CA_PLUGIN_PATH . 'vendor/autoload.php';
if (file_exists($composerAutoload)) {
    require_once $composerAutoload;
}

use CheapAlarms\Plugin\Plugin;

Plugin::instance()->boot();

register_activation_hook(__FILE__, function () {
    Plugin::instance()->activate();
});

register_deactivation_hook(__FILE__, function () {
    Plugin::instance()->deactivate();
});

