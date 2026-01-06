<?php
/**
 * Plugin Name: CheapAlarms Platform Bridge
 * Description: Hardened WordPress integration layer for CheapAlarms – exposes secure REST endpoints, admin dashboard loader, and GHL integration.
 * Version: 2.0.0
 * Author: CheapAlarms Engineering
 */

if (!defined('ABSPATH')) {
    exit;
}

define('CA_PLUGIN_PATH', rtrim(__DIR__, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR);
define('CA_PLUGIN_VERSION', '2.0.0');

require_once CA_PLUGIN_PATH . 'autoload.php';

use CheapAlarms\Plugin\Plugin;

Plugin::instance()->boot();

register_activation_hook(__FILE__, function () {
    Plugin::instance()->activate();
});

register_deactivation_hook(__FILE__, function () {
    Plugin::instance()->deactivate();
});

