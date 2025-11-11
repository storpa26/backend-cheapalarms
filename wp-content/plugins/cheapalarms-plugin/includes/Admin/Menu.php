<?php

namespace CheapAlarms\Plugin\Admin;

if (!defined('ABSPATH')) {
    exit;
}

class Menu
{
    public function __construct()
    {
        add_action('admin_menu', [$this, 'register']);
    }

    public function register(): void
    {
        add_menu_page(
            __('CheapAlarms Estimates', 'cheapalarms'),
            __('Estimates', 'cheapalarms'),
            'manage_options',
            'cheapalarms-estimates',
            [$this, 'renderDashboard'],
            'dashicons-list-view',
            30
        );

        add_submenu_page(
            'cheapalarms-estimates',
            __('All Estimates', 'cheapalarms'),
            __('All Estimates', 'cheapalarms'),
            'manage_options',
            'cheapalarms-estimates',
            [$this, 'renderDashboard']
        );
    }

    public function renderDashboard(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.', 'cheapalarms'));
        }

        $themeDir  = get_stylesheet_directory();
        $reactDir  = $themeDir . '/react-app';
        $manifest  = $reactDir . '/.vite/manifest.json';

        if (!file_exists($manifest)) {
            wp_die(__('React app not found. Please build the app.', 'cheapalarms'));
        }

        $manifestData = json_decode(file_get_contents($manifest), true);
        $mainJs  = $manifestData['src/main.jsx']['file'] ?? null;
        $mainCss = $manifestData['src/main.jsx']['css'][0] ?? null;

        if (!$mainJs) {
            wp_die(__('React manifest is invalid. Rebuild the app.', 'cheapalarms'));
        }

        $themeUri = get_stylesheet_directory_uri();

        require CA_PLUGIN_PATH . 'views/admin-dashboard.php';
    }
}

