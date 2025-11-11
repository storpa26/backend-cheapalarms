<?php

use CheapAlarms\Plugin\Frontend\PortalPage;

if (!defined('ABSPATH')) {
    exit;
}

$viewData = PortalPage::getViewData();
$assetBase = $viewData['assetBase'] ?? '';
$mainJs = $viewData['mainJs'] ?? '';
$mainCss = $viewData['mainCss'] ?? null;
$portalConfig = $viewData['portalConfig'] ?? [];

?><!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
    <meta charset="<?php bloginfo('charset'); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?php esc_html_e('CheapAlarms Portal', 'cheapalarms'); ?></title>
    <?php wp_head(); ?>
    <?php if ($mainCss) : ?>
        <link rel="stylesheet" href="<?php echo esc_url($assetBase . '/' . $mainCss); ?>">
    <?php endif; ?>
</head>
<body class="cheapalarms-portal">
    <div id="root" class="cheap-alarms-app"></div>
    <script>
        window.wpApiSettings = window.wpApiSettings || {};
        window.wpApiSettings.nonce = '<?php echo esc_js(wp_create_nonce('wp_rest')); ?>';
    </script>
    <script type="module">
        window.caPortalMode = true;
        window.caPortalConfig = <?php echo wp_json_encode($portalConfig); ?>;
        if (window.caPortalConfig?.estimateId) {
            window.caEstimateId = window.caPortalConfig.estimateId;
        }
        if (window.caPortalConfig?.locationId) {
            window.caLocationId = window.caPortalConfig.locationId;
        }
        if (window.caPortalConfig?.apiBase) {
            window.CA_API_BASE_URL = window.caPortalConfig.apiBase;
        }
        if (window.caPortalConfig?.inviteToken) {
            window.caPortalInviteToken = window.caPortalConfig.inviteToken;
        }
        import('<?php echo esc_url($assetBase . '/' . $mainJs); ?>');
    </script>
    <?php wp_footer(); ?>
</body>
</html>

