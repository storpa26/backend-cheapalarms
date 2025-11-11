<?php
/** @var string $themeUri */
/** @var string|null $mainCss */
/** @var string $mainJs */

?><!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
    <meta charset="<?php bloginfo('charset'); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?php esc_html_e('Estimates Dashboard - CheapAlarms', 'cheapalarms'); ?></title>
    <?php wp_head(); ?>
    <?php if ($mainCss): ?>
        <link rel="stylesheet" href="<?php echo esc_url($themeUri . '/react-app/' . $mainCss); ?>">
    <?php endif; ?>
</head>
<body class="wp-admin">
    <div id="root"></div>
    <script type="module">
        window.caAdminMode = true;
        window.caInitialRoute = '/admin/dashboard';
        import('<?php echo esc_url($themeUri . '/react-app/' . $mainJs); ?>');
    </script>
    <?php wp_footer(); ?>
</body>
</html>

