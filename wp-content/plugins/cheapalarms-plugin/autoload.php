<?php

if (!defined('ABSPATH')) {
    exit;
}

spl_autoload_register(function ($class) {
    $prefix   = 'CheapAlarms\\Plugin\\';
    $baseDir  = CA_PLUGIN_PATH . 'includes/';

    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relativeClass = substr($class, $len);
    $relativePath  = str_replace('\\', DIRECTORY_SEPARATOR, $relativeClass) . '.php';
    $file          = $baseDir . $relativePath;

    if (file_exists($file)) {
        require $file;
    }
});

