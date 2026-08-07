<?php

define('PROJECT_ROOT', dirname(__DIR__));

spl_autoload_register(function (string $class): void {
    $prefix = 'OpsDesk\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $path = PROJECT_ROOT . '/src/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($path)) {
        require $path;
    }
});

require_once __DIR__ . '/Support/TestServer.php';
require_once __DIR__ . '/Support/HttpClient.php';
