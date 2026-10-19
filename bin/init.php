<?php
// Run by the entrypoint before Apache starts. Checks the configuration, so the server refuses to
// start with invalid settings, and prepares /data.
declare(strict_types=1);

namespace Wurd;

require __DIR__ . '/../src/Config.php';
require __DIR__ . '/../src/Http.php';
require __DIR__ . '/../src/Store.php';
require __DIR__ . '/../src/Users.php';

try {
    $config = Config::fromEnvironment();
    Config::checkTrustedProxies();
    Store::setUp();
    Users::checkPepper(Store::connect(), $config->pepper);
} catch (ConfigError $e) {
    fwrite(STDERR, "wurd: not starting. {$e->getMessage()}\n");
    exit(1);
}

// Apache's LimitRequestBody, so oversized uploads are refused before PHP sees them
echo $config->maxFileBytes, "\n";
