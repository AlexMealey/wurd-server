<?php
// The API's front controller: Apache sends every /api request here.
declare(strict_types=1);

namespace Wurd;

require __DIR__ . '/../src/Config.php';
require __DIR__ . '/../src/Http.php';
require __DIR__ . '/../src/Auth.php';
require __DIR__ . '/../src/Users.php';
require __DIR__ . '/../src/Vault.php';
require __DIR__ . '/../src/Store.php';

const FILE_ROUTE = '#^/api/files/([0-9a-f]{32})$#';

try {
    $config = Config::fromEnvironment();
    $method = Http::method();
    $path = Http::path();

    if ($method === 'OPTIONS') {
        Http::preflight($config->allowedOrigins);
    }
    Http::cors($config->allowedOrigins);

    if ($path === '/api/health') {
        $method === 'GET' || throw new HttpError(405, 'Use GET.', ['Allow' => 'GET']);
        Http::json(200, ['ok' => true]);
    }

    // Anyone who can reach the server can get a token; each one opens a new, empty vault
    if ($path === '/api/tokens') {
        $method === 'POST' || throw new HttpError(405, 'Use POST.', ['Allow' => 'POST']);
        Http::json(201, ['token' => new Users(Store::connect())->issue(Http::clientIp())]);
    }

    $isList = $path === '/api/files';
    $isFile = (bool) preg_match(FILE_ROUTE, $path, $m);
    if (!$isList && !$isFile) {
        throw new HttpError(404, 'Not found.');
    }
    $allowed = $isList ? ['GET', 'POST'] : ['GET', 'PUT', 'DELETE'];
    if (!in_array($method, $allowed, true)) {
        throw new HttpError(405, 'Use ' . implode(', ', $allowed) . '.', ['Allow' => implode(', ', $allowed)]);
    }

    $db = Store::connect();
    $user = new Auth($db)->check(Http::clientIp(), Http::header('Authorization'));
    $store = new Store($db, $config, $user);

    if ($isList) {
        if ($method === 'GET') {
            Http::json(200, $store->list());
        }
        [$name, $format] = Store::parseName(Http::header('X-File-Name'));
        $file = $store->create($name, $format, Http::contentLength($config->maxFileBytes));
        Http::json(201, $file, ['ETag' => "\"{$file['rev']}\"", 'Location' => "/api/files/{$file['id']}"]);
    }

    $id = $m[1];
    switch ($method) {
        case 'GET':
            $file = $store->get($id);
            Http::download($store->read($id), $file);
        case 'PUT':
            $rev = Http::ifMatch();
            $rename = Http::header('X-File-Name') === null ? null : Store::parseName(Http::header('X-File-Name'));
            $file = $store->update($id, $rev, $rename, Http::contentLength($config->maxFileBytes));
            Http::json(200, $file, ['ETag' => "\"{$file['rev']}\""]);
        case 'DELETE':
            $store->delete($id, Http::ifMatch());
            Http::noContent();
    }
} catch (HttpError $e) {
    Http::error($e);
} catch (ConfigError $e) {
    error_log("wurd: {$e->getMessage()}");
    Http::error(new HttpError(500, 'The server is misconfigured. Its log says why.'));
} catch (\Throwable $e) {
    error_log('wurd: ' . $e::class . ": {$e->getMessage()} at {$e->getFile()}:{$e->getLine()}");
    Http::error(new HttpError(500, 'Something went wrong on the server.'));
}
