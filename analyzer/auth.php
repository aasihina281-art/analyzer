<?php
declare(strict_types=1);

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

const ANALYZER_SESSION_KEY = 'antibot_analyzer_authenticated';

function analyzerConfiguredCredentials(): array {
    $configFile = __DIR__ . '/config.php';
    if (is_file($configFile)) {
        $cfg = require $configFile;
        if (is_array($cfg)) return $cfg;
    }
    return [];
}

function analyzerIsAuthenticated(): bool {
    return !empty($_SESSION[ANALYZER_SESSION_KEY]);
}

function analyzerRequireLogin(): void {
    if (!analyzerIsAuthenticated()) {
        header('Location: login.php');
        exit;
    }
}

function analyzerLogin(string $username, string $password): bool {
    $cfg = analyzerConfiguredCredentials();
    $expectedUser = (string)($cfg['username'] ?? '');
    $hash = (string)($cfg['password_hash'] ?? '');
    if ($expectedUser === '' || $hash === '') return false;
    if (!hash_equals($expectedUser, $username)) return false;
    if (!password_verify($password, $hash)) return false;
    session_regenerate_id(true);
    $_SESSION[ANALYZER_SESSION_KEY] = true;
    $_SESSION['antibot_analyzer_user'] = $expectedUser;
    $_SESSION['antibot_analyzer_login_at'] = time();
    return true;
}

function analyzerLogout(): void {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time()-42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    session_destroy();
}
