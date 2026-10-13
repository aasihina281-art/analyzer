<?php
declare(strict_types=1);
require_once __DIR__ . '/auth.php';

if (empty(analyzerConfiguredCredentials()['password_hash']) || analyzerConfiguredCredentials()['password_hash'] === '$2y$10$REPLACE_THIS_WITH_A_REAL_PASSWORD_HASH') { header('Location: setup.php'); exit; }

if (analyzerIsAuthenticated()) {
    header('Location: index.php');
    exit;
}
$error = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim((string)($_POST['username'] ?? ''));
    $password = (string)($_POST['password'] ?? '');
    $csrf = (string)($_POST['csrf'] ?? '');
    if (!isset($_SESSION['login_csrf'])) $_SESSION['login_csrf'] = bin2hex(random_bytes(32));
    if (!hash_equals($_SESSION['login_csrf'], $csrf)) $error = 'Сессия истекла. Обновите страницу.';
    elseif (analyzerLogin($username, $password)) { header('Location: index.php'); exit; }
    else { $error = 'Неверный логин или пароль.'; }
}
if (!isset($_SESSION['login_csrf'])) $_SESSION['login_csrf'] = bin2hex(random_bytes(32));
?>
<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AntiBot Analyzer — вход</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#070b13;color:#edf2f7;font-family:Arial,sans-serif}
.box{width:min(420px,calc(100% - 32px));background:#101827;border:1px solid #243044;border-radius:18px;padding:28px;box-sizing:border-box}
h1{margin:0 0 8px}.muted{color:#94a3b8;font-size:13px;margin-bottom:20px}label{display:block;color:#cbd5e1;font-size:13px;margin:14px 0 6px}
input{width:100%;box-sizing:border-box;padding:12px;border-radius:9px;border:1px solid #334155;background:#0b1220;color:#fff}
button{width:100%;margin-top:18px;padding:12px;border:0;border-radius:9px;background:#2563eb;color:#fff;font-weight:700;cursor:pointer}
.err{background:#3a1418;color:#fecaca;border:1px solid #991b1b;padding:10px;border-radius:9px;font-size:13px}
</style></head><body><div class="box"><h1>🛡 AntiBot Analyzer</h1><div class="muted">Защищённый доступ к анализатору</div>
<?php if($error): ?><div class="err"><?=htmlspecialchars($error,ENT_QUOTES,'UTF-8')?></div><?php endif; ?>
<form method="post"><input type="hidden" name="csrf" value="<?=htmlspecialchars($_SESSION['login_csrf'],ENT_QUOTES,'UTF-8')?>">
<label>Логин</label><input name="username" autocomplete="username" required>
<label>Пароль</label><input type="password" name="password" autocomplete="current-password" required>
<button type="submit">Войти</button></form></div></body></html>