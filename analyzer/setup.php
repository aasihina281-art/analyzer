<?php
declare(strict_types=1);
require_once __DIR__ . '/auth.php';

$cfg = analyzerConfiguredCredentials();
$hasRealConfig = !empty($cfg['username']) && !empty($cfg['password_hash']) && $cfg['password_hash'] !== '$2y$10$REPLACE_THIS_WITH_A_REAL_PASSWORD_HASH';

if ($hasRealConfig) {
    header('Location: login.php');
    exit;
}

$error = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf = (string)($_POST['csrf'] ?? '');
    if (!isset($_SESSION['setup_csrf'])) $_SESSION['setup_csrf'] = bin2hex(random_bytes(32));
    if (!hash_equals($_SESSION['setup_csrf'], $csrf)) {
        $error = 'Сессия истекла. Обновите страницу.';
    } else {
        $username = trim((string)($_POST['username'] ?? ''));
        $password = (string)($_POST['password'] ?? '');
        $password2 = (string)($_POST['password2'] ?? '');
        if ($username === '' || strlen($username) < 3) $error = 'Логин должен содержать минимум 3 символа.';
        elseif (strlen($password) < 10) $error = 'Пароль должен содержать минимум 10 символов.';
        elseif ($password !== $password2) $error = 'Пароли не совпадают.';
        else {
            $content = "<?php\nreturn " . var_export([
                'username' => $username,
                'password_hash' => password_hash($password, PASSWORD_DEFAULT),
            ], true) . ";\n";
            $configPath = __DIR__ . '/config.php';
            if (@file_put_contents($configPath, $content, LOCK_EX) === false) {
                $error = 'Не удалось записать config.php. Проверьте права на папку analyzer.';
            } else {
                @chmod($configPath, 0600);
                header('Location: login.php?setup=1');
                exit;
            }
        }
    }
}
if (!isset($_SESSION['setup_csrf'])) $_SESSION['setup_csrf'] = bin2hex(random_bytes(32));
?>
<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AntiBot Analyzer — настройка</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#070b13;color:#edf2f7;font-family:Arial,sans-serif}
.box{width:min(440px,calc(100% - 32px));background:#101827;border:1px solid #243044;border-radius:18px;padding:28px;box-sizing:border-box}
h1{margin:0 0 8px}.muted{color:#94a3b8;font-size:13px;margin-bottom:20px}label{display:block;color:#cbd5e1;font-size:13px;margin:14px 0 6px}
input{width:100%;box-sizing:border-box;padding:12px;border-radius:9px;border:1px solid #334155;background:#0b1220;color:#fff}
button{width:100%;margin-top:18px;padding:12px;border:0;border-radius:9px;background:#2563eb;color:#fff;font-weight:700;cursor:pointer}
.err{background:#3a1418;color:#fecaca;border:1px solid #991b1b;padding:10px;border-radius:9px;font-size:13px}
.note{margin-top:14px;color:#94a3b8;font-size:12px}
</style></head><body><div class="box"><h1>🛡 Первичная настройка</h1><div class="muted">Создайте учётную запись администратора AntiBot Analyzer.</div>
<?php if($error): ?><div class="err"><?=htmlspecialchars($error,ENT_QUOTES,'UTF-8')?></div><?php endif; ?>
<form method="post"><input type="hidden" name="csrf" value="<?=htmlspecialchars($_SESSION['setup_csrf'],ENT_QUOTES,'UTF-8')?>">
<label>Логин</label><input name="username" minlength="3" autocomplete="username" required>
<label>Пароль</label><input type="password" name="password" minlength="10" autocomplete="new-password" required>
<label>Повтор пароля</label><input type="password" name="password2" minlength="10" autocomplete="new-password" required>
<button type="submit">Создать доступ</button></form>
<div class="note">После создания config.php доступ к этой странице автоматически закрывается.</div></div></body></html>