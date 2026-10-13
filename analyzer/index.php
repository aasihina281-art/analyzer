<?php
declare(strict_types=1);

require_once __DIR__ . '/auth.php';
analyzerRequireLogin();

try {
    require __DIR__ . '/antibot-analyzer-v2-wrapper.php';
} catch (Throwable $e) {
    http_response_code(500);
    ?>
    <!doctype html>
    <html lang="ru">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>AntiBot Analyzer — ошибка</title>
        <style>
            body{margin:0;background:#070b13;color:#edf2f7;font-family:Arial,sans-serif}
            .box{max-width:900px;margin:8vh auto;padding:28px;background:#101827;border:1px solid #3b4558;border-radius:16px}
            h1{color:#f87171}
            pre{white-space:pre-wrap;background:#080d16;padding:15px;border-radius:10px;overflow:auto;color:#fecaca}
            a{color:#93c5fd}
        </style>
    </head>
    <body><div class="box">
        <h1>AntiBot Analyzer: ошибка запуска</h1>
        <p>Авторизация прошла, но PHP не смог запустить анализатор.</p>
        <pre><?= htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') ?></pre>
        <p>Файл: <b><?= htmlspecialchars($e->getFile(), ENT_QUOTES, 'UTF-8') ?></b><br>
        Строка: <b><?= (int)$e->getLine() ?></b></p>
        <p><a href="logout.php">Выйти</a></p>
    </div></body>
    </html>
    <?php
}
