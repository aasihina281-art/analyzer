<?php
/** Диагностика FP-бага: что реально лежит в $session['fingerprints'] после parseFile. */
declare(strict_types=1);
require_once __DIR__ . '/includes/parser.php';

$parsed = AntiBotLogParser::parseFile($argv[1] ?? dirname(__DIR__) . '/antibot.log');
$n = 0;
foreach ($parsed['sessions'] as $s) {
    if (!empty($s['fingerprints'])) {
        printf("rayId=%s ip=%s fingerprints=%s fingerprint='%s' clientKey=%s\n",
            implode(',', $s['rayIds'] ?? [$s['rayId']]), $s['ip'],
            json_encode($s['fingerprints']), $s['fingerprint'], $s['clientKey']);
        if (++$n >= 5) break;
    }
}
// сырая проверка на уровне RayID-групп (до merge): повторим regex парсера
$fh = fopen($argv[1] ?? dirname(__DIR__) . '/antibot.log', 'rb');
$test = ['FP:  15baef716b69e7da0dbe318af47f4e63'];
foreach ($test as $msg) {
    $ok = preg_match('/\bFP:\s*([a-f0-9]{16,128})\b/i', $msg, $mm);
    echo "regex on '$msg': match=" . var_export($ok, true) . " group=" . ($mm[1] ?? '-') . "\n";
}
