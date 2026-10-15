<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/parser.php';

// Минимальная эмуляция цикла парсера для одного visitor'а с FP
$ray = '7bff79a6a4809716';
$s = (new ReflectionClass('AntiBotLogParser'))->newInstanceWithoutConstructor();
$ref = new ReflectionMethod('AntiBotLogParser', 'newSession');
$ref->setAccessible(true);
$session = $ref->invoke($s, $ray, '84.42.92.236', '2026-10-10 05:40:40');

$msg = 'FP:  15baef716b69e7da0dbe318af47f4e63';
$first = $msg[0];
echo "first char: '$first'\n";
if ($first === 'F') {
    if (preg_match('/\bFP:\s*([a-f0-9]{16,128})\b/i', $msg, $fpMatch)) {
        $fp = strtolower($fpMatch[1]);
        echo "matched fp=$fp\n";
        $session['fingerprints'][$fp] = true;
        $session['fingerprint'] = $fp;
    }
}
echo "array keys before array_keys: "; var_export(array_keys($session['fingerprints'])); echo "\n";
$session['fingerprints'] = array_keys($session['fingerprints']);
echo "after array_keys: "; var_export($session['fingerprints']); echo "\n";
