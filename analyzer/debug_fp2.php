<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/parser.php';
$m = [];
var_dump(preg_match('/^(\\d{4}-\\d{2}-\\d{2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+(\\S+)\\s+(\\S+)\\s*(.*)$/u',
    '2026-10-10 05:40:40 7bff79a6a4809716 84.42.92.236 FP:  15baef716b69e7da0dbe318af47f4e63', $m));
$msg = trim($m[4]);
var_dump($msg);
$ok = preg_match('/\bFP:\s*([a-f0-9]{16,128})\b/i', $msg, $mm);
var_dump($ok, $mm);
