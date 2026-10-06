<?php
declare(strict_types=1);

require_once __DIR__ . '/auth.php';
analyzerRequireLogin();
header('Content-Type: application/json; charset=utf-8');

$root = dirname(__DIR__) . '/antibot';
$log = is_readable($root . '/logs/antibot.log') ? $root . '/logs/antibot.log' : $root . '/antibot.log';
$type = (string)($_GET['type'] ?? '');
$value = trim((string)($_GET['value'] ?? ''));

if (!in_array($type, ['ip', 'fingerprint'], true) || $value === '') {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'Некорректные параметры'], JSON_UNESCAPED_UNICODE);
    exit;
}

if (!is_readable($log)) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'Лог AntiBot не найден или недоступен для чтения'], JSON_UNESCAPED_UNICODE);
    exit;
}

/*
 * Keep only the last HISTORY_LIMIT matching events while scanning the whole log.
 * This avoids returning the oldest 250 events from a growing production log.
 */
const HISTORY_LIMIT = 250;
$events = [];
$ips = [];
$urls = [];
$sessions = [];
$fh = fopen($log, 'rb');

if ($fh === false) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'Не удалось открыть лог'], JSON_UNESCAPED_UNICODE);
    exit;
}

while (($line = fgets($fh)) !== false) {
    if (!preg_match('/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s*(.*)$/u', rtrim($line, "\r\n"), $m)) {
        continue;
    }

    $msg = trim($m[4]);
    $match = false;

    if ($type === 'ip') {
        $match = $m[3] === $value;
    } else {
        $match = (bool)preg_match('/\bFP:\s*' . preg_quote($value, '/') . '\b/i', $msg);
    }

    if (!$match) {
        continue;
    }

    $kind = 'event';
    if ($msg !== '' && $msg[0] === '/') {
        $kind = 'request';
        $urls[$msg] = true;
    } elseif (str_starts_with($msg, 'REF:')) {
        $kind = 'referrer';
    } elseif (str_starts_with($msg, 'PTR:')) {
        $kind = 'ptr';
    } elseif (str_starts_with($msg, 'UA:')) {
        $kind = 'ua';
    } elseif (stripos($msg, 'captcha') !== false) {
        $kind = 'captcha';
    } elseif (stripos($msg, 'blocked') !== false || stripos($msg, 'blocking page') !== false) {
        $kind = 'block';
    }

    $event = [
        'time' => $m[1],
        'ray' => $m[2],
        'ip' => $m[3],
        'kind' => $kind,
        'message' => $msg,
    ];

    $sessions[$m[2]] = true;
    $ips[$m[3]] = true;

    if (count($events) >= HISTORY_LIMIT) {
        array_shift($events);
    }
    $events[] = $event;
}

fclose($fh);

/* The ring buffer above is chronological already; sort defensively in case the log is not perfectly ordered. */
usort($events, static fn(array $a, array $b): int => strcmp($a['time'], $b['time']) ?: strcmp($a['ray'], $b['ray']));

/* URLs are intentionally collected from the returned window only. */
foreach ($events as $event) {
    if ($event['kind'] === 'request') {
        $urls[$event['message']] = true;
    }
}

$urls = array_keys($urls);
sort($urls, SORT_STRING);

// Keep the response compact and deterministic.
echo json_encode([
    'ok' => true,
    'events' => $events,
    'sessions' => count($sessions),
    'ips' => array_keys($ips),
    'urls' => $urls,
    'truncated' => count($events) >= HISTORY_LIMIT,
], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
