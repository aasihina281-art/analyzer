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

const HISTORY_LIMIT = 250;

function parseLogLine(string $line): ?array {
    if (!preg_match('/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s*(.*)$/u', rtrim($line, "\r\n"), $m)) {
        return null;
    }
    return ['time'=>$m[1], 'ray'=>$m[2], 'ip'=>$m[3], 'message'=>trim($m[4])];
}

function eventKind(string $msg): string {
    if ($msg !== '' && $msg[0] === '/') return 'request';
    if (str_starts_with($msg, 'REF:')) return 'referrer';
    if (str_starts_with($msg, 'PTR:')) return 'ptr';
    if (str_starts_with($msg, 'UA:')) return 'ua';
    if (stripos($msg, 'captcha') !== false) return 'captcha';
    if (stripos($msg, 'blocked') !== false || stripos($msg, 'blocking page') !== false) return 'block';
    return 'event';
}

function pushLatest(array &$events, array $event): void {
    if (count($events) >= HISTORY_LIMIT) array_shift($events);
    $events[] = $event;
}

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

if ($type === 'ip') {
    // Fast path: only lines belonging to the requested IP are relevant.
    while (($line = fgets($fh)) !== false) {
        $row = parseLogLine($line);
        if ($row === null || $row['ip'] !== $value) continue;

        $sessions[$row['ray']] = true;
        $kind = eventKind($row['message']);
        if ($kind === 'request') $urls[$row['message']] = true;
        $row['kind'] = $kind;
        pushLatest($events, $row);
    }
} else {
    /*
     * Fingerprint history must contain the whole RayID/session, not only the
     * single "FP: ..." line. First collect every RayID where this fingerprint
     * appears, then return all events belonging to those sessions.
     */
    $matchingRays = [];
    while (($line = fgets($fh)) !== false) {
        $row = parseLogLine($line);
        if ($row === null) continue;
        if (preg_match('/\bFP:\s*' . preg_quote($value, '/') . '\b/i', $row['message'])) {
            $matchingRays[$row['ray']] = true;
        }
    }
    fclose($fh);

    if ($matchingRays) {
        $fh = fopen($log, 'rb');
        if ($fh !== false) {
            while (($line = fgets($fh)) !== false) {
                $row = parseLogLine($line);
                if ($row === null || !isset($matchingRays[$row['ray']])) continue;

                $sessions[$row['ray']] = true;
                $ips[$row['ip']] = true;
                $kind = eventKind($row['message']);
                if ($kind === 'request') $urls[$row['message']] = true;
                $row['kind'] = $kind;
                pushLatest($events, $row);
            }
            fclose($fh);
        }
    }
}

if (is_resource($fh)) fclose($fh);

usort($events, static fn(array $a, array $b): int => strcmp($a['time'], $b['time']) ?: strcmp($a['ray'], $b['ray']));

foreach ($events as $event) {
    $ips[$event['ip']] = true;
    $sessions[$event['ray']] = true;
    if ($event['kind'] === 'request') $urls[$event['message']] = true;
}

$urls = array_keys($urls);
sort($urls, SORT_STRING);

$ipList = array_keys($ips);
sort($ipList, SORT_STRING);

echo json_encode([
    'ok' => true,
    'events' => $events,
    'sessions' => count($sessions),
    'ips' => $ipList,
    'urls' => $urls,
    'truncated' => count($events) >= HISTORY_LIMIT,
], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
