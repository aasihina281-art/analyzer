<?php
/**
 * AntiBot Analyzer — Simple Action View
 *
 * Показывает только то, что нужно оператору:
 * 1. Уже заблокированы
 * 2. Рекомендуется заблокировать
 * 3. CAPTCHA ожидает прохождения
 * 4. CAPTCHA пройдена
 * 5. Индексирующие боты
 *
 * ВАЖНО:
 * - Файлы upstream AntiBot не изменяются.
 * - Analyzer работает только с antibot.log.
 * - "CAPTCHA не пройдена" означает отсутствие записи успешного
 *   прохождения в логе. Это не доказывает, что пользователь ответил
 *   неправильно: он мог закрыть страницу.
 */

declare(strict_types=1);

require_once __DIR__ . '/auth.php';
analyzerRequireLogin();

/**
 * Real blocking actions.
 *
 * Security:
 * - If analyzer runs inside WordPress, only users with manage_options can act.
 * - Otherwise actions require ANTIBOT_ANALYZER_ACTION_KEY to be defined in a
 *   local config/bootstrap before this file. Do NOT expose this analyzer publicly
 *   without authentication.
 */
function analyzerActionAuthorized(): bool {
    return analyzerIsAuthenticated();
}



$actionMessage = null;
// Analyzer lives in /analyzer, while AntiBot itself lives in /antibot.
$antiBotRoot = dirname(__DIR__) . '/antibot';

$logCandidates = [
    $antiBotRoot . '/logs/antibot.log',
    $antiBotRoot . '/antibot.log',
];

$logFile = null;
foreach ($logCandidates as $candidate) {
    if (is_file($candidate) && is_readable($candidate)) {
        $logFile = $candidate;
        break;
    }
}

if ($logFile === null) {
    http_response_code(500);
    ?>
    <!doctype html>
    <html lang="ru"><head>
        <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>AntiBot Analyzer — лог не найден</title>
        <style>
            body{margin:0;background:#0b1120;color:#e5e7eb;font-family:Arial,sans-serif}
            .box{max-width:760px;margin:10vh auto;padding:28px;background:#111827;border:1px solid #374151;border-radius:16px}
            code{display:block;margin:12px 0;padding:12px;background:#030712;border-radius:8px;overflow:auto;color:#93c5fd}
            h1{color:#f87171}
        </style>
    </head><body><div class="box">
        <h1>Лог AntiBot не найден</h1>
        <p>Analyzer ищет <b>antibot.log</b> в следующих местах:</p>
        <?php foreach ($logCandidates as $candidate): ?><code><?= htmlspecialchars($candidate, ENT_QUOTES, 'UTF-8') ?></code><?php endforeach; ?>
    </div></body></html>
    <?php
    exit;
}

$actionMessage = $_SESSION['antibot_analyzer_flash']['message'] ?? null;
$actionError = !empty($_SESSION['antibot_analyzer_flash']['error']);
unset($_SESSION['antibot_analyzer_flash']);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['analyzer_action'])) {
    $csrf = (string)($_POST['csrf'] ?? '');

    if (!hash_equals(analyzerActionToken(), $csrf)) {
        $actionMessage = 'Сессия безопасности истекла. Обновите страницу.';
        $actionError = true;
    } elseif (!analyzerActionAuthorized()) {
        $actionMessage = 'Действие запрещено: анализатор должен быть защищён авторизацией. Для WordPress нужен manage_options, для standalone задайте ANTIBOT_ANALYZER_ACTION_KEY.';
        $actionError = true;
    } else {
        $action = (string)$_POST['analyzer_action'];
        $ip = trim((string)($_POST['ip'] ?? ''));
        $fp = trim((string)($_POST['fingerprint'] ?? ''));

        $result = analyzerPerformBlock($logFile ?? '', $action, $ip, $fp);
        $actionMessage = $result['message'] ?? 'Готово.';
        $actionError = empty($result['ok']);

        if (!empty($result['results'])) {
            $parts = [];
            foreach ($result['results'] as $item) {
                $parts[] = $item['target'] . ': ' . ($item['added'] ? 'добавлен' : 'уже заблокирован');
            }
            $actionMessage .= ' ' . implode(' · ', $parts);
        }
    }
}




function analyzerActionToken(): string {
    if (empty($_SESSION['antibot_analyzer_csrf'])) {
        $_SESSION['antibot_analyzer_csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['antibot_analyzer_csrf'];
}

function analyzerValidateIP(string $ip): bool {
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

function analyzerValidateFingerprint(string $fp): bool {
    // AntiBot fingerprints are hexadecimal hashes. Keep this strict so the
    // analyzer can never be used to write arbitrary lines into the list.
    return (bool)preg_match('/^[a-f0-9]{16,128}$/i', $fp);
}

function analyzerListCandidates(string $logFile, string $listName): array {
    $candidates = [];

    $logDir = dirname($logFile);
    if (basename($logDir) === 'logs') {
        $root = dirname($logDir);
    } else {
        $root = $logDir;
    }

    // AntiBot is installed in /antibot, so its lists are always under
    // /antibot/lists/.
    $candidates[] = dirname(__DIR__) . '/antibot/lists/' . $listName;

    // Fallbacks for non-standard deployments.
    $candidates[] = $root . '/lists/' . $listName;
    $candidates[] = __DIR__ . '/../antibot/lists/' . $listName;

    return array_values(array_unique($candidates));
}

function analyzerFindOrCreateList(string $logFile, string $listName): ?string {
    $candidates = analyzerListCandidates($logFile, $listName);

    foreach ($candidates as $path) {
        if (is_file($path) && is_readable($path) && is_writable($path)) {
            return $path;
        }
    }

    // Prefer the directory associated with the actual log.
    $logDir = dirname($logFile);
    $root = basename($logDir) === 'logs' ? dirname($logDir) : $logDir;
    $dir = $root . '/lists';

    if (!is_dir($dir)) {
        return null;
    }

    $path = $dir . '/' . $listName;
    if (!file_exists($path)) {
        $header = $listName === 'blacklist_ip'
            ? "# blacklist_ip\n# Черный список IP-адресов\n# Формат: IP # комментарий\n"
            : "# blacklist_fingerprint\n# Список FingerPrint\n# Символ # используется как комментарий.\n";
        if (@file_put_contents($path, $header, LOCK_EX) === false) {
            return null;
        }
    }

    return is_writable($path) ? $path : null;
}

function analyzerListContains(string $path, string $value): bool {
    if (!is_readable($path)) {
        return false;
    }

    $handle = fopen($path, 'rb');
    if (!$handle) return false;

    try {
        while (($line = fgets($handle)) !== false) {
            $line = trim((string)preg_replace('/#.*$/', '', $line));
            if ($line !== '' && hash_equals($line, $value)) {
                return true;
            }
        }
    } finally {
        fclose($handle);
    }

    return false;
}

function analyzerAddToList(string $path, string $value, string $comment): array {
    if (!is_writable($path)) {
        return ['ok' => false, 'message' => 'Файл списка недоступен для записи: ' . $path];
    }

    $handle = fopen($path, 'c+');
    if (!$handle) {
        return ['ok' => false, 'message' => 'Не удалось открыть blacklist для записи.'];
    }

    try {
        if (!flock($handle, LOCK_EX)) {
            return ['ok' => false, 'message' => 'Не удалось заблокировать файл списка.'];
        }

        rewind($handle);
        $content = stream_get_contents($handle);
        $lines = preg_split('/\R/', (string)$content);

        foreach ($lines as $line) {
            $lineValue = trim((string)preg_replace('/#.*$/', '', $line));
            if ($lineValue !== '' && $lineValue === $value) {
                flock($handle, LOCK_UN);
                return ['ok' => true, 'added' => false, 'message' => 'Уже находится в blacklist.'];
            }
        }

        fseek($handle, 0, SEEK_END);
        $stat = fstat($handle);
        if (($stat['size'] ?? 0) > 0) {
            fseek($handle, -1, SEEK_END);
            $last = fread($handle, 1);
            if ($last !== "\n") {
                fwrite($handle, PHP_EOL);
            }
            fseek($handle, 0, SEEK_END);
        }

        $line = $value . ' # ' . date('Y-m-d H:i:s') . ' ' . $comment . PHP_EOL;
        fwrite($handle, $line);
        fflush($handle);
        flock($handle, LOCK_UN);

        return ['ok' => true, 'added' => true, 'message' => 'Добавлено в blacklist.'];
    } finally {
        fclose($handle);
    }
}

function analyzerReadBlacklist(string $logFile, string $listName): array {
    $path = analyzerFindOrCreateList($logFile, $listName);
    if ($path === null || !is_readable($path)) return [];
    $set = [];
    $fh = fopen($path, 'rb');
    if (!$fh) return [];
    while (($line = fgets($fh)) !== false) {
        $value = trim((string)preg_replace('/#.*$/', '', $line));
        if ($value !== '') $set[$value] = true;
    }
    fclose($fh);
    return $set;
}

function analyzerPerformBlock(string $logFile, string $action, string $ip, string $fp): array {
    if (!in_array($action, ['ip', 'fingerprint', 'both'], true)) {
        return ['ok' => false, 'message' => 'Неизвестное действие блокировки.'];
    }

    $results = [];
    $comment = 'Added from AntiBot Analyzer';

    if ($action === 'ip' || $action === 'both') {
        if (!analyzerValidateIP($ip)) {
            return ['ok' => false, 'message' => 'Некорректный IP-адрес.'];
        }

        $path = analyzerFindOrCreateList($logFile, 'blacklist_ip');
        if ($path === null) {
            return ['ok' => false, 'message' => 'Не найден или недоступен lists/blacklist_ip.'];
        }

        $results[] = ['target'=>'IP', 'value'=>$ip] + analyzerAddToList($path, $ip, $comment);
    }

    if ($action === 'fingerprint' || $action === 'both') {
        if (!analyzerValidateFingerprint($fp)) {
            return ['ok' => false, 'message' => 'Некорректный Fingerprint.'];
        }

        $path = analyzerFindOrCreateList($logFile, 'blacklist_fingerprint');
        if ($path === null) {
            return ['ok' => false, 'message' => 'Не найден или недоступен lists/blacklist_fingerprint.'];
        }

        $results[] = ['target'=>'Fingerprint', 'value'=>$fp] + analyzerAddToList($path, $fp, $comment);
    }

    $added = array_sum(array_map(fn($r) => !empty($r['added']) ? 1 : 0, $results));
    $failed = array_filter($results, fn($r) => empty($r['ok']));

    return [
        'ok' => empty($failed),
        'added' => $added,
        'results' => $results,
        'message' => empty($failed)
            ? ($added > 0 ? 'Блокировка применена.' : 'Все выбранные значения уже были в blacklist.')
            : 'Не все действия выполнены.',
    ];
}

/**
 * Built-in AntiBot log parser.
 *
 * The upstream AntiBot project does NOT contain class-antibot-log-parser.php.
 * The analyzer therefore parses the native AntiBot log format itself:
 * YYYY-MM-DD HH:MM:SS RAYID IP MESSAGE
 *
 * This keeps the analyzer independent from upstream files and updates.
 */
if (!class_exists('AntiBotLogParser')) {
    final class AntiBotLogParser {
        public static function parse(string $content, ?string $timeFrom = null, ?string $timeTo = null, ?string $searchTerm = null): array {
            $sessions = [];

            foreach (preg_split('/\R/u', $content) as $line) {
                $line = trim((string)$line);
                if ($line === '') {
                    continue;
                }

                if (!preg_match(
                    '/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s*(.*)$/u',
                    $line,
                    $m
                )) {
                    continue;
                }

                $timestamp = $m[1];
                $rayId = $m[2];
                $ip = $m[3];
                $message = trim($m[4]);

                if ($timeFrom !== null && $timeFrom !== '' && $timestamp < $timeFrom) {
                    continue;
                }
                if ($timeTo !== null && $timeTo !== '' && $timestamp > $timeTo) {
                    continue;
                }
                $key = $rayId !== '' ? $rayId : ($ip . '|' . $timestamp);
                if (!isset($sessions[$key])) {
                    $sessions[$key] = [
                        'rayId' => $rayId,
                        'ip' => $ip,
                        'firstSeen' => $timestamp,
                        'lastSeen' => $timestamp,
                        'requestCount' => 0,
                        'logLineCount' => 0,
                        'entries' => [],
                        'fingerprints' => [],
                        'fingerprint' => '',
                        'captchaShowCount' => 0,
                        'verificationPageCount' => 0,
                        'captchaPassCount' => 0,
                        'captchaPassed' => false,
                        'captchaReason' => '',
                        'blocked' => false,
                        'blockCount' => 0,
                        'blockEvidence' => [],
                        'isRobot' => false,
                        'robotName' => '',
                        'isWhitelisted' => false,
                    ];
                }

                $s =& $sessions[$key];
                $s['logLineCount']++;
                if ($message !== '' && ($message[0] === '/' || preg_match('/^https?:\/\//i', $message))) {
                    $s['requestCount']++;
                }
                if ($timestamp < $s['firstSeen']) $s['firstSeen'] = $timestamp;
                if ($timestamp > $s['lastSeen']) $s['lastSeen'] = $timestamp;

                $s['entries'][] = [
                    'timestamp' => $timestamp,
                    'message' => $message,
                ];

                if (preg_match('/\bFP:\s*([a-f0-9]{16,128})\b/i', $message, $fpMatch)) {
                    $fp = strtolower($fpMatch[1]);
                    $s['fingerprints'][$fp] = true;
                    $s['fingerprint'] = $fp;
                }

                if (stripos($message, 'Indexing robot') !== false) {
                    $s['isRobot'] = true;
                    $robot = trim(preg_replace('/^.*?Indexing robot\s*:?\s*/i', '', $message));
                    $s['robotName'] = $robot !== '' ? $robot : 'Индексирующий бот';
                }

                if (
                    stripos($message, 'whitelist') !== false ||
                    stripos($message, 'white list') !== false ||
                    stripos($message, 'IP address found in whitelist') !== false
                ) {
                    $s['isWhitelisted'] = true;
                }

                if (preg_match('/^Show captcha$/i', trim($message))) {
                    // ВАЖНО: "Show captcha for DIRECT" — это служебное событие,
                    // а не отдельный показ CAPTCHA. Считаем только точное "Show captcha".
                    $s['captchaShowCount']++;
                    $reason = trim($message);
                    if ($reason !== '') $s['captchaReason'] = $reason;
                }

                if (stripos($message, 'Displaying the verification page') !== false) {
                    $s['verificationPageCount']++;
                }

                if (stripos($message, 'Successfully passed the captcha') !== false) {
                    $s['captchaPassCount']++;
                    $s['captchaPassed'] = true;
                }

                $isBlock = (
                    stripos($message, 'blocked') !== false ||
                    stripos($message, 'blocking page') !== false ||
                    stripos($message, 'blocked:') !== false
                );

                if ($isBlock) {
                    $s['blocked'] = true;
                    $s['blockCount']++;
                    $s['blockEvidence'][] = [
                        'timestamp' => $timestamp,
                        'message' => $message,
                    ];
                }

                unset($s);
            }

            foreach ($sessions as &$session) {
                $session['fingerprints'] = array_keys($session['fingerprints']);
                $session['fingerprint'] = $session['fingerprints'][0] ?? '';
                $session['urls'] = [];

                foreach ($session['entries'] as $entry) {
                    $msg = (string)$entry['message'];

                    // Native AntiBot writes requested URLs as ordinary log messages.
                    if (
                        $msg !== '' &&
                        $msg[0] === '/' &&
                        !preg_match('/^(\/|https?:\/\/).*?(?:\s+)?(?:blocked|captcha|allowed)/i', $msg)
                    ) {
                        $session['urls'][] = $msg;
                    }
                }

                $session['urls'] = array_values(array_unique($session['urls']));
            }
            unset($session);

            // Search after grouping so matching fingerprints can find sessions across IPs.
            if ($searchTerm !== null && $searchTerm !== '') {
                $needle = strtolower($searchTerm);
                $sessions = array_filter($sessions, static function (array $session) use ($needle): bool {
                    if (stripos((string)($session['ip'] ?? ''), $needle) !== false) {
                        return true;
                    }
                    foreach (($session['fingerprints'] ?? []) as $fp) {
                        if (stripos((string)$fp, $needle) !== false) {
                            return true;
                        }
                    }
                    return false;
                });
            }

            return ['sessions' => array_values($sessions)];
        }
    }
}

$timeFrom = isset($_GET['from']) ? trim((string)$_GET['from']) : null;
$timeTo   = isset($_GET['to']) ? trim((string)$_GET['to']) : null;
$searchTerm = isset($_GET['search']) ? trim((string)$_GET['search']) : null;
$sortBy = (string)($_GET['sort'] ?? 'captchaShown');
$sortOrder = (($_GET['order'] ?? 'desc') === 'asc') ? 'asc' : 'desc';
$allowedSorts = ['captchaShown', 'requests', 'sessions', 'blocked', 'ipCount', 'firstSeen', 'lastSeen'];
if (!in_array($sortBy, $allowedSorts, true)) $sortBy = 'captchaShown';

$minCaptchaAttempts = max(1, min(20, (int)($_GET['threshold'] ?? 2)));

$logContent = file_get_contents($logFile);
if ($logContent === false) {
    die('Не удалось прочитать antibot.log');
}

$data = AntiBotLogParser::parse(
    $logContent,
    $timeFrom ?: null,
    $timeTo ?: null,
    $searchTerm ?: null
);

$sessions = array_values($data['sessions'] ?? []);

function h($value): string {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function uniqueStrings(array $items): array {
    $out = [];
    foreach ($items as $item) {
        $item = trim((string)$item);
        if ($item !== '') $out[$item] = true;
    }
    return array_keys($out);
}

function sessionFingerprints(array $session): array {
    $fps = $session['fingerprints'] ?? [];
    if (!$fps && !empty($session['fingerprint'])) {
        $fps = [$session['fingerprint']];
    }
    return uniqueStrings($fps);
}

function isExplicitlyBlocked(array $session): bool {
    return !empty($session['blocked']) ||
        !empty($session['blockCount']) ||
        !empty($session['blockEvidence']);
}

function hasCaptchaSuccess(array $session): bool {
    return !empty($session['captchaPassed']) || ((int)($session['captchaPassCount'] ?? 0) > 0);
}

function sessionLastMessage(array $session): string {
    $evidence = $session['blockEvidence'] ?? [];
    if (!empty($evidence[0]['message'])) return (string)$evidence[0]['message'];

    $entries = $session['entries'] ?? [];
    if ($entries) {
        $last = end($entries);
        return (string)($last['message'] ?? '');
    }
    return '';
}

/**
 * Агрегируем поведение по IP и fingerprint.
 * Это важно: один fingerprint может работать с нескольких IP.
 */
$entities = [
    'ip' => [],
    'fp' => [],
];

$currentBlacklistIPs = analyzerReadBlacklist($logFile, 'blacklist_ip');
$currentBlacklistFPs = analyzerReadBlacklist($logFile, 'blacklist_fingerprint');

$blockedSessions = [];
$pendingSessions = [];
$passedSessions = [];
$robotSessions = [];
$whitelistSessions = [];

foreach ($sessions as $session) {
    $ip = trim((string)($session['ip'] ?? ''));
    $fps = sessionFingerprints($session);

    if (!empty($session['isRobot'])) {
        $robotSessions[] = $session;
        continue;
    }

    if (!empty($session['isWhitelisted'])) {
        $whitelistSessions[] = $session;
        continue;
    }

    $blocked = isExplicitlyBlocked($session);
    $passed = hasCaptchaSuccess($session);
    $shown = (int)($session['captchaShowCount'] ?? 0);

    if ($blocked) {
        $blockedSessions[] = $session;
    } elseif ($shown > 0 && !$passed) {
        $pendingSessions[] = $session;
    } elseif ($passed) {
        $passedSessions[] = $session;
    }

    if ($ip !== '') {
        if (!isset($entities['ip'][$ip])) {
            $entities['ip'][$ip] = [
                'type' => 'ip',
                'value' => $ip,
                'ips' => [$ip => true],
                'fps' => [],
                'sessions' => 0,
                'requests' => 0,
                'captchaShown' => 0,
                'verificationPages' => 0,
                'captchaPassed' => 0,
                'blocked' => 0,
                'blockReasons' => [],
                'firstSeen' => $session['firstSeen'] ?? '',
                'lastSeen' => $session['lastSeen'] ?? '',
                'captchaReasons' => [],
                'urls' => [],
                'inBlacklist' => false,
                'blacklistSource' => '',
            ];
        }
        $e =& $entities['ip'][$ip];
        $e['sessions']++;
        $e['requests'] += (int)($session['requestCount'] ?? 0);
        $e['captchaShown'] += $shown;
        $e['verificationPages'] += (int)($session['verificationPageCount'] ?? 0);
        $e['captchaPassed'] += (int)($session['captchaPassCount'] ?? 0);
        if ($blocked) {
            $e['blocked']++;
            $reason = sessionLastMessage($session);
            if ($reason !== '') $e['blockReasons'][$reason] = true;
        }
        foreach ($fps as $fp) $e['fps'][$fp] = true;
        if (!empty($session['captchaReason'])) $e['captchaReasons'][(string)$session['captchaReason']] = true;
        foreach (($session['urls'] ?? []) as $url) {
            $url = trim((string)$url);
            if ($url !== '') $e['urls'][$url] = true;
        }
        if (($session['firstSeen'] ?? '') !== '' && ($e['firstSeen'] === '' || $session['firstSeen'] < $e['firstSeen'])) $e['firstSeen'] = $session['firstSeen'];
        if (($session['lastSeen'] ?? '') > $e['lastSeen']) $e['lastSeen'] = $session['lastSeen'];
        unset($e);
    }

    foreach ($fps as $fp) {
        if (!isset($entities['fp'][$fp])) {
            $entities['fp'][$fp] = [
                'type' => 'fp',
                'value' => $fp,
                'ips' => [],
                'fps' => [$fp => true],
                'sessions' => 0,
                'requests' => 0,
                'captchaShown' => 0,
                'verificationPages' => 0,
                'captchaPassed' => 0,
                'blocked' => 0,
                'blockReasons' => [],
                'firstSeen' => $session['firstSeen'] ?? '',
                'lastSeen' => $session['lastSeen'] ?? '',
                'captchaReasons' => [],
                'urls' => [],
            ];
        }
        $e =& $entities['fp'][$fp];
        $e['sessions']++;
        $e['requests'] += (int)($session['requestCount'] ?? 0);
        $e['captchaShown'] += $shown;
        $e['verificationPages'] += (int)($session['verificationPageCount'] ?? 0);
        $e['captchaPassed'] += (int)($session['captchaPassCount'] ?? 0);
        if ($blocked) {
            $e['blocked']++;
            $reason = sessionLastMessage($session);
            if ($reason !== '') $e['blockReasons'][$reason] = true;
        }
        if ($ip !== '') $e['ips'][$ip] = true;
        if (!empty($session['captchaReason'])) $e['captchaReasons'][(string)$session['captchaReason']] = true;
        foreach (($session['urls'] ?? []) as $url) {
            $url = trim((string)$url);
            if ($url !== '') $e['urls'][$url] = true;
        }
        if (($session['firstSeen'] ?? '') !== '' && ($e['firstSeen'] === '' || $session['firstSeen'] < $e['firstSeen'])) $e['firstSeen'] = $session['firstSeen'];
        if (($session['lastSeen'] ?? '') > $e['lastSeen']) $e['lastSeen'] = $session['lastSeen'];
        unset($e);
    }
}

foreach (['ip','fp'] as $type) {
    foreach ($entities[$type] as &$entity) {
        $entity['ips'] = array_keys($entity['ips']);
        $entity['fps'] = array_keys($entity['fps']);
        $entity['blockReasons'] = array_keys($entity['blockReasons']);
        $entity['captchaReasons'] = array_keys($entity['captchaReasons']);
        $entity['urls'] = array_keys($entity['urls']);
        $entity['ipCount'] = count($entity['ips']);
        $entity['fpCount'] = count($entity['fps']);
        if ($type === 'ip' && isset($currentBlacklistIPs[$entity['value']])) { $entity['inBlacklist'] = true; $entity['blacklistSource'] = 'IP'; }
        if ($type === 'fp' && isset($currentBlacklistFPs[$entity['value']])) { $entity['inBlacklist'] = true; $entity['blacklistSource'] = 'Fingerprint'; }
    }
    unset($entity);
}

/**
 * Решение для блокировки:
 * - уже есть реальное block-событие -> УЖЕ ЗАБЛОКИРОВАН;
 * - CAPTCHA показывалась N раз и ни одного успешного прохождения нет -> К БЛОКИРОВКЕ;
 * - один успешный проход защищает сущность от автоматической рекомендации блокировки;
 * - один показ CAPTCHA без успеха -> только "ожидает проверки".
 *
 * Это намеренно простая модель, понятная оператору.
 */
$alreadyBlocked = [];
$toBlock = [];
$captchaPending = [];
$captchaPassed = [];

foreach (['ip','fp'] as $type) {
    foreach ($entities[$type] as $entity) {
        if ($entity['blocked'] > 0 || $entity['inBlacklist']) {
            $alreadyBlocked[] = $entity;
            continue;
        }

        if ($entity['captchaShown'] >= $minCaptchaAttempts && $entity['captchaPassed'] === 0) {
            $toBlock[] = $entity;
        } elseif ($entity['captchaShown'] > 0 && $entity['captchaPassed'] === 0) {
            $captchaPending[] = $entity;
        } elseif ($entity['captchaPassed'] > 0) {
            $captchaPassed[] = $entity;
        }
    }
}

/**
 * Если fingerprint рекомендуется к блокировке, IP, связанные с ним,
 * отдельно не дублируем в основном списке: оператор видит связь FP -> IP.
 */
$toBlockFp = [];
$toBlockIp = [];
foreach ($toBlock as $item) {
    if ($item['type'] === 'fp') $toBlockFp[] = $item;
    else $toBlockIp[] = $item;
}

usort($toBlockFp, fn($a,$b) => ($b['captchaShown'] <=> $a['captchaShown']) ?: ($b['ipCount'] <=> $a['ipCount']));
usort($toBlockIp, fn($a,$b) => ($b['captchaShown'] <=> $a['captchaShown']) ?: ($b['sessions'] <=> $a['sessions']));
usort($alreadyBlocked, fn($a,$b) => ($b['blocked'] <=> $a['blocked']) ?: ($b['lastSeen'] <=> $a['lastSeen']));
usort($captchaPending, fn($a,$b) => ($b['captchaShown'] <=> $a['captchaShown']));
usort($captchaPassed, fn($a,$b) => ($b['captchaPassed'] <=> $a['captchaPassed']));

$sortEntities = static function (array &$items) use ($sortBy, $sortOrder): void {
    usort($items, static function (array $a, array $b) use ($sortBy, $sortOrder): int {
        $av = $a[$sortBy] ?? '';
        $bv = $b[$sortBy] ?? '';
        $cmp = (is_numeric($av) && is_numeric($bv))
            ? ((float)$av <=> (float)$bv)
            : strcmp((string)$av, (string)$bv);
        return $sortOrder === 'asc' ? $cmp : -$cmp;
    });
};
$sortEntities($toBlockFp);
$sortEntities($toBlockIp);
$sortEntities($alreadyBlocked);
$sortEntities($captchaPending);
$sortEntities($captchaPassed);

$allBlockedIPs = [];
$allBlockedFPs = [];
foreach ($alreadyBlocked as $item) {
    if ($item['type'] === 'ip') $allBlockedIPs[$item['value']] = true;
    if ($item['type'] === 'fp') $allBlockedFPs[$item['value']] = true;
}

$stats = [
    'sessions' => count($sessions),
    'ips' => count($entities['ip']),
    'fps' => count($entities['fp']),
    'blocked' => count($alreadyBlocked),
    'toBlock' => count($toBlock),
    'toBlockIp' => count($toBlockIp),
    'toBlockFp' => count($toBlockFp),
    'pending' => count($captchaPending),
    'passed' => count($captchaPassed),
    'robots' => count($robotSessions),
    'whitelist' => count($whitelistSessions),
    'captchaShown' => array_sum(array_map(fn($s)=>(int)($s['captchaShowCount']??0), $sessions)),
    'captchaPassed' => array_sum(array_map(fn($s)=>(int)($s['captchaPassCount']??0), $sessions)),
];

$lastModified = date('Y-m-d H:i:s', filemtime($logFile));
$fileSize = round(filesize($logFile) / 1024 / 1024, 2);

function renderEntity(array $item, string $mode): void {
    $isFp = $item['type'] === 'fp';
    $label = $isFp ? 'Fingerprint' : 'IP';
    $value = $item['value'];
    $ips = $item['ips'];
    $fps = $item['fps'];

    $badge = $mode === 'blocked'
        ? (!empty($item['inBlacklist'])
            ? '<span class="badge red">В BLACKLIST</span>'
            : '<span class="badge red">УЖЕ ЗАБЛОКИРОВАН</span>')
        : ($mode === 'block'
            ? '<span class="badge orange">НУЖНО ЗАБЛОКИРОВАТЬ</span>'
            : ($mode === 'pending'
                ? '<span class="badge yellow">ОЖИДАЕТ CAPTCHA</span>'
                : '<span class="badge green">CAPTCHA ПРОЙДЕНА</span>'));

    // For a fingerprint card we can block the FP directly, or block all
    // currently associated IPs via the "both" action.
    $actionIp = $isFp ? ($ips[0] ?? '') : $value;
    $actionFp = $isFp ? $value : ($fps[0] ?? '');
    ?>
    <article class="entity-card">
        <div class="entity-top">
            <div>
                <?= $badge ?>
                <div class="entity-value"><?= h($value) ?></div>
                <div class="entity-type"><?= h($label) ?></div>
                <?php if (!empty($item['inBlacklist'])): ?><div class="entity-type" style="color:#fca5a5">✓ Сейчас находится в blacklist</div><?php endif; ?>
            </div>
            <div class="entity-actions">
                <button class="copy" data-copy="<?= h($value) ?>">Копировать</button>
            </div>
        </div>

        <div class="facts">
            <div><b>Сессий</b><span><?= (int)$item['sessions'] ?></span></div>
            <div><b>Запросов</b><span><?= (int)$item['requests'] ?></span></div>
            <div><b>CAPTCHA</b><span><?= (int)$item['captchaShown'] ?> показано</span></div>
            <div><b>Страница проверки</b><span><?= (int)$item['verificationPages'] ?></span></div>
            <div><b>Успешно</b><span><?= (int)$item['captchaPassed'] ?></span></div>
            <div><b>IP</b><span><?= (int)$item['ipCount'] ?></span></div>
            <div><b>Fingerprint</b><span><?= (int)$item['fpCount'] ?></span></div>
        </div>

        <?php if ($item['blockReasons']): ?>
            <div class="reason"><b>Причина блокировки:</b> <?= h(implode(' · ', array_slice($item['blockReasons'],0,3))) ?></div>
        <?php endif; ?>

        <?php if ($item['captchaReasons']): ?>
            <div class="reason"><b>Почему показана CAPTCHA:</b> <?= h(implode(' · ', array_slice($item['captchaReasons'],0,4))) ?></div>
        <?php endif; ?>

        <?php if ($isFp && $ips): ?>
            <div class="linked">
                <b>Связанные IP:</b>
                <?php foreach (array_slice($ips,0,30) as $ip): ?>
                    <button class="token copy" data-copy="<?= h($ip) ?>"><?= h($ip) ?></button>
                <?php endforeach; ?>
                <?php if (count($ips)>30): ?><span class="muted">+<?= count($ips)-30 ?> ещё</span><?php endif; ?>
            </div>
        <?php elseif (!$isFp && $fps): ?>
            <div class="linked">
                <b>Fingerprint:</b>
                <?php foreach (array_slice($fps,0,10) as $fp): ?>
                    <button class="token copy" data-copy="<?= h($fp) ?>"><?= h($fp) ?></button>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <?php if ($mode === 'block' && analyzerActionAuthorized()): ?>
            <div class="actions">
                <?php if ($isFp): ?>
                    <form method="post" onsubmit="return confirm('Заблокировать этот Fingerprint?');">
                        <input type="hidden" name="csrf" value="<?= h(analyzerActionToken()) ?>">
                        <input type="hidden" name="analyzer_action" value="fingerprint">
                        <input type="hidden" name="fingerprint" value="<?= h($actionFp) ?>">
                        <button class="action fp-action" type="submit">🚫 Заблокировать Fingerprint</button>
                    </form>

                <?php else: ?>
                    <form method="post" onsubmit="return confirm('Заблокировать этот IP?');">
                        <input type="hidden" name="csrf" value="<?= h(analyzerActionToken()) ?>">
                        <input type="hidden" name="analyzer_action" value="ip">
                        <input type="hidden" name="ip" value="<?= h($actionIp) ?>">
                        <button class="action ip-action" type="submit">🚫 Заблокировать IP</button>
                    </form>
                    <?php if ($actionFp): ?>
                        <form method="post" onsubmit="return confirm('Заблокировать IP и Fingerprint?');">
                            <input type="hidden" name="csrf" value="<?= h(analyzerActionToken()) ?>">
                            <input type="hidden" name="analyzer_action" value="both">
                            <input type="hidden" name="ip" value="<?= h($actionIp) ?>">
                            <input type="hidden" name="fingerprint" value="<?= h($actionFp) ?>">
                            <button class="action both-action" type="submit">🚫 Заблокировать оба</button>
                        </form>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        <?php elseif ($mode === 'block'): ?>
            <div class="action-warning">Действия блокировки скрыты: нет авторизации оператора.</div>
        <?php endif; ?>

        <div class="meta">
            <?= h($item['firstSeen']) ?> → <?= h($item['lastSeen']) ?>
        </div>
    </article>
    <?php
}?>
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AntiBot — что делать</title>
<style>
:root{--bg:#070b13;--panel:#101827;--panel2:#0b1220;--line:#243044;--text:#edf2f7;--muted:#94a3b8;--red:#f87171;--orange:#fb923c;--yellow:#facc15;--green:#34d399;--blue:#60a5fa}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,Arial,sans-serif}
.wrap{max-width:1450px;margin:auto;padding:22px}.header{display:flex;justify-content:space-between;gap:20px;align-items:center;margin-bottom:20px}
h1{font-size:28px;margin:0 0 5px}.sub{color:var(--muted);font-size:13px}.grid{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin:18px 0}.stat{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:15px}.stat b{display:block;font-size:25px}.stat span{color:var(--muted);font-size:12px}.stat.red b{color:var(--red)}.stat.orange b{color:var(--orange)}.stat.yellow b{color:var(--yellow)}.stat.green b{color:var(--green)}
.tabs{display:flex;gap:7px;flex-wrap:wrap;margin:20px 0}.tab{border:1px solid var(--line);background:var(--panel);color:#cbd5e1;padding:10px 13px;border-radius:10px;cursor:pointer}.tab.active{border-color:#64748b;background:#172033;color:#fff}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:18px;margin-bottom:18px}.panel h2{margin:0 0 5px;font-size:19px}.hint{color:var(--muted);font-size:12px;margin-bottom:14px}.cards{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.entity-card{background:var(--panel2);border:1px solid var(--line);border-radius:14px;padding:15px}.entity-top{display:flex;justify-content:space-between;gap:12px}.entity-value{font:700 16px ui-monospace,SFMono-Regular,Consolas,monospace;margin-top:9px;word-break:break-all}.entity-type{font-size:11px;color:var(--muted);margin-top:3px}.badge{display:inline-block;border-radius:999px;padding:5px 8px;font-size:10px;font-weight:800;letter-spacing:.04em}.badge.red{background:#3a1418;color:#fca5a5}.badge.orange{background:#3b2110;color:#fdba74}.badge.yellow{background:#382f08;color:#fde68a}.badge.green{background:#0d3328;color:#6ee7b7}
.facts{display:grid;grid-template-columns:repeat(3,1fr);gap:7px;margin:14px 0}.facts div{background:#111a2a;border-radius:8px;padding:8px}.facts b{display:block;color:#7f8da3;font-size:10px;text-transform:uppercase}.facts span{display:block;margin-top:3px;font-size:12px}.reason{border-left:3px solid #475569;background:#111827;padding:9px;margin-top:8px;font-size:12px;color:#cbd5e1}.linked{margin-top:11px;font-size:12px;color:#cbd5e1}.token,.copy{font:inherit;border:0;cursor:pointer}.token{display:inline-block;background:#182235;color:#93c5fd;border-radius:6px;padding:4px 6px;margin:3px;font-family:monospace;font-size:11px}.copy{background:#182235;color:#cbd5e1;border-radius:7px;padding:7px 9px;font-size:11px}.copy:hover,.token:hover{background:#24334d}.meta{margin-top:12px;color:#64748b;font-size:10px}.muted{color:#64748b}
.actions{display:flex;gap:7px;flex-wrap:wrap;margin-top:14px;padding-top:12px;border-top:1px solid var(--line)}
.actions form{margin:0}.action{border:0;border-radius:8px;padding:9px 11px;color:#fff;font-size:11px;font-weight:700;cursor:pointer}
.ip-action{background:#b91c1c}.fp-action{background:#c2410c}.both-action{background:#7c3aed}.action:hover{filter:brightness(1.12)}
.action-result{margin-bottom:15px;border-radius:10px;padding:12px 14px;font-size:13px;border:1px solid}
.action-result.success{background:#0d3328;color:#a7f3d0;border-color:#166534}.action-result.error{background:#3a1418;color:#fecaca;border-color:#991b1b}
.action-warning{margin-top:12px;padding:9px;background:#2a2110;color:#fcd34d;border-radius:8px;font-size:11px}
.empty{padding:35px;text-align:center;color:#64748b;background:var(--panel2);border:1px dashed var(--line);border-radius:12px}
.filters{display:flex;gap:8px;align-items:end;flex-wrap:wrap}.filters label{display:flex;flex-direction:column;gap:5px;color:var(--muted);font-size:11px}.filters input,.filters select{background:#0b1220;border:1px solid var(--line);color:#fff;border-radius:8px;padding:9px}.filters button{background:#2563eb;color:#fff;border:0;border-radius:8px;padding:10px 14px;cursor:pointer}
footer{color:#64748b;font-size:11px;text-align:center;padding:10px}
@media(max-width:1050px){.grid{grid-template-columns:repeat(3,1fr)}}@media(max-width:700px){.wrap{padding:12px}.header{display:block}.grid,.cards{grid-template-columns:1fr}.facts{grid-template-columns:repeat(2,1fr)}h1{font-size:22px}}
</style>
</head>
<body>
<div class="wrap">
<?php if ($actionMessage !== null): ?>
<div class="action-result <?= $actionError ? 'error' : 'success' ?>">
    <?= h($actionMessage) ?>
</div>
<?php endif; ?>
<header class="header">
    <div>
        <h1>🛡 AntiBot — что делать</h1>
        <div class="sub">Простой анализ журнала: кого уже заблокировали и кого следует заблокировать.</div>
    </div>
    <div class="sub">Лог: <?= h(basename($logFile)) ?> · <?= h($fileSize) ?> MB · <?= h($lastModified) ?></div>
</header>

<div class="panel">
<form class="filters" method="get">
    <label>С даты<input type="text" name="from" placeholder="2026-10-01 00:00:00" value="<?= h($timeFrom) ?>"></label>
    <label>По дату<input type="text" name="to" placeholder="2026-10-03 23:59:59" value="<?= h($timeTo) ?>"></label>
    <label>IP или Fingerprint<input type="text" name="search" placeholder="IP или часть fingerprint" value="<?= h($searchTerm) ?>"></label>
    <label>Сортировать по<select name="sort"><option value="captchaShown" <?= $sortBy==='captchaShown' ? 'selected' : '' ?>>Показам CAPTCHA</option><option value="requests" <?= $sortBy==='requests' ? 'selected' : '' ?>>Запросам</option><option value="sessions" <?= $sortBy==='sessions' ? 'selected' : '' ?>>Сессиям</option><option value="blocked" <?= $sortBy==='blocked' ? 'selected' : '' ?>>Блокировкам</option><option value="ipCount" <?= $sortBy==='ipCount' ? 'selected' : '' ?>>Количеству IP</option><option value="firstSeen" <?= $sortBy==='firstSeen' ? 'selected' : '' ?>>Первому появлению</option><option value="lastSeen" <?= $sortBy==='lastSeen' ? 'selected' : '' ?>>Последнему появлению</option></select></label>
    <label>Порядок<select name="order"><option value="desc" <?= $sortOrder==='desc' ? 'selected' : '' ?>>По убыванию</option><option value="asc" <?= $sortOrder==='asc' ? 'selected' : '' ?>>По возрастанию</option></select></label>
    <label>Порог CAPTCHA<input type="number" min="1" max="20" name="threshold" value="<?= (int)$minCaptchaAttempts ?>"></label>
    <button type="submit">Обновить</button>
</form>
</div>

<div class="grid">
    <div class="stat red"><b><?= (int)$stats['toBlock'] ?></b><span>К блокировке</span></div>
    <div class="stat red"><b><?= (int)$stats['blocked'] ?></b><span>Уже заблокированы</span></div>
    <div class="stat yellow"><b><?= (int)$stats['pending'] ?></b><span>Ожидают CAPTCHA</span></div>
    <div class="stat green"><b><?= (int)$stats['passed'] ?></b><span>CAPTCHA пройдена</span></div>
    <div class="stat"><b><?= (int)$stats['ips'] ?></b><span>IP</span></div>
    <div class="stat"><b><?= (int)$stats['fps'] ?></b><span>Fingerprint</span></div>
</div>

<div class="tabs">
    <button class="tab active" data-tab="block">🔴 К блокировке (<?= (int)$stats['toBlock'] ?>)</button>
    <button class="tab" data-tab="blocked">⛔ Уже заблокированы (<?= (int)$stats['blocked'] ?>)</button>
    <button class="tab" data-tab="pending">🟡 CAPTCHA не завершена (<?= (int)$stats['pending'] ?>)</button>
    <button class="tab" data-tab="passed">🟢 CAPTCHA пройдена (<?= (int)$stats['passed'] ?>)</button>
    <button class="tab" data-tab="robots">🤖 Боты (<?= (int)$stats['robots'] ?>)</button>
</div>

<section class="tab-content" id="tab-block">
    <div class="panel">
        <h2>🔴 К блокировке</h2>
        <div class="hint">CAPTCHA показывалась не менее <?= (int)$minCaptchaAttempts ?> раз, успешного прохождения не найдено. Если есть Fingerprint — он показывается вместе с IP.</div>

        <?php if (!$toBlock): ?>
            <div class="empty">Нет сущностей, которые сейчас соответствуют правилу блокировки.</div>
        <?php else: ?>
            <?php if ($toBlockFp): ?>
                <h3>Fingerprint</h3>
                <div class="cards"><?php foreach ($toBlockFp as $item) renderEntity($item,'block'); ?></div>
            <?php endif; ?>

            <?php if ($toBlockIp): ?>
                <h3>IP</h3>
                <div class="cards"><?php foreach ($toBlockIp as $item) renderEntity($item,'block'); ?></div>
            <?php endif; ?>
        <?php endif; ?>
    </div>
</section>

<section class="tab-content" id="tab-blocked" hidden>
    <div class="panel">
        <h2>⛔ Уже заблокированы</h2>
        <div class="hint">Здесь находятся те, у кого есть событие блокировки в журнале или кто уже находится в текущем blacklist-файле.</div>
        <?php if (!$alreadyBlocked): ?><div class="empty">Фактических блокировок не найдено.</div>
        <?php else: ?><div class="cards"><?php foreach ($alreadyBlocked as $item) renderEntity($item,'blocked'); ?></div><?php endif; ?>
    </div>
</section>

<section class="tab-content" id="tab-pending" hidden>
    <div class="panel">
        <h2>🟡 CAPTCHA не завершена</h2>
        <div class="hint">Есть показ CAPTCHA, но в журнале пока нет успешного прохождения. Один такой случай не считается основанием для блокировки.</div>
        <?php if (!$captchaPending): ?><div class="empty">Незавершённых CAPTCHA нет.</div>
        <?php else: ?><div class="cards"><?php foreach ($captchaPending as $item) renderEntity($item,'pending'); ?></div><?php endif; ?>
    </div>
</section>

<section class="tab-content" id="tab-passed" hidden>
    <div class="panel">
        <h2>🟢 CAPTCHA пройдена</h2>
        <div class="hint">Сущности, для которых в журнале зафиксировано успешное прохождение CAPTCHA.</div>
        <?php if (!$captchaPassed): ?><div class="empty">Успешных прохождений не найдено.</div>
        <?php else: ?><div class="cards"><?php foreach (array_slice($captchaPassed,0,200) as $item) renderEntity($item,'passed'); ?></div><?php endif; ?>
    </div>
</section>

<section class="tab-content" id="tab-robots" hidden>
    <div class="panel">
        <h2>🤖 Индексирующие боты</h2>
        <div class="hint">Они не смешиваются с посетителями и не попадают в список блокировки.</div>
        <?php if (!$robotSessions): ?><div class="empty">Индексирующих ботов не найдено.</div>
        <?php else: ?>
            <div class="cards">
            <?php foreach (array_slice($robotSessions,0,100) as $s): ?>
                <article class="entity-card">
                    <span class="badge green"><?= h($s['robotName'] ?? 'Индексирующий бот') ?></span>
                    <div class="entity-value"><?= h($s['ip'] ?? '') ?></div>
                    <div class="facts">
                        <div><b>Запросов</b><span><?= (int)($s['requestCount'] ?? 0) ?></span></div>
                        <div><b>Первый</b><span><?= h($s['firstSeen'] ?? '') ?></span></div>
                        <div><b>Последний</b><span><?= h($s['lastSeen'] ?? '') ?></span></div>
                    </div>
                </article>
            <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>
</section>

<div class="panel">
    <h2>ℹ️ Как читать результат</h2>
    <div class="hint">
        <b>Уже заблокирован</b> — в логе есть реальное событие блокировки.<br>
        <b>К блокировке</b> — CAPTCHA показывалась <?= (int)$minCaptchaAttempts ?>+ раз, но успешного прохождения нет.<br>
        <b>CAPTCHA не завершена</b> — проверка показана, но пока нет успеха; это ещё не доказательство нарушения.<br>
        <b>CAPTCHA пройдена</b> — успешное прохождение зафиксировано.<br>
        <b>Fingerprint</b> связывает обращения с одного и того же отпечатка даже при смене IP.
    </div>
</div>

<footer>
    AntiBot Analyzer Simple Action View · <?= h($lastModified) ?> · Порог CAPTCHA: <?= (int)$minCaptchaAttempts ?>
</footer>
</div>

<script>
(function(){
    const tabs=document.querySelectorAll('.tab');
    const contents=document.querySelectorAll('.tab-content');
    tabs.forEach(btn=>{
        btn.addEventListener('click',()=>{
            tabs.forEach(x=>x.classList.remove('active'));
            btn.classList.add('active');
            contents.forEach(x=>x.hidden=true);
            const target=document.getElementById('tab-'+btn.dataset.tab);
            if(target) target.hidden=false;
            history.replaceState(null,'','#'+btn.dataset.tab);
        });
    });

    const hash=location.hash.replace('#','');
    if(hash){
        const btn=document.querySelector('.tab[data-tab="'+hash+'"]');
        if(btn) btn.click();
    }

    document.addEventListener('click',async e=>{
        const btn=e.target.closest('.copy');
        if(!btn) return;
        const value=btn.dataset.copy||'';
        try{
            await navigator.clipboard.writeText(value);
            const old=btn.textContent;
            btn.textContent='✓ Скопировано';
            setTimeout(()=>btn.textContent=old,900);
        }catch(err){
            const ta=document.createElement('textarea');
            ta.value=value; document.body.appendChild(ta); ta.select();
            document.execCommand('copy'); ta.remove();
        }
    });
})();
</script>
</body>
</html>