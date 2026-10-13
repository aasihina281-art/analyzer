<?php
/**
 * AntiBot Analyzer v3 — behavioral visitor risk dashboard.
 *
 * Key idea: passing a CAPTCHA does NOT make a visitor good. Behavioral bots
 * solve captchas too and then hammer the SAME page again and again (even
 * daily) with machine-like regularity — this hurts Yandex metrics and
 * distorts analytics. This dashboard detects such visitors by behavior:
 *
 *  - repeated hits on one URL from one FP/IP (incl. across different days)
 *  - mechanical periodicity of request intervals (low CV, exact repeats)
 *  - suspiciously fast captcha solves, zero screen FPS, UA churn
 *  - fingerprint rotation across many IPs
 *
 * Each entity gets a 0..100 risk score and a verdict (ok/watch/suspect/block).
 *
 * Optimizations:
 *  - single-pass streaming log parser (bounded memory)
 *  - analytics cache keyed by log size+mtime (no re-parse on refresh)
 *  - server-side pagination + chart data precomputed in PHP
 *  - responsive CSS (mobile-first), no external JS/CSS dependencies
 */

declare(strict_types=1);

require_once __DIR__ . '/auth.php';
analyzerRequireLogin();

require_once __DIR__ . '/includes/parser.php';
require_once __DIR__ . '/includes/risk.php';
require_once __DIR__ . '/includes/cache.php';

/* ------------------------------------------------------------------ *
 * Blocking actions (unchanged security model)
 * ------------------------------------------------------------------ */

function analyzerActionAuthorized(): bool {
    return analyzerIsAuthenticated();
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
    return (bool)preg_match('/^[a-f0-9]{16,128}$/i', $fp);
}

function analyzerListCandidates(string $logFile, string $listName): array {
    $candidates = [];
    $logDir = dirname($logFile);
    $root = basename($logDir) === 'logs' ? dirname($logDir) : $logDir;

    $candidates[] = dirname(__DIR__) . '/antibot/lists/' . $listName;
    $candidates[] = $root . '/lists/' . $listName;
    $candidates[] = __DIR__ . '/../antibot/lists/' . $listName;

    return array_values(array_unique($candidates));
}

function analyzerFindOrCreateList(string $logFile, string $listName): ?string {
    foreach (analyzerListCandidates($logFile, $listName) as $path) {
        if (is_file($path) && is_readable($path) && is_writable($path)) {
            return $path;
        }
    }

    $logDir = dirname($logFile);
    $root = basename($logDir) === 'logs' ? dirname($logDir) : $logDir;
    $dir = $root . '/lists';
    if (!is_dir($dir)) return null;

    $path = $dir . '/' . $listName;
    if (!file_exists($path)) {
        $header = $listName === 'blacklist_ip'
            ? "# blacklist_ip\n# Черный список IP-адресов\n# Формат: IP # комментарий\n"
            : "# blacklist_fingerprint\n# Список FingerPrint\n# Символ # используется как комментарий.\n";
        if (@file_put_contents($path, $header, LOCK_EX) === false) return null;
    }

    return is_writable($path) ? $path : null;
}

function analyzerAddToList(string $path, string $value, string $comment): array {
    if (!is_writable($path)) {
        return ['ok' => false, 'message' => 'Файл списка недоступен для записи: ' . $path];
    }
    $handle = fopen($path, 'c+');
    if (!$handle) return ['ok' => false, 'message' => 'Не удалось открыть blacklist для записи.'];

    try {
        if (!flock($handle, LOCK_EX)) {
            return ['ok' => false, 'message' => 'Не удалось заблокировать файл списка.'];
        }
        rewind($handle);
        $content = stream_get_contents($handle);
        foreach (preg_split('/\R/', (string)$content) as $line) {
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
            if (fread($handle, 1) !== "\n") fwrite($handle, PHP_EOL);
            fseek($handle, 0, SEEK_END);
        }
        fwrite($handle, $value . ' # ' . date('Y-m-d H:i:s') . ' ' . $comment . PHP_EOL);
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
    $comment = 'Added from AntiBot Analyzer (behavioral risk)';

    if ($action === 'ip' || $action === 'both') {
        if (!analyzerValidateIP($ip)) return ['ok' => false, 'message' => 'Некорректный IP-адрес.'];
        $path = analyzerFindOrCreateList($logFile, 'blacklist_ip');
        if ($path === null) return ['ok' => false, 'message' => 'Не найден или недоступен lists/blacklist_ip.'];
        $results[] = ['target' => 'IP', 'value' => $ip] + analyzerAddToList($path, $ip, $comment);
    }
    if ($action === 'fingerprint' || $action === 'both') {
        if (!analyzerValidateFingerprint($fp)) return ['ok' => false, 'message' => 'Некорректный Fingerprint.'];
        $path = analyzerFindOrCreateList($logFile, 'blacklist_fingerprint');
        if ($path === null) return ['ok' => false, 'message' => 'Не найден или недоступен lists/blacklist_fingerprint.'];
        $results[] = ['target' => 'Fingerprint', 'value' => $fp] + analyzerAddToList($path, $fp, $comment);
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

/* ------------------------------------------------------------------ *
 * Locate log file
 * ------------------------------------------------------------------ */

$antiBotRoot = dirname(__DIR__) . '/antibot';
$logCandidates = [
    getenv('ANTIBOT_LOG') ?: '',
    $antiBotRoot . '/logs/antibot.log',
    $antiBotRoot . '/antibot.log',
    __DIR__ . '/antibot.log',
    dirname(__DIR__) . '/antibot.log',
];

$logFile = null;
foreach ($logCandidates as $candidate) {
    if ($candidate !== '' && is_file($candidate) && is_readable($candidate)) {
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
        body{margin:0;background:#0b1120;color:#e5e7eb;font-family:system-ui,Arial,sans-serif}
        .box{max-width:760px;margin:10vh auto;padding:28px;background:#111827;border:1px solid #374151;border-radius:16px}
        code{display:block;margin:12px 0;padding:12px;background:#030712;border-radius:8px;overflow:auto;color:#93c5fd}
        h1{color:#f87171}
    </style>
</head><body><div class="box">
    <h1>Лог AntiBot не найден</h1>
    <p>Analyzer ищет <b>antibot.log</b> в следующих местах:</p>
    <?php foreach ($logCandidates as $candidate): if ($candidate === '') continue; ?>
        <code><?= htmlspecialchars($candidate, ENT_QUOTES, 'UTF-8') ?></code>
    <?php endforeach; ?>
    <p>Можно указать путь явно через переменную окружения <code>ANTIBOT_LOG</code>.</p>
</div></body></html>
    <?php
    exit;
}

/* ------------------------------------------------------------------ *
 * Cache location (needed also for invalidation after blocking)
 * ------------------------------------------------------------------ */

$cacheDir = dirname($logFile);
if (!is_writable($cacheDir)) $cacheDir = __DIR__ . '/cache';
if (!is_dir($cacheDir)) @mkdir($cacheDir, 0700, true);
$cacheDirForInvalidate = $cacheDir;

/* ------------------------------------------------------------------ *
 * Handle POST block actions
 * ------------------------------------------------------------------ */

$actionMessage = $_SESSION['antibot_analyzer_flash']['message'] ?? null;
$actionError = !empty($_SESSION['antibot_analyzer_flash']['error']);
unset($_SESSION['antibot_analyzer_flash']);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['analyzer_action'])) {
    $csrf = (string)($_POST['csrf'] ?? '');

    if (!hash_equals(analyzerActionToken(), $csrf)) {
        $actionMessage = 'Сессия безопасности истекла. Обновите страницу.';
        $actionError = true;
    } elseif (!analyzerActionAuthorized()) {
        $actionMessage = 'Действие запрещено: анализатор должен быть защищён авторизацией.';
        $actionError = true;
    } else {
        $action = (string)$_POST['analyzer_action'];
        $ip = trim((string)($_POST['ip'] ?? ''));
        $fp = trim((string)($_POST['fingerprint'] ?? ''));

        $result = analyzerPerformBlock($logFile, $action, $ip, $fp);
        $actionMessage = $result['message'] ?? 'Готово.';
        $actionError = empty($result['ok']);

        if (!empty($result['results'])) {
            $parts = [];
            foreach ($result['results'] as $item) {
                $parts[] = $item['target'] . ': ' . ($item['added'] ? 'добавлен' : 'уже заблокирован');
            }
            $actionMessage .= ' ' . implode(' · ', $parts);
        }
        // Invalidate analytics cache (blacklist membership affects verdicts)
        foreach ([$cacheDirForInvalidate] as $__d) {
            @unlink($__d . '/analytics-' . md5($logFile) . '.json');
        }
    }
}

/* ------------------------------------------------------------------ *
 * Query parameters
 * ------------------------------------------------------------------ */

$timeFrom   = isset($_GET['from']) ? trim((string)$_GET['from']) : '';
$timeTo     = isset($_GET['to']) ? trim((string)$_GET['to']) : '';
$searchTerm = isset($_GET['search']) ? trim((string)$_GET['search']) : '';
$view       = (string)($_GET['view'] ?? 'risk');
if (!in_array($view, ['risk', 'blocked', 'pending', 'passed', 'robots', 'all'], true)) $view = 'risk';
$minRisk    = max(0, min(100, (int)($_GET['minrisk'] ?? 40)));
$page       = max(1, (int)($_GET['page'] ?? 1));
$perPage    = 30;
$nocache    = !empty($_GET['fresh']);

/* ------------------------------------------------------------------ *
 * Parse + score (with cache)
 * ------------------------------------------------------------------ */

$cache = new AnalyzerCache($cacheDir);

$blackIps = analyzerReadBlacklist($logFile, 'blacklist_ip');
$blackFps = analyzerReadBlacklist($logFile, 'blacklist_fingerprint');

$cached = $nocache ? null : $cache->get($logFile);
$parseMs = null;

if ($cached !== null && isset($cached['entities'], $cached['charts'], $cached['stats'])) {
    $entities = $cached['entities'];
    $chartData = $cached['charts'];
    $stats = $cached['stats'];
    $robotSessions = $cached['robotSessions'] ?? [];
    $fromCache = true;
} else {
    $t0 = microtime(true);
    $parsed = AntiBotLogParser::parseFile(
        $logFile,
        $timeFrom !== '' ? $timeFrom : null,
        $timeTo !== '' ? $timeTo : null,
        $searchTerm !== '' ? $searchTerm : null
    );
    $sessions = $parsed['sessions'];

    $scorer = new RiskScorer($blackIps, $blackFps);
    $entities = $scorer->buildEntities($sessions);

    // Robots / whitelist lists kept for their tabs
    $robotSessions = [];
    $whitelistCount = 0;
    foreach ($sessions as $s) {
        if (!empty($s['isRobot'])) $robotSessions[] = $s;
        if (!empty($s['isWhitelisted'])) $whitelistCount++;
    }

    /* ---------- Global chart data (single aggregation pass) ---------- */

    // Timeline buckets over all requests
    $bucketCounts = [];      // label => total
    $badBucketCounts = [];   // label => risky requests

    // day-of-week & hour heat over all sessions' request times
    $heat = array_fill(0, 7, array_fill(0, 24, 0));
    $topUrlAgg = [];
    $riskDist = ['ok' => 0, 'watch' => 0, 'suspect' => 0, 'block' => 0, 'blocked' => 0];

    foreach (['ip', 'fp'] as $type) {
        foreach ($entities[$type] as $key => $e) {
            if ($type === 'ip' && !empty($e['fps'])) continue; // FP covers this IP
            $riskDist[$e['riskVerdict']] = ($riskDist[$e['riskVerdict']] ?? 0) + 1;
        }
    }

    // Re-walk sessions only for cheap global aggregates (already parsed arrays)
    foreach ($sessions as $s) {
        if (!empty($s['isRobot'])) continue;
        $ip = $s['ip'];
        $isBad = false;
        if (isset($entities['fp'])) {
            foreach ($s['fingerprints'] as $fp) {
                $v = $entities['fp'][$fp]['riskVerdict'] ?? null;
                if ($v === 'block' || $v === 'suspect' || $v === 'blocked') $isBad = true;
            }
        }
        if (!$isBad) {
            $v = $entities['ip'][$ip]['riskVerdict'] ?? null;
            if ($v === 'block' || $v === 'suspect' || $v === 'blocked') $isBad = true;
        }

        foreach ($s['requestTimes'] as $ts) {
            $label = substr($ts, 0, 13) . ':00';
            $bucketCounts[$label] = ($bucketCounts[$label] ?? 0) + 1;
            if ($isBad) $badBucketCounts[$label] = ($badBucketCounts[$label] ?? 0) + 1;

            $dow = (int)date('N', strtotime(str_replace(' ', 'T', $ts)));
            $hour = (int)substr($ts, 11, 2);
            $heat[$dow - 1][$hour]++;
        }
        foreach ($s['urls'] as $u) {
            $u = (string)$u;
            $u = preg_replace('/\?.*$/', '', $u);
            if ($u === '') continue;
            $topUrlAgg[$u] = ($topUrlAgg[$u] ?? 0) + 1;
        }
    }
    unset($sessions);
    ksort($bucketCounts, SORT_STRING);
    ksort($badBucketCounts, SORT_STRING);

    // Downsample timeline to <= 96 points
    $labels = array_keys($bucketCounts);
    $step = max(1, (int)ceil(count($labels) / 96));
    $timeline = [];
    $acc = 0; $accBad = 0; $accLabel = null; $flushCounter = 0;
    foreach ($bucketCounts as $label => $cnt) {
        if ($accLabel === null) $accLabel = $label;
        $acc += $cnt;
        $accBad += $badBucketCounts[$label] ?? 0;
        $flushCounter++;
        if ($flushCounter % $step === 0) {
            $timeline[] = ['t' => substr((string)$accLabel, 0, 13), 'total' => $acc, 'bad' => $accBad];
            $acc = 0; $accBad = 0; $accLabel = null;
        }
    }
    if ($acc > 0) $timeline[] = ['t' => substr((string)$accLabel, 0, 13), 'total' => $acc, 'bad' => $accBad];

    arsort($topUrlAgg);
    $topUrls = [];
    foreach (array_slice($topUrlAgg, 0, 10, true) as $u => $c) {
        $topUrls[] = ['url' => $u, 'count' => $c];
    }

    $chartData = [
        'timeline' => $timeline,
        'heat' => $heat,
        'topUrls' => $topUrls,
        'riskDist' => $riskDist,
    ];

    /* ---------- Stats ---------- */

    $stats = [
        'totalRequests' => array_sum(array_map(fn($s) => (int)$s['requestCount'], $parsed['sessions'])),
        'ips' => count($entities['ip']),
        'fps' => count($entities['fp']),
        'riskBlock' => $riskDist['block'] ?? 0,
        'riskSuspect' => $riskDist['suspect'] ?? 0,
        'riskWatch' => $riskDist['watch'] ?? 0,
        'blocked' => $riskDist['blocked'] ?? 0,
        'passed' => $riskDist['ok'] ?? 0,
        'robots' => count($robotSessions),
        'whitelist' => $whitelistCount ?? 0,
        'lines' => $parsed['meta']['lines'] ?? 0,
        'sessions' => count($parsed['sessions']),
    ];

    $parseMs = round((microtime(true) - $t0) * 1000);

    // Keep robots small for the tab
    usort($robotSessions, fn($a, $b) => strcmp((string)($b['lastSeen'] ?? ''), (string)($a['lastSeen'] ?? '')));
    $robotSessions = array_slice($robotSessions, 0, 150);

    $cache->put($logFile, [
        'entities' => $entities,
        'charts' => $chartData,
        'stats' => $stats,
        'robotSessions' => $robotSessions,
    ]);
    $fromCache = false;
}

/* ------------------------------------------------------------------ *
 * Build view list
 * ------------------------------------------------------------------ */

$list = [];
foreach (['fp', 'ip'] as $type) {
    foreach ($entities[$type] as $key => $e) {
        if ($type === 'ip' && !empty($e['fps'])) continue; // shown under its FP card
        switch ($view) {
            case 'risk':
                if (in_array($e['riskVerdict'], ['block', 'suspect'], true) && $e['riskScore'] >= $minRisk) $list[] = $e;
                break;
            case 'blocked':
                if ($e['riskVerdict'] === 'blocked') $list[] = $e;
                break;
            case 'pending':
                if ($e['captchaShown'] > 0 && $e['captchaPassed'] === 0 && $e['riskVerdict'] !== 'blocked') $list[] = $e;
                break;
            case 'passed':
                if ($e['captchaPassed'] > 0 && $e['riskVerdict'] === 'ok') $list[] = $e;
                break;
            case 'all':
                $list[] = $e;
                break;
        }
    }
}

usort($list, static function (array $a, array $b): int {
    return ($b['riskScore'] <=> $a['riskScore'])
        ?: ($b['topUrlHits'] <=> $a['topUrlHits'])
        ?: strcmp((string)$b['lastSeen'], (string)$a['lastSeen']);
});

$totalItems = count($list);
$totalPages = max(1, (int)ceil($totalItems / $perPage));
$page = min($page, $totalPages);
$listPage = array_slice($list, ($page - 1) * $perPage, $perPage);

$lastModified = date('Y-m-d H:i:s', (int)filemtime($logFile));
$fileSizeMb = round(filesize($logFile) / 1024 / 1024, 2);

function h($value): string {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function fmtInt($n): string {
    return number_format((int)$n, 0, ',', ' ');
}

function viewQuery(array $overrides = []): string {
    $params = array_merge([
        'view' => $_GET['view'] ?? 'risk',
        'from' => $_GET['from'] ?? '',
        'to' => $_GET['to'] ?? '',
        'search' => $_GET['search'] ?? '',
        'minrisk' => $_GET['minrisk'] ?? '40',
    ], $overrides);
    $params = array_filter($params, static fn($v) => $v !== '' && $v !== null);
    return '?' . http_build_query($params);
}

$verdictLabels = [
    'blocked' => ['⛔ Заблокирован', 'red'],
    'block'   => ['🚫 К блокировке', 'red'],
    'suspect' => ['🟠 Опасный', 'orange'],
    'watch'   => ['🟡 Наблюдать', 'yellow'],
    'ok'      => ['🟢 Нормальный', 'green'],
];

$badgeTitles = [
    'zaprosy'  => 'Многократные повторы одной страницы',
    'dni'      => 'Повторы одной страницы по разным дням',
    'ritm'     => 'Машинная регулярность интервалов',
    'captcha'  => 'Подозрительно быстрые прохождения CAPTCHA',
    'iprotacia' => 'Один отпечаток на нескольких IP',
];

$chartJson = json_encode($chartData, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
?>
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#070b13">
<title>AntiBot Analyzer v3 — поведение посетителей</title>
<style>
:root{
  --bg:#070b13;--panel:#101827;--panel2:#0b1220;--line:#243044;--text:#edf2f7;--muted:#94a3b8;
  --red:#f87171;--orange:#fb923c;--yellow:#facc15;--green:#34d399;--blue:#60a5fa;
  --radius:14px;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,'Segoe UI',Roboto,Arial,sans-serif;line-height:1.45}
.wrap{max-width:1400px;margin:0 auto;padding:clamp(10px,2.5vw,22px)}
a{color:#93c5fd}

.header{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;flex-wrap:wrap;margin-bottom:14px}
h1{font-size:clamp(19px,3.4vw,26px);margin:0 0 4px}
.sub{color:var(--muted);font-size:12px}
.sub b{color:var(--text)}

.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:9px;margin:14px 0}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:12px}
.stat b{display:block;font-size:clamp(18px,2.6vw,24px)}
.stat span{color:var(--muted);font-size:11px}
.stat.red b{color:var(--red)}.stat.orange b{color:var(--orange)}.stat.yellow b{color:var(--yellow)}.stat.green b{color:var(--green)}

.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:clamp(12px,2vw,18px);margin-bottom:14px}
.panel h2{margin:0 0 4px;font-size:clamp(15px,2.4vw,18px)}
.hint{color:var(--muted);font-size:12px;margin-bottom:10px}

.filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;align-items:end}
.filters label{display:flex;flex-direction:column;gap:4px;color:var(--muted);font-size:11px}
.filters input,.filters select{background:#0b1220;border:1px solid var(--line);color:#fff;border-radius:8px;padding:9px 10px;font-size:13px;min-width:0;width:100%}
.filters button{background:#2563eb;color:#fff;border:0;border-radius:8px;padding:10px 14px;cursor:pointer;font-size:13px}
.filters button.secondary{background:#1e293b;color:#cbd5e1}

.tabs{display:flex;gap:6px;flex-wrap:wrap;margin:14px 0}
.tab{border:1px solid var(--line);background:var(--panel);color:#cbd5e1;padding:9px 12px;border-radius:10px;cursor:pointer;font-size:12px;text-decoration:none;display:inline-block}
.tab.active{border-color:#64748b;background:#172033;color:#fff}
@media(max-width:640px){.tab{flex:1 1 45%;text-align:center;padding:10px 6px;font-size:11px}}

.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,340px),1fr));gap:12px;margin-bottom:14px}
.chart-card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:14px;min-width:0}
.chart-card h3{margin:0 0 2px;font-size:14px}
.chart-card .hint{margin-bottom:8px}
.chart-scroll{width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch}
.chart-svg{display:block;width:100%;height:auto;min-width:320px}
.chart-legend{display:flex;gap:12px;flex-wrap:wrap;margin-top:8px;color:var(--muted);font-size:11px}
.chart-legend i{display:inline-block;width:9px;height:9px;border-radius:3px;margin-right:4px}
.donut-wrap{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
.donut{width:130px;height:130px;flex:0 0 auto}
.donut-legend{font-size:12px;display:grid;gap:4px}
.donut-legend b{display:inline-block;min-width:26px}
.heat-table{border-collapse:separate;border-spacing:2px;font-size:9px;width:100%}
.heat-table th{color:var(--muted);font-weight:500;text-align:center;padding:2px}
.heat-table td{width:auto;min-width:14px;height:16px;border-radius:3px}
.top-url-row{display:grid;grid-template-columns:1fr auto;gap:8px;align-items:center;font-size:11px;padding:4px 0;border-bottom:1px solid #172033}
.top-url-row:last-child{border-bottom:0}
.top-url-row code{color:#93c5fd;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block}
.top-url-bar{height:6px;border-radius:4px;background:#1e293b;position:relative;margin-top:3px}
.top-url-bar i{position:absolute;left:0;top:0;bottom:0;border-radius:4px;background:#38bdf8}

.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,420px),1fr));gap:11px}
.entity-card{background:var(--panel2);border:1px solid var(--line);border-radius:var(--radius);padding:14px;min-width:0}
.entity-top{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}
.entity-value{font:700 clamp(13px,1.8vw,15px)/1.3 ui-monospace,SFMono-Regular,Consolas,monospace;margin-top:7px;word-break:break-all}
.entity-type{font-size:11px;color:var(--muted);margin-top:2px}
.badge{display:inline-block;border-radius:999px;padding:4px 8px;font-size:10px;font-weight:800;letter-spacing:.03em;white-space:nowrap}
.badge.red{background:#3a1418;color:#fca5a5}.badge.orange{background:#3b2110;color:#fdba74}
.badge.yellow{background:#382f08;color:#fde68a}.badge.green{background:#0d3328;color:#6ee7b7}
.badge.blue{background:#12283f;color:#93c5fd}
.sig{display:inline-block;background:#182235;color:#cbd5e1;border-radius:6px;padding:3px 7px;margin:3px 3px 0 0;font-size:10px}

.risk-gauge{flex:0 0 auto;text-align:center}
.risk-num{font-size:22px;font-weight:800;line-height:1}
.risk-lbl{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}

.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(86px,1fr));gap:6px;margin:12px 0}
.facts div{background:#111a2a;border-radius:8px;padding:7px 8px}
.facts b{display:block;color:#7f8da3;font-size:9px;text-transform:uppercase}
.facts span{display:block;margin-top:2px;font-size:12px;font-weight:600}
.facts span.warn{color:var(--orange)}
.facts span.bad{color:var(--red)}

.reason{border-left:3px solid #7c3aed;background:#111827;padding:8px 10px;margin-top:8px;font-size:11.5px;color:#e2e8f0;border-radius:0 8px 8px 0}
.reason ul{margin:4px 0 0;padding-left:16px}
.linked{margin-top:10px;font-size:12px;color:#cbd5e1}
.token,.copy{font:inherit;border:0;cursor:pointer}
.token{display:inline-block;background:#182235;color:#93c5fd;border-radius:6px;padding:4px 6px;margin:3px 3px 0 0;font-family:ui-monospace,Consolas,monospace;font-size:10.5px;max-width:100%;overflow:hidden;text-overflow:ellipsis;vertical-align:middle}
.copy{background:#182235;color:#cbd5e1;border-radius:7px;padding:7px 9px;font-size:11px}
.copy:hover,.token:hover{background:#24334d}
.meta{margin-top:10px;color:#64748b;font-size:10.5px}
.muted{color:#64748b}
.url-hit{font-size:11px;color:#cbd5e1;margin-top:6px;word-break:break-all}
.url-hit code{color:#93c5fd}

.actions{display:flex;gap:7px;flex-wrap:wrap;margin-top:12px;padding-top:10px;border-top:1px solid var(--line)}
.actions form{margin:0}
.action{border:0;border-radius:8px;padding:9px 11px;color:#fff;font-size:11px;font-weight:700;cursor:pointer}
.ip-action{background:#b91c1c}.fp-action{background:#c2410c}.both-action{background:#7c3aed}
.action:hover{filter:brightness(1.12)}
.action:active{transform:translateY(1px)}
.history-btn{background:#182235;color:#cbd5e1;border:0;border-radius:7px;padding:9px 10px;font-size:11px;cursor:pointer}
.history-btn:hover{background:#24334d}

.action-result{margin-bottom:14px;border-radius:10px;padding:12px 14px;font-size:13px;border:1px solid}
.action-result.success{background:#0d3328;color:#a7f3d0;border-color:#166534}
.action-result.error{background:#3a1418;color:#fecaca;border-color:#991b1b}
.empty{padding:30px 14px;text-align:center;color:#64748b;background:var(--panel2);border:1px dashed var(--line);border-radius:12px}

.pager{display:flex;gap:6px;justify-content:center;flex-wrap:wrap;margin:16px 0}
.pager a,.pager span{background:var(--panel);border:1px solid var(--line);color:#cbd5e1;border-radius:8px;padding:8px 12px;font-size:12px;text-decoration:none}
.pager .cur{background:#1d4ed8;border-color:#60a5fa;color:#fff}

footer{color:#64748b;font-size:11px;text-align:center;padding:12px 0 calc(12px + env(safe-area-inset-bottom))}

/* history panel (loaded per card) */
.history-panel{display:none;margin-top:12px;border-top:1px solid #243044;padding-top:10px}
.history-panel.open{display:block}
.history-list{max-height:380px;overflow:auto;background:#080d16;border:1px solid #243044;border-radius:10px}
.history-event{display:grid;grid-template-columns:minmax(110px,auto) 60px 1fr;gap:6px;padding:7px 9px;border-bottom:1px solid #172033;font-size:10.5px}
.history-event:last-child{border-bottom:0}
.history-event time{color:#94a3b8;font-family:ui-monospace,Consolas,monospace}
.history-kind{font-size:9px;font-weight:800;color:#93c5fd}
.history-kind.request{color:#6ee7b7}.history-kind.captcha{color:#fde68a}.history-kind.block{color:#fca5a5}
.history-event code{white-space:pre-wrap;overflow-wrap:anywhere;color:#e2e8f0}
.history-loading,.history-error{padding:10px;color:#94a3b8;font-size:11px}
.history-error{color:#fca5a5}
.mini-hist{margin-top:8px}
.mini-hist svg{width:100%;height:auto;display:block}

@media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style>
</head>
<body>
<div class="wrap">

<?php if ($actionMessage !== null): ?>
<div class="action-result <?= $actionError ? 'error' : 'success' ?>"> <?= h($actionMessage) ?></div>
<?php endif; ?>

<header class="header">
    <div>
        <h1>🛡 AntiBot Analyzer <span style="color:#60a5fa">v3</span></h1>
        <div class="sub">Поведенческий анализ посетителей: прошёл CAPTCHA ≠ хороший посетитель.</div>
    </div>
    <div class="sub" style="text-align:right">
        Лог: <b><?= h(basename($logFile)) ?></b> · <?= h($fileSizeMb) ?> MB · <?= h($lastModified) ?><br>
        <?php if (!empty($fromCache)): ?>
            данные из кэша <a href="<?= h(viewQuery(['fresh' => 1])) ?>">обновить принудительно</a>
        <?php elseif ($parseMs !== null): ?>
            разбор за <?= (int)$parseMs ?> мс
        <?php endif; ?>
    </div>
</header>

<div class="panel">
<form class="filters" method="get">
    <input type="hidden" name="view" value="<?= h($view) ?>">
    <label>С даты<input type="text" inputmode="datetime" name="from" placeholder="2026-10-01 00:00" value="<?= h($timeFrom) ?>"></label>
    <label>По дату<input type="text" inputmode="datetime" name="to" placeholder="2026-10-13 23:59" value="<?= h($timeTo) ?>"></label>
    <label>Поиск (IP / FP / URL)<input type="search" name="search" placeholder="например 134.122.40" value="<?= h($searchTerm) ?>"></label>
    <label>Мин. риск (0–100)<input type="number" min="0" max="100" step="5" name="minrisk" value="<?= (int)$minRisk ?>"></label>
    <button type="submit">Применить</button>
    <button type="submit" formaction="<?= h(viewQuery(['from'=>'','to'=>'','search'=>'','page'=>''])) ?>" class="secondary" formnovalidate>Сброс</button>
</form>
</div>

<div class="grid">
    <div class="stat red"><b><?= fmtInt($stats['riskBlock'] ?? 0) ?></b><span>К блокировке (риск ≥60)</span></div>
    <div class="stat orange"><b><?= fmtInt($stats['riskSuspect'] ?? 0) ?></b><span>Опасные (40–59)</span></div>
    <div class="stat yellow"><b><?= fmtInt($stats['riskWatch'] ?? 0) ?></b><span>Наблюдать (20–39)</span></div>
    <div class="stat red"><b><?= fmtInt($stats['blocked'] ?? 0) ?></b><span>Уже заблокированы</span></div>
    <div class="stat green"><b><?= fmtInt($stats['passed'] ?? 0) ?></b><span>Нормальные</span></div>
    <div class="stat"><b><?= fmtInt($stats['totalRequests'] ?? 0) ?></b><span>Запросов всего</span></div>
    <div class="stat"><b><?= fmtInt($stats['ips'] ?? 0) ?></b><span>IP</span></div>
    <div class="stat"><b><?= fmtInt($stats['fps'] ?? 0) ?></b><span>Fingerprint</span></div>
</div>

<!-- Charts -->
<div class="charts">
    <div class="chart-card" style="grid-column:1/-1">
        <h3>📈 Трафик по времени: весь против «плохих» визитеров</h3>
        <div class="hint">Каждый HTTP-запрос из antibot.log. Красным выделены запросы сущностей с вердиктом «опасный/к блокировке/заблокирован» — именно они искажают метрики Яндекса.</div>
        <div class="chart-scroll"><svg id="chart-timeline" class="chart-svg" viewBox="0 0 960 260" role="img" aria-label="График трафика по времени"></svg></div>
        <div class="chart-legend"><span><i style="background:#38bdf8"></i>Весь трафик</span><span><i style="background:#ef4444"></i>Плохие визитеры</span></div>
    </div>

    <div class="chart-card">
        <h3>🍩 Распределение риска</h3>
        <div class="hint">Доли сущностей (IP без FP + все FP) по вердикту анализатора.</div>
        <div class="donut-wrap">
            <svg id="chart-donut" class="donut" viewBox="0 0 42 42" role="img" aria-label="Распределение риска"></svg>
            <div class="donut-legend" id="donut-legend"></div>
        </div>
    </div>

    <div class="chart-card">
        <h3>🔥 Активность по дням и часам</h3>
        <div class="hint">Пн–Вс × 0–23 ч. Ровная «полоса» в ночные часы — признак автоматизированного обхода.</div>
        <div class="chart-scroll" id="chart-heat"></div>
    </div>

    <div class="chart-card" style="grid-column:1/-1">
        <h3>🎯 Самые запрашиваемые страницы</h3>
        <div class="hint">Топ-10 URL по общему числу запросов. Повтор одного URL одним посетителем подсвечивается в карточках ниже.</div>
        <div id="chart-topurls"></div>
    </div>
</div>

<!-- Tabs -->
<div class="tabs">
    <a class="tab <?= $view==='risk'?'active':'' ?>" href="<?= h(viewQuery(['view'=>'risk','page'=>''])) ?>">🔴 Плохие визитеры (<?= (int)(($stats['riskBlock']??0)+($stats['riskSuspect']??0)) ?>)</a>
    <a class="tab <?= $view==='blocked'?'active':'' ?>" href="<?= h(viewQuery(['view'=>'blocked','page'=>''])) ?>">⛔ Заблокированы (<?= (int)($stats['blocked']??0) ?>)</a>
    <a class="tab <?= $view==='pending'?'active':'' ?>" href="<?= h(viewQuery(['view'=>'pending','page'=>''])) ?>">🟡 CAPTCHA не завершена</a>
    <a class="tab <?= $view==='passed'?'active':'' ?>" href="<?= h(viewQuery(['view'=>'passed','page'=>''])) ?>">🟢 Хорошие посетители</a>
    <a class="tab <?= $view==='robots'?'active':'' ?>" href="<?= h(viewQuery(['view'=>'robots','page'=>''])) ?>">🤖 Поисковые боты (<?= (int)($stats['robots']??0) ?>)</a>
    <a class="tab <?= $view==='all'?'active':'' ?>" href="<?= h(viewQuery(['view'=>'all','page'=>''])) ?>">📋 Все</a>
</div>

<?php if ($view === 'robots'): ?>
    <div class="panel">
        <h2>🤖 Индексирующие боты</h2>
        <div class="hint">Легальные поисковые роботы — они не попадают в списки блокировки.</div>
        <?php if (!$robotSessions): ?><div class="empty">Индексирующих ботов не найдено.</div><?php else: ?>
        <div class="cards">
            <?php foreach (array_slice($robotSessions,0,60) as $s): ?>
            <article class="entity-card">
                <span class="badge blue"><?= h($s['robotName'] ?: 'Индексирующий бот') ?></span>
                <div class="entity-value"><?= h($s['ip']) ?></div>
                <div class="facts">
                    <div><b>Запросов</b><span><?= (int)$s['requestCount'] ?></span></div>
                    <div><b>URL</b><span><?= count($s['urls']) ?></span></div>
                    <div><b>Последний</b><span style="font-size:10px"><?= h(substr((string)$s['lastSeen'],5,11)) ?></span></div>
                </div>
            </article>
            <?php endforeach; ?>
        </div><?php endif; ?>
    </div>
<?php else: ?>
    <div class="panel">
        <h2><?php
            echo match($view) {
                'risk' => '🔴 Плохие визитеры — рекомендуются к блокировке',
                'blocked' => '⛔ Уже заблокированы',
                'pending' => '🟡 CAPTCHA показана, но не завершена',
                'passed' => '🟢 Посетители, прошедшие проверку без аномалий',
                default => '📋 Все сущности',
            };
        ?></h2>
        <div class="hint">
            <?php if ($view === 'risk'): ?>
                Оценка строится на <b>поведении после</b> прохождения CAPTCHA: повторы одной страницы (в т.ч. ежедневно), машинная периодичность интервалов, мгновенные решения капчи, ротация IP у одного отпечатка. Порог показа: риск ≥ <?= (int)$minRisk ?>.
            <?php elseif ($view === 'pending'): ?>
                Один незавершённый показ CAPTCHA — не основание для блокировки: пользователь мог закрыть страницу. Но систематические незавершённые проверки — сигнал.
            <?php endif; ?>
            Всего в выборке: <b><?= fmtInt($totalItems) ?></b> · страница <?= (int)$page ?> из <?= (int)$totalPages ?>.
        </div>

        <?php if (!$listPage): ?>
            <div class="empty">Нет сущностей, подходящих под текущий фильтр.</div>
        <?php else: ?>
        <div class="cards">
        <?php foreach ($listPage as $item):
            [$vl, $vc] = $verdictLabels[$item['riskVerdict']] ?? ['—','green'];
            $isFp = $item['type'] === 'fp';
            $actionIp = $isFp ? ($item['ips'][0] ?? '') : $item['value'];
            $actionFp = $isFp ? $item['value'] : ($item['fps'][0] ?? '');
            $iv = $item['intervals'];
        ?>
        <article class="entity-card" data-entity-type="<?= h($item['type']) ?>" data-entity-value="<?= h($item['value']) ?>">
            <div class="entity-top">
                <div style="min-width:0">
                    <span class="badge <?= h($vc) ?>"><?= h($vl) ?></span>
                    <?php if ($item['captchaPassed'] > 0): ?><span class="badge green">CAPTCHA пройдена ✓</span><?php endif; ?>
                    <?php if (!empty($item['inBlacklist'])): ?><span class="badge red">В BLACKLIST</span><?php endif; ?>
                    <div class="entity-value"><?= h($item['value']) ?></div>
                    <div class="entity-type"><?= $isFp ? 'Fingerprint' : 'IP-адрес' ?> · сессий: <?= (int)$item['sessions'] ?></div>
                    <?php foreach ($item['riskBadges'] as $b): ?>
                        <span class="sig" title="<?= h($badgeTitles[$b] ?? $b) ?>"><?= h($badgeTitles[$b] ?? $b) ?></span>
                    <?php endforeach; ?>
                </div>
                <div class="risk-gauge">
                    <svg width="64" height="64" viewBox="0 0 42 42" aria-hidden="true">
                        <circle cx="21" cy="21" r="15.9" fill="none" stroke="#1e293b" stroke-width="5"/>
                        <circle cx="21" cy="21" r="15.9" fill="none"
                            stroke="<?= $item['riskScore']>=60?'#ef4444':($item['riskScore']>=40?'#fb923c':($item['riskScore']>=20?'#facc15':'#34d399')) ?>"
                            stroke-width="5" stroke-linecap="round"
                            stroke-dasharray="<?= (float)$item['riskScore'] ?> <?= 100 - (int)$item['riskScore'] ?>"
                            stroke-dashoffset="25"/>
                    </svg>
                    <div class="risk-num" style="margin-top:-46px"><?= (int)$item['riskScore'] ?></div>
                    <div class="risk-lbl" style="margin-top:26px">риск</div>
                </div>
            </div>

            <div class="facts">
                <div><b>Запросов</b><span class="<?= $item['requests']>=50?'bad':($item['requests']>=20?'warn':'') ?>"><?= fmtInt($item['requests']) ?></span></div>
                <div><b>Топ URL ×</b><span class="<?= $item['topUrlHits']>=25?'bad':($item['topUrlHits']>=12?'warn':'') ?>"><?= (int)$item['topUrlHits'] ?></span></div>
                <div><b>Дней с повтором</b><span class="<?= $item['topUrlDays']>=3?'bad':($item['topUrlDays']>=2?'warn':'') ?>"><?= (int)$item['topUrlDays'] ?></span></div>
                <div><b>Уникал. URL</b><span><?= (int)$item['uniqueUrls'] ?></span></div>
                <div><b>Медиана инт.</b><span class="<?= ($iv['median']!==null&&$iv['median']<10)?'warn':'' ?>"><?= $iv['median']!==null ? h((string)$iv['median']).' с' : '—' ?></span></div>
                <div><b>Ровность CV</b><span class="<?= ($iv['cv']!==null&&$iv['cv']<0.5)?'bad':'' ?>"><?= $iv['cv']!==null ? h((string)$iv['cv']) : '—' ?></span></div>
                <div><b>CAPTCHA пок/прош</b><span><?= (int)$item['captchaShown'] ?>/<?= (int)$item['captchaPassed'] ?></span></div>
                <div><b>Быстрых реш. ≤3с</b><span class="<?= $item['fastPasses']>=3?'bad':'' ?>"><?= (int)$item['fastPasses'] ?></span></div>
                <div><b>IP / FP / UA</b><span><?= (int)$item['ipCount'] ?>/<?= (int)$item['fpCount'] ?>/<?= (int)$item['uaCount'] ?></span></div>
            </div>

            <?php if ($item['topUrl'] !== ''): ?>
            <div class="url-hit">Чаще всего: <code><?= h($item['topUrl']) ?></code> — <?= (int)$item['topUrlHits'] ?> раз(а), <?= (int)$item['dominantUrlShare'] ?>% всего трафика сущности</div>
            <?php endif; ?>

            <?php if (!empty($item['riskReasons'])): ?>
            <div class="reason"><b>Почему такой вердикт:</b><ul>
                <?php foreach ($item['riskReasons'] as $r): ?><li><?= h($r) ?></li><?php endforeach; ?>
            </ul></div>
            <?php endif; ?>

            <?php if ($isFp && $item['ips']): ?>
            <div class="linked"><b>Связанные IP:</b>
                <?php foreach (array_slice($item['ips'],0,25) as $ip): ?>
                    <button class="token copy" data-copy="<?= h($ip) ?>"><?= h($ip) ?></button>
                <?php endforeach; ?>
                <?php if (count($item['ips'])>25): ?><span class="muted">+<?= count($item['ips'])-25 ?> ещё</span><?php endif; ?>
            </div>
            <?php endif; ?>

            <div class="mini-hist" data-hist='<?= h(json_encode(array_values($item['intervalHistogram'] ?? []))) ?>'></div>

            <div class="actions">
                <button type="button" class="history-btn">🕓 История</button>
                <button class="copy" data-copy="<?= h($item['value']) ?>">Копировать</button>
                <?php if (analyzerActionAuthorized()): ?>
                    <?php if ($isFp): ?>
                        <form method="post" onsubmit="return confirm('Заблокировать этот Fingerprint?');">
                            <input type="hidden" name="csrf" value="<?= h(analyzerActionToken()) ?>">
                            <input type="hidden" name="analyzer_action" value="fingerprint">
                            <input type="hidden" name="fingerprint" value="<?= h($actionFp) ?>">
                            <button class="action fp-action" type="submit">🚫 FP</button>
                        </form>
                        <?php if ($actionIp): ?>
                        <form method="post" onsubmit="return confirm('Заблокировать Fingerprint и связанные IP?');">
                            <input type="hidden" name="csrf" value="<?= h(analyzerActionToken()) ?>">
                            <input type="hidden" name="analyzer_action" value="both">
                            <input type="hidden" name="fingerprint" value="<?= h($actionFp) ?>">
                            <input type="hidden" name="ip" value="<?= h($actionIp) ?>">
                            <button class="action both-action" type="submit">🚫 FP + IP</button>
                        </form>
                        <?php endif; ?>
                    <?php else: ?>
                        <form method="post" onsubmit="return confirm('Заблокировать этот IP?');">
                            <input type="hidden" name="csrf" value="<?= h(analyzerActionToken()) ?>">
                            <input type="hidden" name="analyzer_action" value="ip">
                            <input type="hidden" name="ip" value="<?= h($actionIp) ?>">
                            <button class="action ip-action" type="submit">🚫 IP</button>
                        </form>
                    <?php endif; ?>
                <?php endif; ?>
            </div>

            <div class="history-panel"></div>

            <div class="meta"><?= h($item['firstSeen']) ?> → <?= h($item['lastSeen']) ?> · дней активности: <?= (int)$item['activeDays'] ?></div>
        </article>
        <?php endforeach; ?>
        </div>

        <?php if ($totalPages > 1):
            $mk = static fn(int $p): string => h(viewQuery(['page' => $p]));
        ?>
        <nav class="pager" aria-label="Страницы">
            <?php if ($page > 1): ?><a href="<?= $mk($page-1) ?>">← Назад</a><?php endif; ?>
            <?php
            $start = max(1, $page - 3); $end = min($totalPages, $page + 3);
            if ($start > 1): ?><a href="<?= $mk(1) ?>">1</a><?php if ($start > 2): ?><span>…</span><?php endif; ?><?php endif;
            for ($p = $start; $p <= $end; $p++):
                if ($p === $page): ?><span class="cur"><?= $p ?></span><?php else: ?><a href="<?= $mk($p) ?>"><?= $p ?></a><?php endif;
            endfor;
            if ($end < $totalPages): ?><?php if ($end < $totalPages-1): ?><span>…</span><?php endif; ?><a href="<?= $mk($totalPages) ?>"><?= $totalPages ?></a><?php endif; ?>
            <?php if ($page < $totalPages): ?><a href="<?= $mk($page+1) ?>">Вперёд →</a><?php endif; ?>
        </nav>
        <?php endif; ?>
        <?php endif; ?>
    </div>
<?php endif; ?>

<div class="panel">
    <h2>ℹ️ Как читать результат</h2>
    <div class="hint">
        <b>Прошёл CAPTCHA ≠ хороший посетитель.</b> Поведенческие боты решают капчу и продолжают монотонно посещать одну и ту же страницу — это портит поведенческие факторы Яндекса и искажает аналитику.<br>
        <b>Риск ≥ 60 (к блокировке)</b> — несколько независимых поведенческих сигналов: повторы одного URL (в том числе ежедневно), машинная периодичность (CV &lt; 0.25), идентичные по секундам интервалы, молниеносные решения капчи, один отпечаток на много IP.<br>
        <b>CV (коэффициент вариации)</b> — разброс интервалов между запросами. У людей он высокий (>0.8), у скриптов почти нулевой.<br>
        <b>Fingerprint</b> связывает обращения с одного отпечатка даже при смене IP — блокируйте FP, а не только IP.<br>
        <b>Поисковые боты</b> (Yandex, Google и др.) распознаются отдельно и никогда не предлагаются к блокировке.
    </div>
</div>

<footer>
    AntiBot Analyzer v3 · behavioral risk engine · <?= h($lastModified) ?>
    <?php if ($parseMs !== null): ?> · parse <?= (int)$parseMs ?> ms<?php endif; ?>
</footer>
</div>

<script>
(function(){
"use strict";
const CHARTS = <?= $chartJson ?: '{}' ?>;
const esc = s => String(s ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));

/* ---------- Timeline area chart ---------- */
function drawTimeline(){
  const svg = document.getElementById('chart-timeline');
  if(!svg) return;
  const data = CHARTS.timeline || [];
  if(data.length < 2){ svg.outerHTML = '<div class="empty" style="padding:16px">Недостаточно данных для графика времени.</div>'; return; }
  const W=960,H=260,L=44,R=10,T=12,B=40,iw=W-L-R,ih=H-T-B;
  const max=Math.max(1,...data.map(d=>d.total));
  const x=i=>L+i*iw/(data.length-1);
  const y=v=>T+ih-(v/max)*ih;
  let s='';
  const step=Math.max(1,Math.ceil(max/4));
  for(let v=0;v<=max;v+=step){
    s+='<line x1="'+L+'" y1="'+y(v)+'" x2="'+(W-R)+'" y2="'+y(v)+'" stroke="#263449"/>';
    s+='<text x="'+(L-6)+'" y="'+(y(v)+4)+'" text-anchor="end" fill="#94a3b8" font-size="10">'+v+'</text>';
  }
  const area=d=>'M'+x(0)+' '+y(0)+' '+d.map((p,i)=>'L'+x(i).toFixed(1)+' '+y(p.v).toFixed(1)).join(' ')+' L'+x(d.length-1)+' '+y(0)+' Z';
  const line=d=>d.map((p,i)=>(i?'L':'M')+x(i).toFixed(1)+' '+y(p.v).toFixed(1)).join(' ');
  const totals=data.map(d=>({v:d.total})), bads=data.map(d=>({v:d.bad||0}));
  s+='<path d="'+area(totals)+'" fill="rgba(56,189,248,.14)"/>';
  s+='<path d="'+line(totals)+'" fill="none" stroke="#38bdf8" stroke-width="2"/>';
  s+='<path d="'+area(bads)+'" fill="rgba(239,68,68,.22)"/>';
  s+='<path d="'+line(bads)+'" fill="none" stroke="#ef4444" stroke-width="2"/>';
  const lstep=Math.max(1,Math.ceil(data.length/8));
  data.forEach((d,i)=>{ if(i%lstep&&!0&&i!==data.length-1)return;
    s+='<text transform="translate('+x(i)+' '+(H-14)+')" text-anchor="middle" fill="#94a3b8" font-size="9">'+esc(String(d.t).slice(5))+'</text>';
  });
  data.forEach((d,i)=>{ s+='<rect x="'+(x(i)-iw/data.length/2).toFixed(1)+'" y="'+T+'" width="'+(iw/data.length).toFixed(1)+'" height="'+ih+'" fill="transparent"><title>'+esc(d.t)+': '+d.total+' всего · '+(d.bad||0)+' плохих</title></rect>'; });
  svg.innerHTML=s;
}

/* ---------- Donut ---------- */
function drawDonut(){
  const svg=document.getElementById('chart-donut'), leg=document.getElementById('donut-legend');
  if(!svg||!leg) return;
  const dist=CHARTS.riskDist||{};
  const items=[
    {k:'block',l:'К блокировке',c:'#ef4444'},
    {k:'suspect',l:'Опасные',c:'#fb923c'},
    {k:'watch',l:'Наблюдать',c:'#facc15'},
    {k:'blocked',l:'Уже в блоке',c:'#7f1d1d'},
    {k:'ok',l:'Нормальные',c:'#34d399'},
  ];
  const total=items.reduce((n,x)=>n+(Number(dist[x.k])||0),0)||1;
  let off=25, s='<circle cx="21" cy="21" r="15.9" fill="none" stroke="#1e293b" stroke-width="6"/>';
  let lh='';
  items.forEach(it=>{
    const v=Number(dist[it.k])||0; if(!v)return;
    const pct=v/total*100;
    s+='<circle cx="21" cy="21" r="15.9" fill="none" stroke="'+it.c+'" stroke-width="6" stroke-dasharray="'+pct.toFixed(2)+' '+(100-pct).toFixed(2)+'" stroke-dashoffset="'+off.toFixed(2)+'"><title>'+it.l+': '+v+'</title></circle>';
    off-=pct;
    lh+='<div><b style="color:'+it.c+'">'+v+'</b> · '+it.l+' ('+pct.toFixed(1)+'%)</div>';
  });
  s+='<text x="21" y="20.4" text-anchor="middle" fill="#edf2f7" font-size="6.5" font-weight="bold">'+total+'</text>';
  s+='<text x="21" y="25.5" text-anchor="middle" fill="#94a3b8" font-size="3.2">сущностей</text>';
  svg.innerHTML=s; leg.innerHTML=lh;
}

/* ---------- Heatmap day x hour ---------- */
function drawHeat(){
  const host=document.getElementById('chart-heat');
  if(!host) return;
  const heat=CHARTS.heat||[];
  if(!heat.length){host.innerHTML='<div class="empty" style="padding:14px">Нет данных.</div>';return}
  const days=['Пн','Вт','Ср','Чт','Пт','Сб','Вс'];
  let max=1; heat.forEach(r=>r.forEach(v=>{if(v>max)max=v}));
  let html='<table class="heat-table" role="img" aria-label="Активность по дням недели и часам"><thead><tr><th></th>';
  for(let h=0;h<24;h++) html+='<th>'+(h%3===0?h:'')+'</th>';
  html+='</tr></thead><tbody>';
  heat.forEach((row,i)=>{
    html+='<tr><th>'+days[i]+'</th>';
    row.forEach((v,h)=>{
      const a=v?Math.min(.95,.08+v/max*.87):.04;
      const night=(h>=1&&h<=4);
      html+='<td title="'+days[i]+' '+h+':00 — '+v+' запросов'+(night?' (ночь)':'')+'" style="background:rgba('+(night?'251,146,60':'56,189,248')+','+a+')"></td>';
    });
    html+='</tr>';
  });
  html+='</tbody></table><div class="chart-legend"><span><i style="background:#38bdf8"></i>День</span><span><i style="background:#fb923c"></i>Ночь 01–05 — подозрительно ровно = бот</span></div>';
  host.innerHTML=html;
}

/* ---------- Top URLs bars ---------- */
function drawTopUrls(){
  const host=document.getElementById('chart-topurls');
  if(!host) return;
  const urls=CHARTS.topUrls||[];
  if(!urls.length){host.innerHTML='<div class="empty" style="padding:14px">Нет запросов.</div>';return}
  const max=Math.max(...urls.map(u=>u.count));
  host.innerHTML=urls.map(u=>
    '<div class="top-url-row"><code title="'+esc(u.url)+'">'+esc(u.url)+'</code><span>'+u.count.toLocaleString('ru-RU')+'</span>'+
    '<div style="grid-column:1/-1"><div class="top-url-bar"><i style="width:'+(u.count/max*100).toFixed(1)+'%"></i></div></div></div>'
  ).join('');
}

/* ---------- Per-card interval histogram ---------- */
function drawMiniHists(){
  document.querySelectorAll('.mini-hist').forEach(el=>{
    let vals=[]; try{vals=JSON.parse(el.dataset.hist||'[]')}catch(_){}
    if(!vals.some(v=>v>0)){el.innerHTML='';return}
    const labels=['<1с','1-5','5-15','15-60','1-5м','5-15','15-60','1-6ч','6-24'];
    const W=320,H=64,P=4,bw=(W-P*(labels.length+1))/labels.length,max=Math.max(...vals,1);
    let s='<svg viewBox="0 0 '+W+' '+H+'" preserveAspectRatio="none" aria-label="Распределение интервалов между запросами">';
    vals.forEach((v,i)=>{
      const h=Math.max(v?2:0,(v/max)*(H-18));
      const color=i<=2?'#ef4444':(i<=3?'#fb923c':'#38bdf8');
      const x=P+i*(bw+P);
      s+='<rect x="'+x.toFixed(1)+'" y="'+(H-14-h).toFixed(1)+'" width="'+bw.toFixed(1)+'" height="'+h.toFixed(1)+'" rx="2" fill="'+color+'"><title>'+labels[i]+' — '+v+' интервалов</title></rect>';
      s+='<text x="'+(x+bw/2).toFixed(1)+'" y="'+(H-3)+'" text-anchor="middle" fill="#64748b" font-size="7">'+labels[i]+'</text>';
    });
    s+='</svg>';
    el.innerHTML=s;
  });
}

drawTimeline(); drawDonut(); drawHeat(); drawTopUrls(); drawMiniHists();

/* ---------- Copy buttons ---------- */
document.addEventListener('click',async e=>{
  const btn=e.target.closest('.copy');
  if(!btn) return;
  const value=btn.dataset.copy||'';
  try{ await navigator.clipboard.writeText(value); }
  catch(_){ const ta=document.createElement('textarea');ta.value=value;document.body.appendChild(ta);ta.select();document.execCommand('copy');ta.remove(); }
  const old=btn.textContent; btn.textContent='✓ Скопировано'; setTimeout(()=>btn.textContent=old,900);
});

/* ---------- History loader ---------- */
const kindLabel=k=>k==='request'?'REQ':(k||'').toUpperCase();
document.addEventListener('click',async e=>{
  const btn=e.target.closest('.history-btn');
  if(!btn) return;
  const card=btn.closest('.entity-card');
  const panel=card.querySelector('.history-panel');
  panel.classList.toggle('open');
  btn.textContent=panel.classList.contains('open')?'🕓 Скрыть историю':'🕓 История';
  if(!panel.classList.contains('open')||panel.dataset.loaded==='1')return;
  panel.innerHTML='<div class="history-loading">Загрузка истории…</div>';
  const type=card.dataset.entityType==='fp'?'fingerprint':'ip';
  const value=card.dataset.entityValue||'';
  try{
    const r=await fetch('request-history.php?type='+encodeURIComponent(type)+'&value='+encodeURIComponent(value),{credentials:'same-origin',cache:'no-store'});
    const d=await r.json(); if(!d.ok)throw new Error(d.error||'Ошибка');
    panel.dataset.loaded='1';
    let html='<div style="font-size:11px;color:#94a3b8;margin-bottom:6px">'+d.events.length+' событий · '+d.sessions+' сессий · '+d.ips.length+' IP'+(d.truncated?' · показаны последние':'')+'</div><div class="history-list">';
    if(!d.events.length)html+='<div class="history-loading">Событий не найдено.</div>';
    d.events.forEach(ev=>html+='<div class="history-event"><time>'+esc(ev.time)+'</time><span class="history-kind '+esc(ev.kind)+'">'+esc(kindLabel(ev.kind))+'</span><code>'+esc(ev.message)+'</code></div>');
    html+='</div>';
    panel.innerHTML=html;
  }catch(err){ panel.innerHTML='<div class="history-error">Не удалось загрузить историю: '+esc(err.message)+'</div>'; }
});
})();
</script>
</body>
</html>
