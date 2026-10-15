<?php
/**
 * Внутренний инструмент сверки: прогоняет анализатор (parser + risk + pf-detector)
 * на логe и выгружает те же метрики, что считает ручной эталон, в JSON.
 * Использование: php analyzer/export.php <log> [out.json]
 */
declare(strict_types=1);
require_once __DIR__ . '/includes/parser.php';
require_once __DIR__ . '/includes/risk.php';
require_once __DIR__ . '/includes/pf-detector.php';

$log = $argv[1] ?? dirname(__DIR__) . '/antibot.log';
$out = $argv[2] ?? dirname(__DIR__) . '/analyzer_out.json';

$parsed = AntiBotLogParser::parseFile($log);
$sessions = $parsed['sessions'];

$scorer = new RiskScorer([], []);
$entities = $scorer->buildEntities($sessions);
$detector = new PFCampaignDetector();
[$entities, $campaigns, $pfCharts] = $detector->detectWithEntities($entities, $sessions);

// --- Глобальные счётчики по всем merged-сессиям ---
$g = [
    'totalRequests' => 0, 'requestLines' => 0, 'blockLines' => 0,
    'captchaShowLineCount' => 0, 'captchaShown' => 0, 'captchaPassed' => 0,
    'verificationPages' => 0, 'tagSetSessions' => 0, 'robotSessions' => 0,
    'ips' => [], 'fps' => [], 'rayIds' => [], 'clientKeys' => [],
];
foreach ($sessions as $s) {
    $g['totalRequests'] += (int)$s['requestCount'];
    $g['requestLines']  += (int)$s['requestLineCount'];
    $g['blockLines']    += (int)$s['blockLineCount'];
    $g['captchaShowLineCount'] += (int)$s['captchaShowLineCount'];
    $g['captchaShown']  += (int)$s['captchaShowCount'];
    $g['captchaPassed'] += (int)$s['captchaPassCount'];
    $g['verificationPages'] += (int)$s['verificationPageCount'];
    if (!empty($s['tagSet'])) $g['tagSetSessions']++;
    if (!empty($s['isRobot'])) $g['robotSessions']++;
    $g['ips'][$s['ip']] = true;
    foreach ($s['fingerprints'] as $fp) $g['fps'][$fp] = true;
    foreach ((array)($s['rayIds'] ?? [$s['rayId']]) as $r) $g['rayIds'][$r] = true;
    $g['clientKeys'][$s['clientKey'] ?? ''] = true;
}

// --- По RayID (visitor_id): анализатор не группирует по RayID, поэтому
//     считаем «по-честному» — сумму по всем merged-сессиям, в rayIds которых есть RayID.
//     Дополнительно отдаём сами merged-сессии с их полями для top-20 сверки.
$perRay = [];
foreach ($sessions as $s) {
    $rays = (array)($s['rayIds'] ?? [$s['rayId']]);
    foreach ($rays as $r) {
        if (!isset($perRay[$r])) {
            $perRay[$r] = ['requests' => 0, 'urls' => [], 'shown' => 0, 'passed' => 0,
                           'blockLines' => 0, 'ips' => [], 'fps' => [], 'sessionCount' => 0,
                           'firstSeen' => $s['firstSeen'], 'lastSeen' => $s['lastSeen']];
        }
        $p =& $perRay[$r];
        // одна merged-сессия может содержать много rayId; атрибутируем ей целиком только
        // «главный» rayId, но для топ-сверки нужно per-ray — используем пропорцию нельзя.
        unset($p);
    }
}

// Проще: повторим парсинг на лету НЕ нужно — вместо этого отдадим merged-сессии
// с полным набором полей и маппинг rayId -> индекс сессии.
$rayToSession = [];
foreach ($sessions as $i => $s) {
    foreach ((array)($s['rayIds'] ?? [$s['rayId']]) as $r) $rayToSession[$r] = $i;
}

$sessOut = [];
foreach ($sessions as $i => $s) {
    $rt = $s['requestTimes'] ?? [];
    sort($rt, SORT_STRING);
    $gaps = [];
    for ($k = 1; $k < count($rt); $k++) {
        $d = strtotime(str_replace(' ', 'T', $rt[$k])) - strtotime(str_replace(' ', 'T', $rt[$k-1]));
        if ($d >= 0 && $d <= 86400*2) $gaps[] = $d;
    }
    $sessOut[$i] = [
        'index' => $i,
        'rayIds' => array_values((array)($s['rayIds'] ?? [$s['rayId']])),
        'ip' => $s['ip'],
        'requestCount' => (int)$s['requestCount'],
        'requestLineCount' => (int)$s['requestLineCount'],
        'blockLineCount' => (int)$s['blockLineCount'],
        'captchaShowCount' => (int)$s['captchaShowCount'],
        'captchaShowLineCount' => (int)$s['captchaShowLineCount'],
        'captchaPassCount' => (int)$s['captchaPassCount'],
        'verificationPageCount' => (int)$s['verificationPageCount'],
        'tagSet' => !empty($s['tagSet']),
        'isRobot' => !empty($s['isRobot']),
        'urls' => $s['urls'],
        'fingerprints' => $s['fingerprints'],
        'userAgents' => $s['userAgents'],
        'firstSeen' => $s['firstSeen'],
        'lastSeen' => $s['lastSeen'],
        'avgIntervalSec' => $gaps ? round(array_sum($gaps)/count($gaps), 2) : null,
        'clientKey' => $s['clientKey'] ?? '',
        'refCats' => $s['refCats'] ?? [],
        'ysclidCount' => (int)($s['ysclidCount'] ?? 0),
        'csrfErrors' => (int)($s['csrfErrors'] ?? 0),
    ];
}

// Сущности IP/FP — score/PF-вес
$entOut = ['ip' => [], 'fp' => []];
foreach (['ip','fp'] as $t) {
    foreach ($entities[$t] as $key => $e) {
        $entOut[$t][(string)$key] = [
            'requests' => (int)$e['requests'],
            'blockLines' => (int)($e['blockLines'] ?? 0),
            'captchaShown' => (int)$e['captchaShown'],
            'captchaShownEvents' => (int)($e['captchaShownEvents'] ?? 0),
            'captchaPassed' => (int)$e['captchaPassed'],
            'sessions' => (int)$e['sessions'],
            'riskScore' => (int)$e['riskScore'],
            'riskVerdict' => $e['riskVerdict'],
            'topUrl' => $e['topUrl'] ?? '',
            'topUrlHits' => (int)($e['topUrlHits'] ?? 0),
            'uniqueUrls' => (int)($e['uniqueUrls'] ?? 0),
            'urlDayMax' => (int)($e['urlDayMax'] ?? 0),
            'intervals' => $e['intervals'] ?? [],
            'isPFCampaign' => !empty($e['isPFCampaign']),
            'pfWeight' => (int)($e['pfWeight'] ?? 0),
            'ysclidRatio' => (int)($e['ysclidRatio'] ?? 0),
            'refCatCounts' => $e['refCatCounts'] ?? [],
            'inBlacklist' => !empty($e['inBlacklist']),
        ];
    }
}

file_put_contents($out, json_encode([
    'global' => [
        'lines' => $parsed['meta']['lines'],
        'mergedSessions' => count($sessions),
        'totalRequests' => $g['totalRequests'],
        'requestLines' => $g['requestLines'],
        'blockLines' => $g['blockLines'],
        'captchaShowLineCount' => $g['captchaShowLineCount'],
        'captchaShown' => $g['captchaShown'],
        'captchaPassed' => $g['captchaPassed'],
        'verificationPages' => $g['verificationPages'],
        'tagSetSessions' => $g['tagSetSessions'],
        'robotSessions' => $g['robotSessions'],
        'uniqueIps' => count($g['ips']),
        'uniqueFps' => count($g['fps']),
        'uniqueRays' => count($g['rayIds']),
        'uniqueClientKeys' => count($g['clientKeys']),
        'entityIpCount' => count($entOut['ip']),
        'entityFpCount' => count($entOut['fp']),
        'campaigns' => count($campaigns),
    ],
    'campaigns' => array_map(fn($c) => [
        'id' => $c['id'], 'ips' => $c['ips'], 'ipsCount' => $c['ipsCount'],
        'fpCount' => $c['fpCount'] ?? count($c['fingerprints'] ?? []),
        'sessionsCount' => $c['sessionsCount'], 'totalRequests' => $c['totalRequests'],
        'topUrl' => $c['topUrl'], 'topUrlHits' => $c['topUrlHits'],
        'urlDayMax' => $c['urlDayMax'] ?? 0, 'ysclidRatio' => $c['ysclidRatio'] ?? 0,
        'refererYandexRatio' => $c['refererYandexRatio'] ?? 0,
        'refererYandexExtRatio' => $c['refererYandexExtRatio'] ?? 0,
        'ownSiteRefRatio' => $c['ownSiteRefRatio'] ?? 0,
        'riskScore' => $c['riskScore'],
    ], $campaigns),
    'rayToSession' => $rayToSession,
    'sessions' => $sessOut,
    'entities' => $entOut,
], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));

$gl = json_decode(file_get_contents($out), true)['global'];
echo json_encode($gl, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), PHP_EOL;
echo "written: $out" , PHP_EOL;
