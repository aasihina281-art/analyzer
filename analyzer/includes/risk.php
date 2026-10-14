<?php
/**
 * AntiBot Analyzer — behavioral risk scoring engine.
 *
 * Core idea: passing a CAPTCHA does NOT make a visitor "good".
 * Behavioral bots solve captchas too, then keep hammering the same URL(s)
 * with machine-like regularity. This module aggregates every session that
 * shares an IP or a fingerprint and computes per-entity behavioral metrics:
 *
 *  - repeatVisitsPerUrl : how many times the SAME url was requested
 *  - dominantUrlShare   : % of all requests pointed at the single most-hit url
 *  - interval stats     : median/avg/min/max between consecutive requests,
 *                         coefficient of variation (CV) + exact-repeat count
 *                         => mechanical periodicity detection
 *  - activeDays         : distinct calendar days the entity was seen
 *  - dailyPattern       : works 24/7 without sleep window => automation
 *  - captchaFastPass    : passed captcha suspiciously fast (<3 s avg)
 *  - noFingerprint      : never reported FP although captcha was solved
 *  - emptyReferrerRatio, UA churn, multi-IP-per-FP rotation
 *
 * Each signal contributes points; total score maps to a verdict:
 *   0-19 ok | 20-39 watch | 40-59 suspicious | 60+ block recommended
 */

declare(strict_types=1);

final class RiskScorer
{
    /** @var array<string,bool> blacklist ip set */
    private array $blackIps;
    /** @var array<string,bool> blacklist fp set */
    private array $blackFps;

    public function __construct(array $blackIps = [], array $blackFps = [])
    {
        $this->blackIps = $blackIps;
        $this->blackFps = $blackFps;
    }

    /**
     * Build entities (ip + fp) from parsed sessions and score them.
     *
     * @param array<int,array> $sessions output of AntiBotLogParser::parseFile()
     * @return array{ip: array<string,array>, fp: array<string,array>}
     */
    public function buildEntities(array $sessions): array
    {
        $entities = ['ip' => [], 'fp' => []];

        foreach ($sessions as $session) {
            if (!empty($session['isRobot'])) continue;      // search bots are not visitors
            if (!empty($session['isWhitelisted'])) continue;

            $ip = trim((string)($session['ip'] ?? ''));
            $fps = $session['fingerprints'] ?? [];

            if ($ip !== '') $this->absorb($entities['ip'], 'ip', $ip, $session, $fps);
            foreach ($fps as $fp) {
                $this->absorb($entities['fp'], 'fp', strtolower((string)$fp), $session, [$fp]);
            }
        }

        foreach (['ip', 'fp'] as $type) {
            foreach ($entities[$type] as $key => &$e) {
                $this->finalize($e, $type);
            }
            unset($e);
        }

        return $entities;
    }

    private function absorb(array &$bucket, string $type, string $key, array $session, array $fps): void
    {
        if (!isset($bucket[$key])) {
            $bucket[$key] = $this->newEntity($type, $key);
        }
        $e =& $bucket[$key];

        $e['sessions']++;
        $e['requests'] += (int)($session['requestCount'] ?? 0);       // только REQ-строки
        $e['blockLines'] += (int)($session['blockLineCount'] ?? 0);   // только BLOCK-строки
        $e['captchaShownEvents'] += (int)($session['captchaShowLineCount'] ?? 0); // CAPTCHA-строки
        $e['rayIds'] += (int)($session['rayCount'] ?? 1);             // HTTP-запросов Cloudflare
        $e['captchaShown'] += (int)($session['captchaShowCount'] ?? 0);
        $e['verificationPages'] += (int)($session['verificationPageCount'] ?? 0);
        $e['captchaPassed'] += (int)($session['captchaPassCount'] ?? 0);
        $e['tagSetCount'] += !empty($session['tagSet']) ? 1 : 0;
        $e['emptyReferrers'] += (int)($session['emptyReferrerCount'] ?? 0);
        $e['totalRefEvents'] += (int)($session['emptyReferrerCount'] ?? 0) + count($session['referrers'] ?? []);

        // --- Накрутка ПФ: агрегация новых сигналов сессии в сущность ---
        $e['csrfErrors'] += (int)($session['csrfErrors'] ?? 0);
        $e['ysclidRequests'] += (int)($session['ysclidCount'] ?? 0);
        $e['utmReferrerRequests'] += (int)($session['utmReferrerCount'] ?? 0);
        foreach ((array)($session['refCats'] ?? []) as $cat => $cnt) {
            $e['refCatCounts'][$cat] = ($e['refCatCounts'][$cat] ?? 0) + (int)$cnt;
        }
        // Флаги ysclid/utm по путям (path => bool) — «тот же URL с меткой Яндекса»
        foreach ((array)($session['pathFlags'] ?? []) as $fl) {
            $p = (string)($fl['path'] ?? '');
            if ($p === '') continue;
            if (!empty($fl['ys'])) $e['pathYs'][$p] = true;
            if (!empty($fl['ut'])) $e['pathUt'][$p] = true;
        }
        // Повторы пути по дням: path => [date => hits] (для urlDayMax и графиков)
        foreach ((array)($session['urlPathDays'] ?? []) as $p => $days) {
            if (!isset($e['pathDayHits'][$p]) && count($e['pathDayHits']) < 2000) {
                $e['pathDayHits'][$p] = [];
            }
            if (!isset($e['pathDayHits'][$p])) continue;
            foreach ($days as $d => $c) {
                $e['pathDayHits'][$p][$d] = ($e['pathDayHits'][$p][$d] ?? 0) + (int)$c;
            }
        }

        if (!empty($session['blocked'])) $e['blocked']++;

        // Per-URL request counters (repeat visits on the same page).
        // $session['urls'] — уже счётчики path => hits (1 hit = 1 HTTP-запрос),
        // поэтому прибавляем именно количество, а не «+1 на уникальный URL».
        foreach ((array)($session['urls'] ?? []) as $url => $hits) {
            $url = (string)$url;
            if ($url === '') continue;
            $hits = max(1, (int)$hits);
            if (!isset($e['urlCounts'][$url]) && count($e['urlCounts']) >= 2000) {
                continue; // защита от разрастания карты URL
            }
            $e['urlCounts'][$url] = ($e['urlCounts'][$url] ?? 0) + $hits;
        }

        // Request timestamps for interval / periodicity analysis
        foreach ((array)($session['requestTimes'] ?? []) as $ts) {
            if (count($e['reqTimes']) < 3000) $e['reqTimes'][] = $ts;
            $d = substr($ts, 0, 10);
            $h = (int)substr($ts, 11, 2);
            if (!isset($e['dayHours'][$d])) $e['dayHours'][$d] = array_fill(0, 24, 0);
            $e['dayHours'][$d][$h]++;
        }

        // Which calendar days each URL was requested (daily repeat visits).
        // Uses the session's observed time range; sessions are short-lived
        // (one captcha tag), so day attribution is accurate in practice.
        $sFirst = substr((string)($session['firstSeen'] ?? ''), 0, 10);
        $sLast  = substr((string)($session['lastSeen'] ?? ''), 0, 10);
        if ($sFirst !== '') {
            foreach ((array)($session['urls'] ?? []) as $uUrl => $hits) {
                $uUrl = (string)$uUrl;
                if ($uUrl === '' || (int)$hits <= 0) continue; // только реальные запросы
                $e['urlDays'][$uUrl][$sFirst] = true;
                if ($sLast !== '' && $sLast !== $sFirst) $e['urlDays'][$uUrl][$sLast] = true;
            }
        }

        // Captcha show/pass times for reaction-speed analysis
        foreach ((array)($session['showTimes'] ?? []) as $ts) {
            if (count($e['showTimes']) < 500) $e['showTimes'][] = $ts;
        }
        foreach ((array)($session['passTimes'] ?? []) as $ts) {
            if (count($e['passTimes']) < 500) $e['passTimes'][] = $ts;
        }

        foreach ((array)($session['userAgents'] ?? []) as $ua) $e['uas'][$ua] = true;
        foreach ((array)($session['referrers'] ?? []) as $ref) $e['refs'][$ref] = true;
        foreach ($fps as $fp) $e['fps'][strtolower((string)$fp)] = true;
        if ($type === 'fp' && $session['ip'] !== '') $e['ips'][$session['ip']] = true;
        foreach ((array)($session['fpsValues'] ?? []) as $v) {
            if (count($e['fpsValues']) < 200) $e['fpsValues'][] = (int)$v;
        }

        if (($session['firstSeen'] ?? '') !== '' && ($e['firstSeen'] === '' || $session['firstSeen'] < $e['firstSeen'])) {
            $e['firstSeen'] = $session['firstSeen'];
        }
        if (($session['lastSeen'] ?? '') > $e['lastSeen']) $e['lastSeen'] = $session['lastSeen'];

        if (!empty($session['inBlacklistIp'])) $e['logBlacklistIp'] = true;
        if (!empty($session['inBlacklistFp'])) $e['logBlacklistFp'] = true;
        if (!empty($session['graylisted'])) $e['graylisted'] = true;

        unset($e);
    }

    private function newEntity(string $type, string $value): array
    {
        return [
            'type' => $type,
            'value' => $value,
            'sessions' => 0,
            'requests' => 0,        // только REQ-строки (обращения к URL)
            'blockLines' => 0,      // только BLOCK-строки (страницы блокировки)
            'captchaShownEvents' => 0, // CAPTCHA-строки (показано + пройдено)
            'rayIds' => 0,          // число RayID (HTTP-запросов Cloudflare)
            'captchaShown' => 0,
            'verificationPages' => 0,
            'captchaPassed' => 0,
            'tagSetCount' => 0,
            'blocked' => 0,
            'emptyReferrers' => 0,
            'totalRefEvents' => 0,
            'urlCounts' => [],
            'reqTimes' => [],
            'showTimes' => [],
            'passTimes' => [],
            'uas' => [],
            'refs' => [],
            'ips' => [],
            'fps' => [],
            'fpsValues' => [],
            'firstSeen' => '',
            'lastSeen' => '',
            'logBlacklistIp' => false,
            'logBlacklistFp' => false,
            'graylisted' => false,
            'inBlacklist' => false,
            'dayHours' => [],   // date -> [hour => hits]
            'urlDays'   => [],  // url  -> [date => true]
            // --- Накрутка ПФ (новые поля) ---
            'csrfErrors' => 0,          // CSRF-token expired/not found
            'ysclidRequests' => 0,      // запросов с ysclid=
            'utmReferrerRequests' => 0, // запросов с utm_referrer=
            'refCatCounts' => [],        // категория реферера => кол-во событий
            'pathYs' => [],              // path => true (встречался с ysclid)
            'pathUt' => [],              // path => true (встречался с utm_referrer)
            'pathDayHits' => [],         // path => [date => hits] — повторы по дням
        ];
    }

    private function finalize(array &$e, string $type): void
    {
        $e['ips'] = array_keys($e['ips']);
        $e['fps'] = array_keys($e['fps']);
        $e['uas'] = array_keys($e['uas']);
        $e['refs'] = array_keys($e['refs']);
        $e['ipCount'] = count($e['ips']);
        $e['fpCount'] = count($e['fps']);
        $e['uaCount'] = count($e['uas']);

        if ($type === 'ip' && isset($this->blackIps[$e['value']])) $e['inBlacklist'] = true;
        if ($type === 'fp' && isset($this->blackFps[$e['value']])) $e['inBlacklist'] = true;
        if ($e['logBlacklistIp'] || $e['logBlacklistFp']) $e['inBlacklist'] = true;

        // ---- URL repetition ----
        arsort($e['urlCounts']);
        $uniqueUrls = count($e['urlCounts']);
        $topUrl = array_key_first($e['urlCounts']) ?? '';
        $topUrlHits = $topUrl !== '' ? (int)$e['urlCounts'][$topUrl] : 0;
        $totalUrlReq = array_sum($e['urlCounts']);
        $e['uniqueUrls'] = $uniqueUrls;
        $e['topUrl'] = $topUrl;
        $e['topUrlHits'] = $topUrlHits;
        $e['repeatRatio'] = $totalUrlReq > 0 ? round(($totalUrlReq - $uniqueUrls) / $totalUrlReq * 100) : 0;
        $e['dominantUrlShare'] = $totalUrlReq > 0 ? round($topUrlHits / $totalUrlReq * 100) : 0;
        $e['urlCountsTop'] = array_slice($e['urlCounts'], 0, 12, true);
        unset($e['urlCounts']);

        // ---- Interval / periodicity analysis ----
        sort($e['reqTimes'], SORT_STRING);
        $gaps = [];
        $prevTs = null;
        $gapDayBuckets = [];
        foreach ($e['reqTimes'] as $ts) {
            $cur = strtotime(str_replace(' ', 'T', $ts));
            if ($cur === false) continue;
            $day = substr($ts, 0, 10);
            if (!isset($gapDayBuckets[$day])) $gapDayBuckets[$day] = [];
            if ($prevTs !== null) {
                $d = $cur - $prevTs;
                if ($d >= 0 && $d <= 86400 * 2) { // ignore multi-day idle gaps
                    $gaps[] = $d;
                    $gapDayBuckets[$day][] = $d;
                }
            }
            $prevTs = $cur;
        }
        unset($e['reqTimes']);

        $stats = self::intervalStats($gaps);
        $e['intervals'] = $stats;
        $e['intervalSamples'] = count($gaps);

        // Histogram for chart (log-bucketed)
        $e['intervalHistogram'] = self::intervalHistogram($gaps);

        // Per-day activity -> sleep window & persistence checks
        $activeDays = array_keys($e['dayHours']);
        sort($activeDays, SORT_STRING);
        $e['activeDays'] = count($activeDays);
        $e['dayList'] = array_slice($activeDays, 0, 60);

        // Hours histogram over the whole lifetime (for heatmap chart)
        $hourTotals = array_fill(0, 24, 0);
        foreach ($e['dayHours'] as $hd) {
            foreach ($hd as $hh => $cnt) $hourTotals[$hh] += $cnt;
        }
        $e['hourHistogram'] = $hourTotals;
        $nightHits = $hourTotals[1] + $hourTotals[2] + $hourTotals[3] + $hourTotals[4];
        $dayTotal = max(1, array_sum($hourTotals));
        $e['nightRatio'] = round($nightHits / $dayTotal * 100);

        // Distinct days the TOP url was seen (daily repeat visits of same page)
        $topUrl = $e['topUrl'];
        $e['topUrlDays'] = isset($e['urlDays'][$topUrl]) ? count($e['urlDays'][$topUrl]) : 0;

        // ---- Накрутка ПФ: производные метрики по путям и реферерам ----
        // Топ-путь (без query): накрутчики ходят на одну страницу, даже если
        // каждый раз подставляется новый ysclid / utm_referrer.
        $pathTotals = [];
        foreach ($e['pathDayHits'] as $p => $days) {
            $pathTotals[$p] = array_sum($days);
        }
        arsort($pathTotals);
        $topPath = array_key_first($pathTotals) ?? '';
        $e['topPath'] = $topPath;
        $e['topPathHits'] = $topPath !== '' ? (int)$pathTotals[$topPath] : 0;
        $topPathDaysMap = $e['pathDayHits'][$topPath] ?? [];
        $e['topPathDays'] = count($topPathDaysMap);
        // Максимум заходов на топ-путь за ОДИН день — ключевой сигнал ПФ
        $e['urlDayMax'] = $topPathDaysMap ? max($topPathDaysMap) : 0;
        // Список заходов топ-пути по дням для графика «календарь повторов»
        ksort($topPathDaysMap, SORT_STRING);
        $e['topPathDaySeries'] = $topPathDaysMap;   // date => hits
        unset($e['pathDayHits'], $e['urlDays'], $e['dayHours']);

        // ---- Доли реферерных категорий от всех REF-событий ----
        /*
         * ВАЖНО: 'own_site' — это реферер с собственного домена (переклейка
         * накрутчика: бот идёт по ссылке, уже побывав на самом сайте).
         * Он НЕ учитывается как «яндекс-трафик». Настоящий источник
         * захода берём из utm_referrer/ysclid внутри URL запроса.
         */
        $refTotal = max(1, array_sum($e['refCatCounts']));
        $extTotal = max(1, $refTotal - (int)($e['refCatCounts']['own_site'] ?? 0));
        $yandexish = (int)($e['refCatCounts']['yandex'] ?? 0) + (int)($e['refCatCounts']['yandex_proxy'] ?? 0);
        $e['refererYandexRatio'] = round($yandexish / $extTotal * 100);
        $e['emptyRefererRatio'] = round(((int)($e['refCatCounts']['direct'] ?? 0)) / $refTotal * 100);
        $e['ownSiteRefRatio'] = round((int)($e['refCatCounts']['own_site'] ?? 0) / $refTotal * 100);
        // «Все заходы через внешний реферер, боковых переходов нет»:
        // почти нет прямых заходов при наличии внешних REF-событий
        $e['allReferralNoSide'] = ($yandexish >= 3 && $e['emptyRefererRatio'] <= 10);

        // Доля URL с ysclid / utm_referrer от всех запросов сущности
        $reqDiv = max(1, $e['requests']);
        $e['ysclidRatio'] = round($e['ysclidRequests'] / $reqDiv * 100);
        $e['utmReferrerRatio'] = round($e['utmReferrerRequests'] / $reqDiv * 100);
        // Топ-путь размечен метками Яндекса?
        $e['topPathHasYsclid'] = ($topPath !== '' && !empty($e['pathYs'][$topPath]));
        $e['topPathHasUtmRef'] = ($topPath !== '' && !empty($e['pathUt'][$topPath]));

        // refererPattern — доминирующая категория источника трафика.
        // Яндекс + его proxy-переклейки (zsay и т.п.) считаются вместе:
        // если их сумма не меньше любой отдельной категории — паттерн яндексовый.
        $catCounts = array_merge(
            ['yandex' => 0, 'yandex_proxy' => 0, 'google' => 0, 'vk' => 0, 'other' => 0, 'direct' => 0],
            $e['refCatCounts']
        );
        unset($catCounts['own_site']); // собственный домен — не источник трафика
        $singleMax = max($catCounts);
        if ($yandexish >= $singleMax && $yandexish > 0) {
            $domCat = ($catCounts['yandex_proxy'] > $catCounts['yandex']) ? 'yandex_proxy' : 'yandex';
        } else {
            arsort($catCounts);
            $domCat = (string)array_key_first($catCounts);
        }
        /*
         * Если HTTP-Referer везде «свой» (переклейка), но в URL есть
         * utm_referrer/ysclid яндексовых зеркал — источник всё-таки Яндекс.
         */
        if (($domCat === 'direct' || $domCat === 'other') && $e['utmReferrerRequests'] + $e['ysclidRequests'] >= max(3, (int)$e['requests'] * 0.5)) {
            $domCat = 'yandex_proxy';
        }
        $e['refererPattern'] = (($e['topPathHasYsclid'] || !empty($e['pathUt'][$topPath])) && in_array($domCat, ['yandex', 'yandex_proxy'], true))
            ? 'yandex_with_ysclid' : $domCat;

        // ---- Captcha reaction speed ----
        sort($e['showTimes'], SORT_STRING);
        sort($e['passTimes'], SORT_STRING);
        $fastPasses = 0; $passDeltas = [];
        $pi = 0;
        foreach ($e['showTimes'] as $show) {
            $showTs = strtotime(str_replace(' ', 'T', $show));
            while ($pi < count($e['passTimes'])) {
                $passTs = strtotime(str_replace(' ', 'T', $e['passTimes'][$pi]));
                $pi++;
                if ($passTs >= $showTs) {
                    $delta = $passTs - $showTs;
                    if ($delta >= 0 && $delta < 3600) {
                        $passDeltas[] = $delta;
                        if ($delta <= 3) $fastPasses++;
                    }
                    break;
                }
            }
        }
        unset($e['showTimes'], $e['passTimes']);
        $e['fastPasses'] = $fastPasses;
        $e['avgPassSeconds'] = $passDeltas ? round(array_sum($passDeltas) / count($passDeltas), 1) : null;

        $e['emptyRefRatio'] = $e['totalRefEvents'] > 0
            ? round($e['emptyReferrers'] / max(1, $e['requests']) * 100)
            : 0;

        // FPS screen values: 0 fps is a strong headless/emulator hint
        $zeroFps = 0;
        foreach ($e['fpsValues'] as $v) if ($v === 0) $zeroFps++;
        $e['zeroFpsCount'] = $zeroFps;
        unset($e['fpsValues']);

        // ---- Score ----
        $e = array_merge($e, self::score($e));
    }

    public static function intervalStats(array $gaps): array
    {
        if (!$gaps) return ['count' => 0, 'median' => null, 'avg' => null, 'min' => null, 'max' => null, 'cv' => null, 'exactRepeats' => 0, 'sub60' => 0];
        sort($gaps, SORT_NUMERIC);
        $n = count($gaps);
        $median = $n % 2 ? $gaps[intdiv($n, 2)] : ($gaps[intdiv($n, 2) - 1] + $gaps[intdiv($n, 2)]) / 2;
        $avg = array_sum($gaps) / $n;
        $var = 0.0;
        foreach ($gaps as $g) $var += ($g - $avg) ** 2;
        $var /= $n;
        $cv = $avg > 0 ? sqrt($var) / $avg : null;

        $freq = [];
        $exactRepeats = 0;
        foreach ($gaps as $g) {
            $k = (int)round($g);
            $freq[$k] = ($freq[$k] ?? 0) + 1;
        }
        foreach ($freq as $c) if ($c >= 3) $exactRepeats += $c;

        $sub60 = 0;
        foreach ($gaps as $g) if ($g < 60) $sub60++;

        return [
            'count' => $n,
            'median' => round($median, 1),
            'avg' => round($avg, 1),
            'min' => round($gaps[0], 1),
            'max' => round($gaps[$n - 1], 1),
            'cv' => $cv !== null ? round($cv, 2) : null,
            'exactRepeats' => $exactRepeats,
            'sub60' => $sub60,
        ];
    }

    /** Log-scale histogram: <1s, 1-5, 5-15, 15-60, 1-5m, 5-15m, 15-60m, 1-6h, 6-24h, >24h */
    public static function intervalHistogram(array $gaps): array
    {
        $labels = ['<1с', '1-5с', '5-15с', '15-60с', '1-5м', '5-15м', '15-60м', '1-6ч', '6-24ч'];
        $edges  = [1, 5, 15, 60, 300, 900, 3600, 21600, 86400];
        $counts = array_fill(0, count($labels), 0);
        foreach ($gaps as $g) {
            for ($i = 0; $i < count($edges); $i++) {
                if ($g < $edges[$i]) { $counts[$i]++; continue 2; }
            }
            $counts[count($labels) - 1]++;
        }
        return array_combine($labels, $counts);
    }

    /**
     * Weighted behavioral scoring. Returns score/verdict/reasons/badges.
     */
    public static function score(array $e): array
    {
        $score = 0;
        $reasons = [];
        $badges = [];

        $iv = $e['intervals'];
        $passedCaptcha = $e['captchaPassed'] > 0;

        // 1) The core case from the task: repeated hits on the SAME url.
        if ($e['topUrlHits'] >= 100) { $score += 30; $reasons[] = "Та же страница запрошена {$e['topUrlHits']} раз"; $badges[] = 'zaprosy'; }
        elseif ($e['topUrlHits'] >= 50) { $score += 25; $reasons[] = "Та же страница {$e['topUrlHits']} раз"; $badges[] = 'zaprosy'; }
        elseif ($e['topUrlHits'] >= 25) { $score += 18; $reasons[] = "Повтор одной страницы: {$e['topUrlHits']}x"; $badges[] = 'zaprosy'; }
        elseif ($e['topUrlHits'] >= 12) { $score += 10; $reasons[] = "Повтор одной страницы: {$e['topUrlHits']}x"; }

        // Dominance: nearly all traffic targets one URL
        if ($e['dominantUrlShare'] >= 80 && $e['topUrlHits'] >= 10) {
            $score += 12; $reasons[] = "80%+ трафика на одну страницу ({$e['dominantUrlShare']}%)";
        }

        // Daily recurrence of the SAME URL across multiple days —
        // the key behavioral-bot signal described by the operator.
        if ($e['topUrlDays'] >= 3 && $e['topUrlHits'] >= 10) {
            $score += 18; $reasons[] = "Та же страница в {$e['topUrlDays']} разных дней"; $badges[] = 'dni';
        } elseif ($e['topUrlDays'] === 2 && $e['topUrlHits'] >= 8) {
            $score += 9; $reasons[] = "Та же страница 2 дня подряд ({$e['topUrlHits']}x)";
        }

        // Night-time activity 01:00-05:00 (humans sleep)
        if ($e['requests'] >= 20 && $e['nightRatio'] >= 25) {
            $score += 7; $reasons[] = "{$e['nightRatio']}% запросов в ночи (01-05 ч)";
        }

        // 2) Mechanical periodicity: low CV with enough samples
        if ($iv['count'] >= 10 && $iv['cv'] !== null) {
            if ($iv['cv'] < 0.25) { $score += 20; $reasons[] = "Машинная регулярность интервалов (CV={$iv['cv']})"; $badges[] = 'ritm'; }
            elseif ($iv['cv'] < 0.5) { $score += 12; $reasons[] = "Подозрительно ровные интервалы (CV={$iv['cv']})"; $badges[] = 'ritm'; }
        }
        if ($iv['exactRepeats'] >= 8) {
            $score += 12; $reasons[] = "{$iv['exactRepeats']} идентичных по секундам интервалов";
        }
        if ($iv['median'] !== null && $iv['median'] < 5 && $iv['count'] >= 10) {
            $score += 15; $reasons[] = "Медиана между запросами всего {$iv['median']} с";
        }

        // 3) Fast captcha passes (machine solving)
        if ($e['fastPasses'] >= 3) {
            $score += 12; $reasons[] = "CAPTCHA решена {$e['fastPasses']} раз быстрее 3 сек"; $badges[] = 'captcha';
        } elseif ($e['fastPasses'] >= 1 && $passedCaptcha) {
            $score += 6; $reasons[] = "Есть мгновенные прохождения CAPTCHA";
        }

        // 4) Passed captcha but keeps hitting verification repeatedly
        if ($passedCaptcha && $e['captchaShown'] >= 5) {
            $score += 10; $reasons[] = "Прошёл капчу, но проверка показана {$e['captchaShown']} раз";
        }

        // 5) Zero reported screen FPS (headless emulator)
        if ($e['zeroFpsCount'] >= 2) {
            $score += 8; $reasons[] = "FPS экрана = 0 (эмулятор/headless)";
        }

        // 6) Fingerprint rotation across IPs
        if ($e['type'] === 'fp' && $e['ipCount'] >= 5) {
            $score += 12; $reasons[] = "Один отпечаток на {$e['ipCount']} IP (ротация адресов)"; $badges[] = 'iprotacia';
        } elseif ($e['type'] === 'fp' && $e['ipCount'] >= 3) {
            $score += 6; $reasons[] = "Один отпечаток на {$e['ipCount']} IP";
        }

        // 7) UA churn on one identity
        if ($e['uaCount'] >= 4) {
            $score += 8; $reasons[] = "Смена User-Agent: {$e['uaCount']} шт.";
        }

        // 8) No fingerprint ever, despite captcha being shown
        if ($e['type'] === 'ip' && $e['fpCount'] === 0 && $e['captchaShown'] >= 2 && !$passedCaptcha) {
            $score += 6; $reasons[] = "Отпечаток не сдан при показе CAPTCHA";
        }

        // 9) Traffic in sleeping hours only / around the clock
        if ($e['requests'] >= 40 && $e['firstSeen'] !== '' && $e['lastSeen'] !== '') {
            $spanH = (strtotime(str_replace(' ', 'T', $e['lastSeen'])) - strtotime(str_replace(' ', 'T', $e['firstSeen']))) / 3600;
            if ($spanH >= 20 && $spanH <= 48 && $e['requests'] / max(1, $spanH) > 3) {
                $score += 8; $reasons[] = "Активность почти без пауз (~{$e['requests']} запросов за ". round($spanH) ." ч)";
            }
        }

        // 10) CSRF-ошибки: куки не сохраняются между заходами — резидентные прокси
        if (($e['csrfErrors'] ?? 0) >= 2) {
            $score += 8; $reasons[] = "CSRF-ошибок: {$e['csrfErrors']} (куки не сохраняются — прокси-ротация)";
            $badges[] = 'csrf';
        } elseif (($e['csrfErrors'] ?? 0) >= 1) {
            $score += 4; $reasons[] = "Есть CSRF-token ошибка (сломанные куки)";
        }

        // Cap
        $score = min(100, $score);

        if ($e['blocked'] > 0 || $e['inBlacklist']) {
            $verdict = 'blocked';
        } elseif ($score >= 60) {
            $verdict = 'block';
        } elseif ($score >= 40) {
            $verdict = 'suspect';
        } elseif ($score >= 20) {
            $verdict = 'watch';
        } else {
            $verdict = 'ok';
        }

        return [
            'riskScore' => $score,
            'riskVerdict' => $verdict,
            'riskReasons' => array_slice($reasons, 0, 8),
            'riskBadges' => array_values(array_unique($badges)),
        ];
    }

    /**
     * Финальная рехерситация вердикта сущности после работы PFCampaignDetector.
     * Если сущность помечена как часть кампании накрутки ПФ — вердикт
     * поднимается до pf_campaign (фиолетовый, топ списка). Не трогает
     * уже заблокированных (blocked) и не понижает «block».
     */
    public static function applyPfVerdict(array &$entity): void
    {
        if (empty($entity['isPFCampaign'])) return;
        if (($entity['riskVerdict'] ?? '') === 'blocked') return; // факт блока сильнее

        $entity['pfOriginalVerdict'] = $entity['riskVerdict'] ?? 'ok';
        $entity['riskVerdict'] = 'pf_campaign';

        // PF-факты ставим в начало причин
        $pfReasons = array_slice($entity['pfReasons'] ?? [], 0, 6);
        $entity['riskReasons'] = array_values(array_unique(
            array_merge($pfReasons, (array)($entity['riskReasons'] ?? []))
        ));
        $entity['riskBadges'] = array_values(array_unique(
            array_merge(['pf'], (array)($entity['riskBadges'] ?? []))
        ));
    }
}
