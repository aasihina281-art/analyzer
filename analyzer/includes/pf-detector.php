<?php
/**
 * AntiBot Analyzer — детектор кампаний накрутки поведенческих факторов (ПФ).
 *
 * Работает ПОВЕРХ RiskScorer: принимает уже посчитанные сущности (ip/fp)
 * и исходные сессии, затем:
 *
 *  1. scorePFCampaign() — скоринг по весам из pf-config.php для каждой
 *     сущности (повторы топ-URL в день, повтор по дням, яндексовый
 *     referer + ysclid, машинная периодичность, ротация IP, CSRF-ошибки).
 *
 *  2. detect() — склейка сущностей в кампании (агрегат более высокого
 *     уровня) по трём правилам:
 *       - совпадающий FP => IP и FP автоматически в одной кампании;
 *       - разные IP из одной подсети /24 (IPv4) или /48 (IPv6),
 *         если у них одинаковый topPath и похожий referer-паттерн;
 *       - совпадающий набор UA (один UA на несколько «одиноких» IP).
 *     Union-Find со сжатием путей — группы формируются транзитивно.
 *
 *  3. Для каждой кампании считается суммарный PF-вес (по объединённым
 *     метрикам), вердикт и флаг isPFCampaign; сущности-участники
 *     получают isPFCampaign/campaignId, после чего dashboard вызывает
 *     RiskScorer::applyPfVerdict() — вердикт становится 'pf_campaign'.
 */

declare(strict_types=1);

require_once __DIR__ . '/pf-config.php';

final class PFCampaignDetector
{
    /** @var array конфиг весов/порогов */
    private array $cfg;

    public function __construct(?array $config = null)
    {
        $this->cfg = $config ?? (array)require __DIR__ . '/pf-config.php';
    }

    private function w(string $key, int $default = 0): int
    {
        return (int)($this->cfg[$key] ?? $default);
    }

    /* ==================================================================
     * 1. Скоринг накрутки ПФ для ОДНОЙ сущности
     * ================================================================== */

    /**
     * Возвращает ['score'=>int, 'isPF'=>bool, 'reasons'=>string[], 'signals'=>[...]]
     * $e — финализированная сущность RiskScorer (см. finalize()).
     */
    public function scorePFCampaign(array $e): array
    {
        $score = 0;
        $reasons = [];
        $signals = [];

        // ---- Повторы одного URL внутри дня (urlDayMax из pathDayHits) ----
        $dayMax = (int)($e['urlDayMax'] ?? 0);
        if ($dayMax >= 10) {
            $score += $this->w('pf_url_day_10', 40);
            $reasons[] = "Тот же URL {$dayMax} раз за один день";
            $signals[] = 'url_day_10';
            // Экстремальные повторы (>=20/день) — дополнительный вес:
            // живая аудитория так себя не ведёт ни при каком трафике.
            if ($dayMax >= 20) {
                $score += $this->w('pf_url_day_20_bonus', 15);
                $reasons[] = "Экстремальные повторы: {$dayMax} заходов за день";
                $signals[] = 'url_day_20';
            }
        } elseif ($dayMax >= 5) {
            $score += $this->w('pf_url_day_5', 25);
            $reasons[] = "Тот же URL {$dayMax} раз за день";
            $signals[] = 'url_day_5';
        } elseif ($dayMax >= 3) {
            $score += $this->w('pf_url_day_3', 12);
            $reasons[] = "Тот же URL {$dayMax}+ раза за день";
            $signals[] = 'url_day_3';
        }

        // ---- Повтор одного URL по разным дням ----
        $topDays = max((int)($e['topUrlDays'] ?? 0), (int)($e['topPathDays'] ?? 0));
        if ($topDays >= 3) {
            $score += $this->w('pf_url_days_3', 30);
            $reasons[] = "Тот же URL в {$topDays} разных дней";
            $signals[] = 'url_days_3';
        } elseif ($topDays === 2) {
            $score += $this->w('pf_url_days_2', 15);
            $reasons[] = "Тот же URL в 2 разных дня";
            $signals[] = 'url_days_2';
        }

        // ---- Referer yandex/ya/zsay + ysclid в URL ----
        $yanRatio = (int)($e['refererYandexRatio'] ?? 0);
        $pattern  = (string)($e['refererPattern'] ?? '');
        if ($pattern === 'yandex_with_ysclid') {
            $score += $this->w('pf_yandex_ysclid', 25);
            $reasons[] = 'Referer Яндекс/переклейка + ysclid в URL';
            $signals[] = 'yandex_ysclid';
        } elseif ($yanRatio >= 50) {
            $score += $this->w('pf_yandex_referer', 15);
            $reasons[] = "Яндексовый referer в {$yanRatio}% переходов";
            $signals[] = 'yandex_referer';
        }

        // ---- Все заходы через referer, боковых переходов нет ----
        if (!empty($e['allReferralNoSide'])) {
            $score += $this->w('pf_all_referer_no_side', 15);
            $reasons[] = 'Нет боковых переходов: только вход по внешнему referer';
            $signals[] = 'no_side_navigation';
        }

        // ---- Доминирование одного URL ----
        if ((int)($e['dominantUrlShare'] ?? 0) >= 80) {
            $score += $this->w('pf_dominant_share_80', 15);
            $reasons[] = "Доля топ-URL: {$e['dominantUrlShare']}% всего трафика";
            $signals[] = 'dominant_80';
        }

        // ---- Машинная периодичность ----
        $iv = $e['intervals'] ?? ['count' => 0, 'cv' => null, 'median' => null, 'exactRepeats' => 0];
        if (($iv['count'] ?? 0) >= 10 && $iv['cv'] !== null && $iv['cv'] < 0.3) {
            $score += $this->w('pf_cv_low', 20);
            $reasons[] = "Ровные интервалы: CV={$iv['cv']} при {$iv['count']} замерах";
            $signals[] = 'cv_low';
        }
        if (($iv['exactRepeats'] ?? 0) >= 5) {
            $score += $this->w('pf_exact_repeats', 15);
            $reasons[] = "{$iv['exactRepeats']} идентичных по секундам пауз";
            $signals[] = 'exact_repeats';
        }
        if ($iv['median'] !== null && $iv['median'] < 15 && ($iv['count'] ?? 0) >= 5) {
            $score += $this->w('pf_median_fast', 10);
            $reasons[] = "Медиана между заходами всего {$iv['median']} с";
            $signals[] = 'median_fast';
        }

        // ---- Ротация IP вокруг одного FP (пул прокси) ----
        if (($e['type'] ?? '') === 'fp') {
            $ipc = (int)($e['ipCount'] ?? 0);
            if ($ipc >= 5) {
                $score += $this->w('pf_ip_per_fp_5', 30);
                $reasons[] = "Один отпечаток ходит с {$ipc} IP";
                $signals[] = 'ip_rotation_5';
            } elseif ($ipc >= 3) {
                $score += $this->w('pf_ip_per_fp_3', 20);
                $reasons[] = "Один отпечаток ходит с {$ipc} IP";
                $signals[] = 'ip_rotation_3';
            } elseif ($ipc >= 2) {
                $score += $this->w('pf_ip_per_fp_2', 10);
                $reasons[] = "Один отпечаток с {$ipc} IP";
                $signals[] = 'ip_rotation_2';
            }
        }

        // ---- CSRF-token expired/not found (куки не сохраняются) ----
        if ((int)($e['csrfErrors'] ?? 0) >= 1) {
            $score += $this->w('pf_csrf_errors', 15);
            $reasons[] = "CSRF-ошибок: {$e['csrfErrors']} — куки не сохраняются между заходами";
            $signals[] = 'csrf';
        }

        // ---- Быстрые решения капчи ----
        if ((int)($e['fastPasses'] ?? 0) >= 2) {
            $score += $this->w('pf_fast_passes', 10);
            $reasons[] = "Капча решена {$e['fastPasses']} раз быстрее 3 сек";
            $signals[] = 'fast_pass';
        }

        // ---- FPS экрана = 0 (headless/эмулятор) ----
        if ((int)($e['zeroFpsCount'] ?? 0) >= 2) {
            $score += $this->w('pf_zero_fps', 10);
            $reasons[] = "FPS=0 {$e['zeroFpsCount']} раз (эмулятор/headless)";
            $signals[] = 'zero_fps';
        }

        $threshold = $this->w('pf_threshold', 80);
        return [
            'score'   => min(150, $score), // сырой вес может превышать 100 — это ок
            'isPF'    => $score >= $threshold,
            'reasons' => $reasons,
            'signals' => $signals,
        ];
    }

    /* ==================================================================
     * 2. Построение кампаний (Union-Find по IP/FP-сущностям)
     * ================================================================== */

    /**
     * Главная точка входа (см. ТЗ): принимает сущности и сессии,
     * возвращает список кампаний.
     *
     * @param array $entities результат RiskScorer::buildEntities() (['ip'=>[], 'fp'=>[]])
     * @param array $sessions результат AntiBotLogParser::parseFile()['sessions']
     * @param array|null &$chartsOut (опционально) глобальные данные для графиков 6.1–6.4
     * @return array<int,array> список кампаний (структура — см. ТЗ п.1)
     *
     * ВАЖНО: PHP копирует массивы по значению, поэтому обогащённые
     * pf-полями сущности возвращаются первым элементом detectWithEntities().
     * Вызывающий код должен присвоить их обратно (см. dashboard.php).
     */
    public function detect(array $entities, array $sessions, ?array &$chartsOut = null): array
    {
        [, $campaigns, $charts] = $this->detectWithEntities($entities, $sessions);
        $chartsOut = $charts;
        return $campaigns;
    }

    /**
     * То же, что detect(), но возвращает всё сразу:
     * [0] => обогащённые сущности (те же, но с pf-полями),
     * [1] => массив кампаний,
     * [2] => глобальные данные для графиков dashboard (urlRepeatCalendar, fpIpPool, pfHeat).
     */
    public function detectWithEntities(array $entities, array $sessions): array
    {
        // --- Шаг 1: PF-вес каждой сущности + временное поле isPFCandidate ---
        foreach (['ip', 'fp'] as $type) {
            foreach ($entities[$type] as $key => $e) {
                $pf = $this->scorePFCampaign($e);
                $e['pfScore'] = $pf['score'];
                $e['pfReasons'] = $pf['reasons'];
                $e['pfSignals'] = $pf['signals'];
                $e['isPFCandidate'] = $pf['isPF'];
                $e['campaignId'] = null;
                $e['isPFCampaign'] = false;
                $entities[$type][$key] = $e;
            }
        }

        // --- Шаг 2: Union-Find по ключам "ip:<addr>" / "fp:<hash>" ---
        $parent = [];
        $find = static function (string $x) use (&$parent, &$find): string {
            if (!isset($parent[$x])) $parent[$x] = $x;
            // итеративное нахождение корня со сжатием путей
            $root = $x; while (($parent[$root] ?? $root) !== $root) $root = $parent[$root];
            while ($x !== $root) { $n = $parent[$x]; $parent[$x] = $root; $x = $n; }
            return $root;
        };
        $union = static function (string $a, string $b) use (&$parent, $find): void {
            $ra = $find($a); $rb = $find($b);
            if ($ra !== $rb) $parent[$rb] = $ra;
        };

        // Правило A: совпадающий FP => все его IP и сам FP — одна кампания
        foreach ($entities['fp'] as $fpKey => $fpE) {
            $fpNode = 'fp:' . $fpKey;
            $find($fpNode);
            foreach ($fpE['ips'] as $ip) {
                if (trim((string)$ip) !== '') $union($fpNode, 'ip:' . trim((string)$ip));
            }
        }

        // Правила B/C: объединяем «плохие» IP-сущности (без FP) по подсети
        // с тем же topPath, либо по общему UA. Берём только кандидатов ПФ и
        // сущности с заметными повторами, чтобы не склеивать случайных людей.
        $minHits = $this->w('campaign_subnet_min_hits', 8);
        $maskV4  = $this->w('campaign_subnet_mask_v4', 24);
        $prefixV6 = $this->w('campaign_subnet_prefix_v6', 48);

        $joinable = []; // node => ['subnet'=>..., 'topPath'=>..., 'uas'=>[...], 'hits'=>...]
        foreach (['ip', 'fp'] as $type) {
            foreach ($entities[$type] as $key => $e) {
                $node = $type . ':' . $key;
                if (!$e['isPFCandidate'] && (int)$e['topUrlHits'] < $minHits && (int)($e['topPathHits'] ?? 0) < $minHits) {
                    continue; // слишком слабый кандидат — не склеиваем
                }
                $subnets = [];
                if ($type === 'ip') {
                    $sn = self::subnetOf($key, $maskV4, $prefixV6);
                    if ($sn !== null) $subnets[$sn] = true;
                } else {
                    foreach ($e['ips'] as $ip) {
                        $sn = self::subnetOf((string)$ip, $maskV4, $prefixV6);
                        if ($sn !== null) $subnets[$sn] = true;
                    }
                }
                $uas = [];
                foreach ($e['uas'] as $ua) $uas[md5((string)$ua)] = true;
                $joinable[$node] = [
                    'subnet'  => array_keys($subnets),
                    'topPath' => (string)($e['topPath'] !== '' ? $e['topPath'] : $e['topUrl']),
                    'uas'     => $uas,
                    'hits'    => max((int)$e['topUrlHits'], (int)($e['topPathHits'] ?? 0)),
                ];
            }
        }

        // Индекс: подсеть => узлы; UA(md5) => узлы. Группы одного размера
        // соединяем только если топ-URL совпадает (campaign_require_same_top).
        $bySubnet = [];
        $byUa = [];
        foreach ($joinable as $node => $info) {
            foreach ($info['subnet'] as $sn) $bySubnet[$sn][] = $node;
            foreach (array_keys($info['uas']) as $u) $byUa[$u][] = $node;
        }

        $needSameTop = !empty($this->cfg['campaign_require_same_top'] ?? true);
        $maxCampaignSize = $this->w('campaign_max_size', 500);

        $mergeGroups = static function (array $index) use ($joinable, $union, $needSameTop, $maxCampaignSize): void {
            foreach ($index as $nodes) {
                if (count($nodes) < 2 || count($nodes) > $maxCampaignSize) continue;
                $first = array_shift($nodes);
                foreach ($nodes as $n) {
                    if ($needSameTop && $joinable[$first]['topPath'] !== $joinable[$n]['topPath']) continue;
                    $union($first, $n);
                }
            }
        };
        $mergeGroups($bySubnet);
        $mergeGroups($byUa);

        // --- Шаг 3: сборка групп -> кампании ---
        $groups = []; // root => [node,...]
        foreach ($entities['ip'] as $key => $_) $groups[$find('ip:' . $key)]['ip:' . $key] = true;
        foreach ($entities['fp'] as $key => $_) $groups[$find('fp:' . $key)]['fp:' . $key] = true;

        $campaigns = [];
        foreach ($groups as $root => $nodeSet) {
            $nodes = array_keys($nodeSet);

            // Участники группы: пары [type, key]
            $members = [];
            foreach ($nodes as $node) {
                [$t, $k] = explode(':', $node, 2);
                if (isset($entities[$t][$k])) $members[] = [$t, $k];
            }

            // Кампания имеет смысл, если: (а) есть хотя бы один PF-кандидат,
            // (б) группа больше одной сущности (пул прокси) с явными повторами.
            $hasCandidate = false; $maxHits = 0;
            foreach ($members as [$t, $k]) {
                if (!empty($entities[$t][$k]['isPFCandidate'])) $hasCandidate = true;
                $maxHits = max($maxHits, (int)$entities[$t][$k]['topUrlHits']);
            }
            if (!$hasCandidate && (count($members) < 2 || $maxHits < $minHits)) continue;

            // --- Агрегат кампании ---
            $ips = []; $fps = []; $uas = []; $sessionsCount = 0; $totalRequests = 0;
            $captchaShown = 0; $captchaPassed = 0; $csrfErrors = 0;
            $pathDayAgg = [];      // path => [date => hits] (объединённый)
            $refCatAgg = [];       // категория => кол-во
            $ysclidReq = 0; $utmReq = 0; $reqSum = 0;
            $firstSeen = ''; $lastSeen = '';
            $bestScore = 0; $bestType = 'ip'; $bestValue = '';
            $entityIds = [];

            foreach ($members as [$mt, $mk]) {
                $e =& $entities[$mt][$mk];
                $entityIds[] = $e['type'] . ':' . $e['value'];
                foreach ($e['ips'] as $ip) if (trim((string)$ip) !== '') $ips[$ip] = true;
                foreach ($e['fps'] as $fp) $fps[$fp] = true;
                if ($e['type'] === 'fp') $fps[$e['value']] = true;
                foreach ($e['uas'] as $ua) $uas[(string)$ua] = true;
                $sessionsCount += (int)$e['sessions'];
                $totalRequests += (int)$e['requests'];
                $captchaShown  += (int)$e['captchaShown'];
                $captchaPassed += (int)$e['captchaPassed'];
                $csrfErrors    += (int)($e['csrfErrors'] ?? 0);
                $ysclidReq     += (int)($e['ysclidRequests'] ?? 0);
                $utmReq        += (int)($e['utmReferrerRequests'] ?? 0);
                $reqSum        += max(1, (int)$e['requests']);
                foreach ($e['refCatCounts'] as $c => $n) $refCatAgg[$c] = ($refCatAgg[$c] ?? 0) + (int)$n;
                // объединяем дневную статистику по путям из topPathDaySeries
                foreach ((array)($e['topPathDaySeries'] ?? []) as $d => $n) {
                    $tp = (string)($e['topPath'] ?? '');
                    if ($tp === '') continue;
                    $pathDayAgg[$tp][$d] = ($pathDayAgg[$tp][$d] ?? 0) + (int)$n;
                }
                if ($e['firstSeen'] !== '' && ($firstSeen === '' || $e['firstSeen'] < $firstSeen)) $firstSeen = $e['firstSeen'];
                if ($e['lastSeen'] > $lastSeen) $lastSeen = $e['lastSeen'];
                if ((int)$e['pfScore'] > $bestScore) { $bestScore = (int)$e['pfScore']; $bestType = $e['type']; $bestValue = (string)$e['value']; }
                unset($e);
            }

            $ips = array_keys($ips); sort($ips, SORT_STRING);
            $fps = array_keys($fps); sort($fps, SORT_STRING);
            $uas = array_keys($uas);

            // Топ-путь кампании = путь с максимумом суммарных дневных хитов
            $topPath = ''; $topPathTotal = 0;
            foreach ($pathDayAgg as $p => $days) {
                $sumv = array_sum($days);
                if ($sumv > $topPathTotal) { $topPathTotal = $sumv; $topPath = $p; }
            }
            $topSeries = $pathDayAgg[$topPath] ?? [];
            ksort($topSeries, SORT_STRING);
            $topPathDays = count($topSeries);
            $urlDayMax = $topSeries ? max($topSeries) : 0;

            // refererPattern кампании
            $yish = (int)($refCatAgg['yandex'] ?? 0) + (int)($refCatAgg['yandex_proxy'] ?? 0);
            $refTotal = max(1, array_sum($refCatAgg));
            $hasYsOnTop = false;
            foreach ($members as [$t2, $k2]) {
                if (($entities[$t2][$k2]['topPath'] ?? '') === $topPath && !empty($entities[$t2][$k2]['topPathHasYsclid'])) $hasYsOnTop = true;
            }
            if ($hasYsOnTop && $yish > 0) $refererPattern = 'yandex_with_ysclid';
            elseif ($yish / $refTotal >= 0.5) $refererPattern = (isset($refCatAgg['yandex_proxy']) && $refCatAgg['yandex_proxy'] > ($refCatAgg['yandex'] ?? 0)) ? 'yandex_proxy' : 'yandex';
            elseif (($refCatAgg['google'] ?? 0) / $refTotal >= 0.5) $refererPattern = 'google';
            elseif (($refCatAgg['direct'] ?? 0) / $refTotal >= 0.5) $refererPattern = 'direct';
            else $refererPattern = 'other';

            // Итоговый PF-вес кампании: максимум из участником + бонус за размер пула
            $poolBonus = 0;
            if (count($ips) >= 5) $poolBonus = $this->w('pf_ip_per_fp_5', 30);
            elseif (count($ips) >= 3) $poolBonus = $this->w('pf_ip_per_fp_3', 20);
            elseif (count($ips) >= 2 && count($fps) >= 1) $poolBonus = $this->w('pf_ip_per_fp_2', 10);
            // бонус начисляем только если он ещё не учтён в лучшей FP-сущности
            $campaignWeight = min(150, $bestScore + ($bestType === 'ip' ? $poolBonus : 0));

            $threshold = $this->w('pf_threshold', 80);
            $suspectThreshold = $this->w('pf_suspect_threshold', 50);
            $isPF = $campaignWeight >= $threshold;

            if ($isPF && $topPathTotal >= $this->w('block_min_top_url_hits', 10) && $topPathDays >= $this->w('block_min_top_url_days', 2)) {
                $verdict = 'block';
            } elseif ($campaignWeight >= $suspectThreshold) {
                $verdict = 'suspect';
            } else {
                $verdict = 'watch';
            }

            $id = 'campaign_' . substr(md5($bestType . '|' . $bestValue . '|' . $topPath), 0, 16);

            $campaigns[] = [
                'id' => $id,
                'fingerprints' => $fps,
                'ips' => $ips,
                'userAgents' => array_slice($uas, 0, 5),
                'primaryType' => $bestType,
                'primaryValue' => $bestValue,
                'entityIds' => $entityIds,
                'topUrl' => $topPath,
                'topUrlHits' => $topPathTotal,
                'topUrlDays' => $topPathDays,
                'urlDayMax' => $urlDayMax,
                'topUrlDaySeries' => $topSeries,   // date => hits (график 6.1/6.4)
                'ipsCount' => count($ips),
                'fpCount' => count($fps),
                'sessionsCount' => $sessionsCount,
                'totalRequests' => $totalRequests,
                'refererPattern' => $refererPattern,
                'refererYandexRatio' => round($yish / $refTotal * 100),
                'ysclidRatio' => round($ysclidReq / max(1, $reqSum) * 100),
                'captchaShown' => $captchaShown,
                'captchaPassed' => $captchaPassed,
                'csrfErrors' => $csrfErrors,
                'pfWeight' => $campaignWeight,
                'riskScore' => min(100, $campaignWeight),
                'riskVerdict' => $isPF ? 'pf_campaign' : $verdict,
                'isPFCampaign' => $isPF,
                'firstSeen' => $firstSeen,
                'lastSeen' => $lastSeen,
            ];

            // Помечаем сущности-участников
            if ($isPF || count($ips) >= 2) {
                foreach ($members as [$t3, $k3]) {
                    $e =& $entities[$t3][$k3];
                    $e['campaignId'] = $id;
                    if ($isPF && ((bool)$e['isPFCandidate'] || (int)$e['pfScore'] >= $suspectThreshold)) {
                        $e['isPFCampaign'] = true;
                    }
                    unset($e);
                }
            }
        }

        usort($campaigns, static fn(array $a, array $b): int =>
            ($b['riskScore'] <=> $a['riskScore'])
            ?: ($b['topUrlHits'] <=> $a['topUrlHits'])
            ?: strcmp((string)$b['lastSeen'], (string)$a['lastSeen']));

        // --- Шаг 4: глобальные данные для новых графиков dashboard ---
        $charts = $this->buildChartData($entities, $campaigns);

        return [$entities, $campaigns, $charts];
    }

    /* ==================================================================
     * Данные для графиков 6.1–6.4
     * ================================================================== */

    private function buildChartData(array $entities, array $campaigns): array
    {
        // 6.1 Календарь повторов топ-URL: по всем campaign-сериям строим
        // общий счётчик «день => суммарные заходы на накручиваемые URL».
        $calendar = [];
        foreach ($campaigns as $c) {
            foreach ($c['topUrlDaySeries'] as $d => $n) {
                $calendar[$d] = ($calendar[$d] ?? 0) + (int)$n;
            }
        }
        ksort($calendar, SORT_STRING);
        $calendar = array_slice($calendar, -14, null, true); // последние 14 дней

        // 6.2 Scatter «Разнообразие vs Повтор»: одна точка на сущность
        $scatter = [];
        foreach (['ip', 'fp'] as $type) {
            foreach ($entities[$type] as $e) {
                if ((int)$e['requests'] < 5) continue;
                if ($type === 'ip' && !empty($e['fps'])) continue; // покрыта FP-карточкой
                $scatter[] = [
                    'label' => $e['type'] . ':' . $e['value'],
                    'uniqueUrls' => (int)$e['uniqueUrls'],
                    'share' => (int)$e['dominantUrlShare'],
                    'requests' => (int)$e['requests'],
                    'verdict' => (string)$e['riskVerdict'],
                    'isPF' => !empty($e['isPFCampaign']),
                ];
            }
        }
        // Ограничим выборку, чтобы SVG не захлебнулся
        usort($scatter, static fn($a, $b) => $b['requests'] <=> $a['requests']);
        $scatter = array_slice($scatter, 0, 300);

        // 6.3 Sankey-подобный FP -> IP: топ-5 FP по числу IP
        $fpPool = [];
        foreach ($entities['fp'] as $fp => $e) {
            $cnt = count($e['ips']);
            if ($cnt < 2) continue;
            $fpPool[] = [
                'fp' => $fp,
                'ips' => array_slice($e['ips'], 0, 40),
                'ipCount' => $cnt,
                'verdict' => (string)$e['riskVerdict'],
                'isPF' => !empty($e['isPFCampaign']),
            ];
        }
        usort($fpPool, static fn($a, $b) => $b['ipCount'] <=> $a['ipCount']);
        $fpPool = array_slice($fpPool, 0, 5);

        // 6.4 Heatmap URL x дни для топ-5 ПФ-сущностей/кампаний
        $daysAll = [];
        foreach ($calendar as $d => $_) $daysAll[] = $d;
        // добавим дни из серий кампаний, которых нет в календаре
        foreach ($campaigns as $c) {
            foreach ($c['topUrlDaySeries'] as $d => $_) $daysAll[$d] = true;
        }
        $daysAll = array_keys($daysAll);
        sort($daysAll, SORT_STRING);
        $daysAll = array_slice($daysAll, -14);

        $heatRows = [];
        $rowsSrc = $campaigns ?: [];
        // если кампаний нет — берём топ-5 сущностей с признаками ПФ
        if (!$rowsSrc) {
            $cand = [];
            foreach (['ip', 'fp'] as $type) {
                foreach ($entities[$type] as $e) {
                    if ((int)($e['urlDayMax'] ?? 0) >= 3 && (int)($e['topPathDays'] ?? 0) >= 2) $cand[] = $e;
                }
            }
            usort($cand, static fn($a, $b) => ($b['urlDayMax'] ?? 0) <=> ($a['urlDayMax'] ?? 0));
            foreach (array_slice($cand, 0, 5) as $e) {
                $heatRows[] = [
                    'label' => $e['type'] . ':' . substr((string)$e['value'], 0, 18),
                    'url' => (string)($e['topPath'] ?: $e['topUrl']),
                    'series' => (array)($e['topPathDaySeries'] ?? []),
                ];
            }
        } else {
            foreach (array_slice($rowsSrc, 0, 5) as $c) {
                $heatRows[] = [
                    'label' => $c['primaryType'] . ':' . substr((string)$c['primaryValue'], 0, 18),
                    'url' => (string)$c['topUrl'],
                    'series' => (array)$c['topUrlDaySeries'],
                ];
            }
        }

        return [
            'pfCalendar' => $calendar,          // 6.1: date => hits
            'pfScatter' => $scatter,            // 6.2
            'fpIpPool' => $fpPool,              // 6.3
            'pfHeat' => ['days' => $daysAll, 'rows' => $heatRows], // 6.4
            'pfAnomalyThreshold' => 5,          // красная линия на 6.1
        ];
    }

    /* ==================================================================
     * Утилиты
     * ================================================================== */

    /**
     * Ключ подсети для IP: IPv4 -> "/24-префикс", IPv6 -> "/48-префикс".
     * Возвращает null, если адрес не разбирается.
     */
    public static function subnetOf(string $ip, int $maskV4 = 24, int $prefixV6 = 48): ?string
    {
        $ip = trim($ip);
        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) return null;

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $ip);
            $keep = intdiv($maskV4, 8); // /24 => 3 октета
            return 'v4:' . implode('.', array_slice($parts, 0, max(1, $keep)));
        }

        // IPv6: нормализуем и берём первые N бит как /48-префикс
        $bin = @inet_pton($ip);
        if ($bin === false) return null;
        $bytes = intdiv($prefixV6, 8); // /48 => 6 байт
        return 'v6:' . bin2hex(substr($bin, 0, max(1, $bytes)));
    }
}
