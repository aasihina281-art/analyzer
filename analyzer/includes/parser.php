<?php
/**
 * AntiBot Analyzer — optimized single-pass streaming log parser.
 *
 * Reads the native AntiBot log line-by-line (streaming, bounded memory),
 * aggregates per-RayID sessions and keeps bounded timestamp lists per
 * session so behavioral metrics (repeat visits, interval regularity)
 * can be computed without holding every raw line in memory.
 *
 * Native log format:
 *   YYYY-MM-DD HH:MM:SS RAYID IP MESSAGE
 */

declare(strict_types=1);

if (!class_exists('AntiBotLogParser')) {
    final class AntiBotLogParser
    {
        /** Max stored request timestamps per session (interval analysis). */
        private const MAX_EVENTS_PER_SESSION = 1500;

        /**
         * Классификация реферера по категориям. Возвращает одну из:
         * 'yandex' | 'google' | 'vk' | 'yandex_proxy' | 'direct' | 'other'.
         * Использует карту хостов из pf-config (если подключён) + жёсткие
         * fallback-правила, чтобы парсер работал и без конфига.
         *
         * @param string $referrer полный URL реферера ('' = прямой заход)
         */
        public static function classifyReferrer(string $referrer): string
        {
            if ($referrer === '') return 'direct';

            // Хост из начала строки (без схемы), в нижнем регистре
            $host = strtolower((string)parse_url($referrer, PHP_URL_HOST));
            if ($host === '') {
                // Реферер без схемы («yandex.ru/page») — возьмём первую часть до /
                $host = strtolower(strtok($referrer, '/'));
            }
            if ($host === '') return 'other';

            // Карта из конфига (zsay.ru и т.п. — прокси-переклейка Яндекса)
            static $map = null;
            if ($map === null) {
                $cfgFile = __DIR__ . '/pf-config.php';
                $map = is_file($cfgFile) ? ((array)require $cfgFile)['referer_map'] ?? [] : [];
            }
            if (isset($map[$host])) return $map[$host];

            // Fallback-правила на случай расширения списка без конфига
            if (str_ends_with($host, '.yandex.ru') || $host === 'yandex.ru' || $host === 'ya.ru') return 'yandex';
            if (str_ends_with($host, '.google.') || $host === 'google.com') return 'google';
            if ($host === 'vk.com' || str_ends_with($host, '.vk.com') || $host === 'm.vk.com') return 'vk';

            return 'other';
        }

        /**
         * Запрос = строка лога, где после IP идёт путь, начинающийся с "/"
         * (или полный http(s)-URL). Все прочие строки (REF:, PTR:, UA:, FP:,
         * FPS:, "Show captcha", "Displaying the verification page", "Tag set",
         * "Found in list", "Display the blocking page" и т.п.) — служебные
         * события ТОГО ЖЕ запроса и запросами не считаются.
         */
        public static function isRequestLine(string $message): bool
        {
            return ($message[0] ?? '') === '/' || preg_match('#^https?://#i', $message) === 1;
        }

        /** Нормализация URL запроса: путь без query, хвостовой слэш убирается. */
        public static function requestPath(string $message): string
        {
            $path = (string)preg_replace('/\?.*$/', '', $message);
            if ($path === '') return '/';
            if ($path !== '/') {
                $path = rtrim($path, '/');
                if ($path === '') return '/';
            }
            return $path;
        }

        /** Есть ли в URL метки клика из поиска Яндекса (ysclid= / utm_referrer=). */
        public static function urlHasYsclid(string $url): bool
        {
            return stripos($url, 'ysclid=') !== false;
        }

        public static function urlHasUtmReferrer(string $url): bool
        {
            return stripos($url, 'utm_referrer=') !== false;
        }

        private static function newSession(string $rayId, string $ip, string $timestamp): array
        {
            return [
                'rayId' => $rayId,
                'ip' => $ip,
                'firstSeen' => $timestamp,
                'lastSeen' => $timestamp,
                'requestCount' => 0,    // число HTTP-запросов (строки-URL), НЕ строк лога
                'logLineCount' => 0,    // всего строк лога в сессии (служебные + запросы)
                'urls' => [],           // path (без query) => hit count — один запрос = +1
                'urlPathDays' => [],    // path (без query) => [date => hits] — для графика повторов по дням
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
                'userAgents' => [],
                'referrers' => [],
                'emptyReferrerCount' => 0,
                'fpsValues' => [],
                'tagSet' => false,
                'inBlacklistIp' => false,
                'inBlacklistFp' => false,
                'graylisted' => false,
                'showTimes' => [],
                'passTimes' => [],
                'requestTimes' => [],
                // --- Новые поля: признаки накрутки ПФ ---
                'csrfErrors' => 0,          // Error: CSRF-token expired/not found
                'ysclidCount' => 0,         // запросов с ysclid= в URL
                'utmReferrerCount' => 0,    // запросов с utm_referrer= в URL
                'refCats' => [],            // категория реферера => счётчик событий
                'pathFlags' => [],          // path => ['ys'=>bool,'ut'=>bool] — флаги меток по уникальным путям
            ];
        }

        /**
         * Parse a log FILE in one streaming pass. Memory-friendly for big logs.
         *
         * @return array{sessions: array<int,array>, meta: array}
         */
        public static function parseFile(
            string $logFile,
            ?string $timeFrom = null,
            ?string $timeTo = null,
            ?string $searchTerm = null
        ): array {
            $handle = @fopen($logFile, 'rb');
            if ($handle === false) {
                return ['sessions' => [], 'meta' => ['error' => 'cannot_open']];
            }

            $sessions = [];
            $lineCount = 0;
            $needle = ($searchTerm !== null && $searchTerm !== '') ? strtolower($searchTerm) : null;

            while (($line = fgets($handle)) !== false) {
                $lineCount++;
                $line = rtrim($line, "\r\n");
                if ($line === '') continue;

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

                if ($timeFrom !== null && $timeFrom !== '' && $timestamp < $timeFrom) continue;
                if ($timeTo !== null && $timeTo !== '' && $timestamp > $timeTo) continue;

                $key = $rayId !== '' ? $rayId : ($ip . '|' . $timestamp);

                if (!isset($sessions[$key])) {
                    $sessions[$key] = self::newSession($rayId, $ip, $timestamp);
                }

                $s =& $sessions[$key];
                $s['logLineCount']++;

                if ($timestamp < $s['firstSeen']) $s['firstSeen'] = $timestamp;
                if ($timestamp > $s['lastSeen']) $s['lastSeen'] = $timestamp;

                // --- Classify message (order matters, cheap checks first) ---
                $first = $message[0] ?? '';

                if (self::isRequestLine($message)) {
                    // HTTP request line: путь, начинающийся с "/" (или полный URL).
                    // Это ЕДИНСТВЕННЫЙ тип строк, который считается запросом.
                    // Все прочие строки (REF:, PTR:, UA:, FP:, FPS:, "Show captcha",
                    // "Displaying the verification page", "Tag set", "Found in list" и т.д.)
                    // — служебные события того же запроса, они НЕ увеличивают requestCount.
                    $s['requestCount']++;

                    // Нормализуем URL до пути без query-строки: одна и та же страница,
                    // приходящая с разными ysclid/utm_referrer, — это ПОВТОР одного URL.
                    $rawUrl = $message;
                    $path = self::requestPath($message);

                    if (isset($s['urls'][$path]) || count($s['urls']) < 300) {
                        $s['urls'][$path] = ($s['urls'][$path] ?? 0) + 1; // path => hit count
                    }
                    if (count($s['requestTimes']) < self::MAX_EVENTS_PER_SESSION) {
                        $s['requestTimes'][] = $timestamp;
                    }

                    // --- Накрутка ПФ: метки клика из поиска + повторы пути по дням ---
                    $hasYs = self::urlHasYsclid($rawUrl);
                    $hasUt = self::urlHasUtmReferrer($rawUrl);
                    if ($hasYs) $s['ysclidCount']++;
                    if ($hasUt) $s['utmReferrerCount']++;

                    if (!isset($s['pathFlags'][$path])) {
                        $s['pathFlags'][$path] = ['ys' => false, 'ut' => false];
                    }
                    if ($hasYs) $s['pathFlags'][$path]['ys'] = true;
                    if ($hasUt) $s['pathFlags'][$path]['ut'] = true;

                    $day = substr($timestamp, 0, 10);
                    if (!isset($s['urlPathDays'][$path])) $s['urlPathDays'][$path] = [];
                    if (!isset($s['urlPathDays'][$path][$day])) $s['urlPathDays'][$path][$day] = 0;
                    if (count($s['urlPathDays'][$path]) <= 90) { // защита от раздувания памяти
                        $s['urlPathDays'][$path][$day]++;
                    }
                } elseif ($first === 'R' && stripos($message, 'REF:') === 0) {
                    $ref = trim(substr($message, 4));
                    if ($ref === '') {
                        $s['emptyReferrerCount']++;
                        $s['refCats']['direct'] = ($s['refCats']['direct'] ?? 0) + 1;
                    } else {
                        if (count($s['referrers']) < 60) {
                            $s['referrers'][$ref] = true;
                        }
                        // Категория реферера: yandex / google / vk / yandex_proxy / other
                        $cat = self::classifyReferrer($ref);
                        $s['refCats'][$cat] = ($s['refCats'][$cat] ?? 0) + 1;
                    }
                } elseif ($first === 'E' && (stripos($message, 'CSRF-token expired') !== false
                          || stripos($message, 'CSRF-token not found') !== false)) {
                    // Куки не сохраняются между заходами — резидентные прокси накрутчиков
                    $s['csrfErrors']++;
                } elseif ($first === 'U' && stripos($message, 'UA:') === 0) {
                    $ua = trim(substr($message, 3));
                    if ($ua !== '' && count($s['userAgents']) < 10) {
                        $s['userAgents'][$ua] = true;
                    }
                } elseif ($first === 'F') {
                    if (preg_match('/\bFP:\s*([a-f0-9]{16,128})\b/i', $message, $fpMatch)) {
                        $fp = strtolower($fpMatch[1]);
                        $s['fingerprints'][$fp] = true;
                        $s['fingerprint'] = $fp;
                    } elseif (preg_match('/^FPS:\s*(\d+)/i', $message, $fpsMatch)) {
                        if (count($s['fpsValues']) < 30) {
                            $s['fpsValues'][] = (int)$fpsMatch[1];
                        }
                    } elseif (stripos($message, 'Found in list') !== false) {
                        if (stripos($message, 'blacklist_ip') !== false) $s['inBlacklistIp'] = true;
                        if (stripos($message, 'blacklist_fingerprint') !== false) $s['inBlacklistFp'] = true;
                        if (stripos($message, 'graylist') !== false) $s['graylisted'] = true;
                        if (stripos($message, 'indexbot_rules') !== false) {
                            $s['isRobot'] = true;
                            if ($s['robotName'] === '' && preg_match('/`([^`]+)`/', $message, $rm)) {
                                $s['robotName'] = $rm[1];
                            }
                        }
                    }
                } elseif ($first === 'T' && stripos($message, 'Tag set') !== false) {
                    $s['tagSet'] = true;
                } elseif ($first === 'I' && stripos($message, 'Indexing robot') !== false) {
                    $s['isRobot'] = true;
                    $robot = trim((string)preg_replace('/^.*?Indexing robot\s*:?\s*/i', '', $message));
                    $s['robotName'] = $robot !== '' ? $robot : 'Индексирующий бот';
                } elseif ($first === 'w' && stripos($message, 'whitelist') !== false) {
                    $s['isWhitelisted'] = true;
                } elseif ($first === 'H' && stripos($message, 'HTTP_REFERER allowed') !== false) {
                    $s['isWhitelisted'] = true;
                } elseif ($first === 'S') {
                    if (preg_match('/^Show captcha\b/i', $message)) {
                        $s['captchaShowCount']++;
                        if (count($s['showTimes']) < 100) $s['showTimes'][] = $timestamp;
                        if ($message !== '') $s['captchaReason'] = $message;
                    } elseif (stripos($message, 'Successfully passed the captcha') !== false) {
                        $s['captchaPassCount']++;
                        $s['captchaPassed'] = true;
                        if (count($s['passTimes']) < 100) $s['passTimes'][] = $timestamp;
                    }
                } elseif ($first === 'D') {
                    if (stripos($message, 'Displaying the verification page') !== false) {
                        $s['verificationPageCount']++;
                    }
                }

                // Block detection is global (any message containing these words)
                if (
                    stripos($message, 'blocked') !== false ||
                    stripos($message, 'blocking page') !== false
                ) {
                    $s['blocked'] = true;
                    $s['blockCount']++;
                    if (count($s['blockEvidence']) < 10) {
                        $s['blockEvidence'][] = ['timestamp' => $timestamp, 'message' => $message];
                    }
                }

                unset($s);
            }
            fclose($handle);

            // Finalize: convert sets to lists
            foreach ($sessions as &$session) {
                $session['fingerprints'] = array_keys($session['fingerprints']);
                if (!$session['fingerprints'] && $session['fingerprint'] !== '') {
                    $session['fingerprints'] = [$session['fingerprint']];
                }
                $session['fingerprint'] = $session['fingerprints'][0] ?? '';
                arsort($session['urls']);   // keep url => count, sorted desc
                $session['userAgents'] = array_keys($session['userAgents']);
                $session['referrers'] = array_keys($session['referrers']);
                // pathFlags compacted to a list of [path, ys, ut] triples (JSON-friendly)
                $flags = [];
                foreach ($session['pathFlags'] as $p => $fl) {
                    $flags[] = ['path' => $p, 'ys' => $fl['ys'], 'ut' => $fl['ut']];
                }
                $session['pathFlags'] = $flags;
            }
            unset($session);

            if ($needle !== null) {
                $sessions = array_filter($sessions, static function (array $s) use ($needle): bool {
                    if (stripos((string)($s['ip'] ?? ''), $needle) !== false) return true;
                    foreach (($s['fingerprints'] ?? []) as $fp) {
                        if (stripos((string)$fp, $needle) !== false) return true;
                    }
                    foreach (array_keys(($s['urls'] ?? [])) as $url) {
                        if (stripos((string)$url, $needle) !== false) return true;
                    }
                    return false;
                });
            }

            return [
                'sessions' => array_values($sessions),
                'meta' => [
                    'lines' => $lineCount,
                    'sessions' => count($sessions),
                ],
            ];
        }

        /**
         * Legacy-compatible API: parse a content string.
         */
        public static function parse(string $content, ?string $timeFrom = null, ?string $timeTo = null, ?string $searchTerm = null): array
        {
            $tmp = tempnam(sys_get_temp_dir(), 'antibot_parse_');
            if ($tmp === false) return ['sessions' => [], 'meta' => ['error' => 'tmp']];
            file_put_contents($tmp, $content);
            $res = self::parseFile($tmp, $timeFrom, $timeTo, $searchTerm);
            @unlink($tmp);
            return $res;
        }
    }
}
