<?php
/**
 * AntiBot Analyzer — optimized single-pass streaming log parser.
 *
 * Reads the native AntiBot log line-by-line (streaming, bounded memory),
 * aggregates per-RayID sessions and keeps bounded timestamp lists per
 * session so behavioral metrics (repeat visits, interval regularity)
 * can be computed without holding every raw line in memory.
 *
 * КЛЮЧЕВОЕ ПРАВИЛО АНАЛИЗАТОРА: рассматриваются ТОЛЬКО посетители,
 * успешно прошедшие CAPTCHA («Successfully passed the captcha»).
 * Поведенческие боты накрутки ПФ решают капчу и только после этого
 * влияют на показатели Яндекс.Метрики; весь остальной трафик
 * (не прошедшие проверку, роботы, прямые блокировки) из анализа
 * исключается на уровне парсера.
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
         * Пауза между запросами одного клиента (IP+UA+FP), разрывающая
         * сессию. RayID — это ID отдельного HTTP-запроса Cloudflare, а не
         * сессия посетителя: реальные клиентские сессии склеиваются из
         * RayID-записей именно по этому правилу.
         */
        public const SESSION_GAP_SEC = 1800; // 30 минут

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
                'requestLineCount' => 0,   // REQ-строки (запросы к URL)
                'blockLineCount' => 0,     // BLOCK-строки (страница блокировки и т.п.)
                'captchaShowLineCount' => 0, // CAPTCHA-строки («показано» + «пройдено»)
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
                'requestBuckets' => [], // точные счётчики запросов по часу; не зависит от лимита requestTimes
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
         * ПОТОК РАЗБОРА:
         *  1) сбор строк лога в «запросовые» RayID-блоки;
         *  2) ОТБРОС всего, что не относится к борьбе с накруткой ПФ:
         *     индексирующих роботов, whitelist-трафика и, главное,
         *     всех, кто НЕ прошёл CAPTCHA успешно;
         *  3) склейка оставшихся RayID-записей в реальные клиентские
         *     сессии (IP+UA+FP, простой > SESSION_GAP_SEC разрывает сессию).
         *
         * На выходе — ТОЛЬКО сущности, прошедшие капчу. Их поведение
         * (повторы тех же URL, периодичность, скорость решения капчи)
         * и анализируется дальше.
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
                    $s['requestLineCount']++;

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
                    $hourBucket = substr($timestamp, 0, 13) . ':00';
                    $s['requestBuckets'][$hourBucket] = ($s['requestBuckets'][$hourBucket] ?? 0) + 1;

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
                        /*
                         * Реферер с собственного домена — это НЕ внешний переход.
                         * Накрутка ПФ маскируется так: запрос приходит уже с
                         * ?utm_referrer=https%3A%2F%2Fzsay.ru%2F... внутри URL,
                         * а HTTP-Referer при этом указывает на сам сайт
                         * (бот «переклеивает» ссылку). Такой REF не должен
                         * считаться яндексовым — иначе метрика врёт.
                         */
                        if ($cat === 'yandex_proxy') {
                            $reqHost = strtolower((string)preg_replace('/:\d+$/', '', (string)($_SERVER['HTTP_HOST'] ?? '')));
                            if ($reqHost === '') $reqHost = 'zsay.ru'; // дефолт проекта
                            $refHost = strtolower((string)parse_url($ref, PHP_URL_HOST));
                            if ($refHost === $reqHost || str_ends_with($refHost, '.' . $reqHost)) {
                                $cat = 'own_site';
                            }
                        }
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
                        $s['captchaShowLineCount']++;
                        if (count($s['showTimes']) < 100) $s['showTimes'][] = $timestamp;
                        if ($message !== '') $s['captchaReason'] = $message;
                    } elseif (stripos($message, 'Successfully passed the captcha') !== false) {
                        $s['captchaPassCount']++;
                        $s['captchaShowLineCount']++;
                        $s['captchaPassed'] = true;
                        if (count($s['passTimes']) < 100) $s['passTimes'][] = $timestamp;
                    }
                } elseif ($first === 'D') {
                    if (stripos($message, 'Displaying the verification page') !== false) {
                        $s['verificationPageCount']++;
                    }
                }

                // Считаем только явные события блокировки, а не URL вроде /access-blocked-colab/.
                if (
                    stripos($message, 'Display the blocking page') !== false ||
                    preg_match('/^FingerPrint blocked$/i', $message) === 1 ||
                    preg_match('/^IP blocked$/i', $message) === 1
                ) {
                    $s['blocked'] = true;
                    $s['blockCount']++;
                    $s['blockLineCount']++;
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

                /*
                 * --- Пересчёт «сессий» в настоящем смысле слова ---
                 * RayID — это ID одного HTTP-запроса Cloudflare, а НЕ сессия
                 * посетителя. Реальная сессия клиента = связка IP + UA + FP,
                 * разбитая по времени простоя (по умолчанию 30 минут).
                 * Один клиент, ходящий на сайт весь день, — ОДНА сессия,
                 * даже если его запросы имеют десятки разных RayID.
                 */
                $spanSec = max(0, strtotime(str_replace(' ', 'T', $session['lastSeen']))
                                   - strtotime(str_replace(' ', 'T', $session['firstSeen'])));
                $session['durationSec'] = $spanSec;
                $session['clientKey'] = $session['ip'] . '|' . implode(',', $session['userAgents'])
                    . '|' . ($session['fingerprint'] ?: '-');
                $session['isProxyRay'] = ($session['requestCount'] <= 1 && $spanSec < 5);

                // pathFlags compacted to a list of [path, ys, ut] triples (JSON-friendly)
                $flags = [];
                foreach ($session['pathFlags'] as $p => $fl) {
                    $flags[] = ['path' => $p, 'ys' => $fl['ys'], 'ut' => $fl['ut']];
                }
                $session['pathFlags'] = $flags;
            }
            unset($session);

            /*
             * =================================================================
             * ФИЛЬТР «ТОЛЬКО ПРОШЕДШИЕ CAPTCHA»
             * =================================================================
             * Анализатор борется с поведенческими ботами накрутки ПФ, а они
             * обязательно решают капчу — иначе не попадут на сайт и не
             * исказят метрику. Поэтому из анализа исключается ВСЁ лишнее:
             *  - индексирующие роботы (не люди, ПФ не накручивают);
             *  - whitelist-трафик;
             *  - все, кто НЕ написал «Successfully passed the captcha»
             *    (показалась, но не прошла / закрыла страницу / заблок.).
             * Остаются только RayID-сессии с успешным прохождением капчи.
             */
            $totalRaySessions = count($sessions);
            $passedRaySessions = 0;
            foreach ($sessions as $key => $sess) {
                if (empty($sess['captchaPassed'])
                    || !empty($sess['isRobot'])
                    || !empty($sess['isWhitelisted'])) {
                    unset($sessions[$key]);
                } else {
                    $passedRaySessions++;
                }
            }

            /*
             * --- Склейка RayID-записей в реальные клиентские сессии ---
             * Группируем по clientKey (IP+UA+FP), внутри группы сортируем по
             * времени и режем цепочку при простое > SESSION_GAP_SEC.
             * Результат: каждая запись = одна поведенческая сессия клиента,
             * ПРОШЕДШЕГО капчу; исходные RayID сохраняются в rayIds.
             */
            // Перед склейкой все set/map-поля должны быть ассоциативными картами.
            // Иначе fingerprints/pathFlags, уже преобразованные в списки выше,
            // при повторной склейке превращаются в ключи 0,1,... вместо реальных FP/path.
            foreach ($sessions as &$session) {
                $session['fingerprints'] = array_fill_keys((array)$session['fingerprints'], true);
                $session['userAgents'] = array_fill_keys((array)$session['userAgents'], true);
                $session['referrers'] = array_fill_keys((array)$session['referrers'], true);
                $normalizedFlags = [];
                foreach ((array)$session['pathFlags'] as $fl) {
                    if (!is_array($fl) || empty($fl['path'])) continue;
                    $path = (string)$fl['path'];
                    $normalizedFlags[$path] = ['ys' => !empty($fl['ys']), 'ut' => !empty($fl['ut'])];
                }
                $session['pathFlags'] = $normalizedFlags;
            }
            unset($session);

            // Группировка по clientKey; ключ приводим к строке явно, чтобы
            // numeric-подобные IP не превращались PHP в целые ключи массива.
            $groupIdx = [];
            $pos = 0;
            foreach ($sessions as $s) {
                $groupIdx[(string)($s['clientKey'] ?? '')][] = $pos++;
            }
            $sessions = array_values($sessions); // нормализуем ключи -> int
            $merged = [];
            foreach ($groupIdx as $key => $idxList) {
                usort($idxList, static fn(int $a, int $b): int
                    => strcmp((string)$sessions[$a]['firstSeen'], (string)$sessions[$b]['firstSeen']));
                $cur = null;
                $curEndTs = 0;
                foreach ($idxList as $idx) {
                    $s = $sessions[$idx];
                    $startTs = strtotime(str_replace(' ', 'T', $s['firstSeen']));
                    $endTs   = strtotime(str_replace(' ', 'T', $s['lastSeen']));
                    if ($cur === null || ($startTs - $curEndTs) > self::SESSION_GAP_SEC) {
                        if ($cur !== null) $merged[] = $cur;
                        $cur = $s;
                        $cur['rayIds'] = [$s['rayId']];
                        $cur['rayCount'] = 1;
                    } else {
                        // присоединяем запрос к текущей сессии клиента
                        $cur['lastSeen'] = max($cur['lastSeen'], $s['lastSeen']);
                        $cur['requestCount'] += (int)$s['requestCount'];
                        $cur['logLineCount'] += (int)$s['logLineCount'];
                        $cur['captchaShowCount'] += $s['captchaShowCount'];
                        $cur['verificationPageCount'] += $s['verificationPageCount'];
                        $cur['captchaPassCount'] += $s['captchaPassCount'];
                        $cur['captchaPassed'] = $cur['captchaPassed'] || $s['captchaPassed'];
                        $cur['blocked'] = $cur['blocked'] || $s['blocked'];
                        $cur['blockCount'] += (int)$s['blockCount'];
                        $cur['requestLineCount'] += (int)$s['requestLineCount'];
                        $cur['blockLineCount'] += (int)$s['blockLineCount'];
                        $cur['captchaShowLineCount'] += (int)$s['captchaShowLineCount'];
                        $cur['csrfErrors'] += (int)$s['csrfErrors'];
                        $cur['ysclidCount'] += (int)$s['ysclidCount'];
                        $cur['utmReferrerCount'] += (int)$s['utmReferrerCount'];
                        $cur['emptyReferrerCount'] += (int)$s['emptyReferrerCount'];
                        $cur['tagSet'] = $cur['tagSet'] || $s['tagSet'];
                        $cur['graylisted'] = $cur['graylisted'] || $s['graylisted'];
                        $cur['isRobot'] = $cur['isRobot'] || $s['isRobot'];
                        $cur['isWhitelisted'] = $cur['isWhitelisted'] || $s['isWhitelisted'];
                        if ($cur['robotName'] === '' && $s['robotName'] !== '') $cur['robotName'] = $s['robotName'];
                        $cur['inBlacklistIp'] = $cur['inBlacklistIp'] || $s['inBlacklistIp'];
                        $cur['inBlacklistFp'] = $cur['inBlacklistFp'] || $s['inBlacklistFp'];
                        $cur['rayIds'][] = $s['rayId'];
                        $cur['rayCount']++;
                        foreach ($s['urls'] as $p => $c)      $cur['urls'][$p] = ($cur['urls'][$p] ?? 0) + $c;
                        foreach ($s['refCats'] as $p => $c)   $cur['refCats'][$p] = ($cur['refCats'][$p] ?? 0) + $c;
                        foreach ($s['requestTimes'] as $t)    $cur['requestTimes'][] = $t;
                        foreach ($s['requestBuckets'] as $b => $cnt) $cur['requestBuckets'][$b] = ($cur['requestBuckets'][$b] ?? 0) + (int)$cnt;
                        foreach ($s['userAgents'] as $ua) $cur['userAgents'][$ua] = true;
                        foreach ($s['referrers'] as $ref) $cur['referrers'][$ref] = true;
                        foreach ($s['showTimes'] as $t)       $cur['showTimes'][] = $t;
                        foreach ($s['passTimes'] as $t)       $cur['passTimes'][] = $t;
                        foreach ($s['fpsValues'] as $v)       $cur['fpsValues'][] = $v;
                        foreach ($s['fingerprints'] as $fp)   $cur['fingerprints'][$fp] = true;
                        foreach ($s['blockEvidence'] as $ev)  $cur['blockEvidence'][] = $ev;
                        foreach ($s['urlPathDays'] as $p => $days) {
                            foreach ($days as $d => $c) $cur['urlPathDays'][$p][$d] = ($cur['urlPathDays'][$p][$d] ?? 0) + $c;
                        }
                        foreach ($s['pathFlags'] as $path => $fl) {
                            if (!isset($cur['pathFlags'][$path])) $cur['pathFlags'][$path] = ['ys' => false, 'ut' => false];
                            if (!empty($fl['ys'])) $cur['pathFlags'][$path]['ys'] = true;
                            if (!empty($fl['ut'])) $cur['pathFlags'][$path]['ut'] = true;
                        }
                        if ($cur['captchaReason'] === '') $cur['captchaReason'] = $s['captchaReason'];
                    }
                    $curEndTs = max($curEndTs, $endTs);
                }
                if ($cur !== null) $merged[] = $cur;
            }

            // Нормализуем склейные поля обратно к формату finalize()
            foreach ($merged as &$m) {
                $m['fingerprints'] = array_keys($m['fingerprints']);
                if (!$m['fingerprints'] && $m['fingerprint'] !== '') $m['fingerprints'] = [$m['fingerprint']];
                $m['fingerprint'] = $m['fingerprints'][0] ?? '';
                arsort($m['urls']);
                $m['requestTimes'] = array_values(array_unique($m['requestTimes']));
                sort($m['requestTimes'], SORT_STRING);
                $m['showTimes'] = array_slice($m['showTimes'], 0, self::MAX_EVENTS_PER_SESSION);
                $m['passTimes'] = array_slice($m['passTimes'], 0, 100);
                $m['fpsValues'] = array_slice($m['fpsValues'], 0, 30);
                $m['blockEvidence'] = array_slice($m['blockEvidence'], 0, 10);
                $m['userAgents'] = array_slice(array_keys($m['userAgents']), 0, 10);
                $m['referrers'] = array_slice(array_keys($m['referrers']), 0, 60);
                $flags = [];
                foreach ((array)$m['pathFlags'] as $p => $fl) {
                    $flags[] = ['path' => (string)$p, 'ys' => !empty($fl['ys']), 'ut' => !empty($fl['ut'])];
                }
                $m['pathFlags'] = $flags;
                $span = max(0, strtotime(str_replace(' ', 'T', $m['lastSeen']))
                               - strtotime(str_replace(' ', 'T', $m['firstSeen'])));
                $m['durationSec'] = $span;
                // Клиентская сессия «прокси-лучок», если это был один RayID-запрос без истории
                $m['isProxyRay'] = ($m['rayCount'] <= 1 && $span < 5);
            }
            unset($m);

            usort($merged, static fn(array $a, array $b): int => strcmp($a['firstSeen'], $b['firstSeen']));
            $sessions = $merged;

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
                    // Статистика фильтрации: только прошедшие CAPTCHA остались в анализе
                    'raySessionsTotal' => $totalRaySessions,
                    'raySessionsPassed' => $passedRaySessions,
                    'raySessionsDropped' => $totalRaySessions - $passedRaySessions,
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
