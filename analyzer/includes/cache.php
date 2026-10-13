<?php
/**
 * AntiBot Analyzer — lightweight analytics cache.
 *
 * Parses a large antibot.log on every page view is wasteful. This helper
 * caches the aggregated analytics JSON next to the log (or in the analyzer
 * directory) and invalidates it automatically when the log changes
 * (size + mtime fingerprint).
 */

declare(strict_types=1);

final class AnalyzerCache
{
    private string $cacheDir;

    public function __construct(string $cacheDir)
    {
        if (!is_dir($cacheDir)) {
            @mkdir($cacheDir, 0700, true);
        }
        $this->cacheDir = rtrim($cacheDir, '/');
    }

    private function pathFor(string $logFile): string
    {
        return $this->cacheDir . '/analytics-' . md5($logFile) . '.json';
    }

    /**
     * Return cached payload if the log fingerprint matches, otherwise null.
     */
    public function get(string $logFile): ?array
    {
        $path = $this->pathFor($logFile);
        if (!is_file($path) || !is_readable($path)) return null;

        $payload = json_decode((string)@file_get_contents($path), true);
        if (!is_array($payload) || empty($payload['fingerprint'])) return null;

        clearstatcache(true, $logFile);
        $fp = $this->fingerprint($logFile);
        if ($fp === null || $payload['fingerprint'] !== $fp) return null;

        return $payload['data'] ?? null;
    }

    public function put(string $logFile, array $data): void
    {
        $path = $this->pathFor($logFile);
        $fp = $this->fingerprint($logFile);
        if ($fp === null) return;

        $tmp = $path . '.tmp.' . getmypid();
        $json = json_encode([
            'fingerprint' => $fp,
            'savedAt' => date('Y-m-d H:i:s'),
            'data' => $data,
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        if (@file_put_contents($tmp, $json, LOCK_EX) !== false) {
            @rename($tmp, $path);
        } else {
            @unlink($tmp);
        }
    }

    private function fingerprint(string $logFile): ?string
    {
        clearstatcache(true, $logFile);
        $size = @filesize($logFile);
        $mtime = @filemtime($logFile);
        if ($size === false || $mtime === false) return null;
        return $size . ':' . $mtime;
    }
}
