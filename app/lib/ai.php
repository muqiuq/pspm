<?php
declare(strict_types=1);

/**
 * OpenAI-compatible chat API (OpenRouter by default), plan §15.3 and
 * docs/security-ai-improvements.md. Only pseudonymised evidence is sent: no addresses,
 * certificates, link tokens or user names. Every call is logged in ai_calls (the AI log).
 *
 * Models have roles, each with its own settings: "main" (verdicts, behaviour, honeypot
 * mining), and, added by later steps, "check" (injection check) and "verify" (verifier).
 */
final class AI
{
    public const DEFAULTS = ['base_url' => 'https://openrouter.ai/api/v1', 'model' => '', 'key_enc' => '', 'mode' => 'enforce',
        'daily_cap' => 200, 'min_interval_min' => 15, 'confidence' => 0.85, 'analyse_authorised' => true, 'reaction_hours' => 24];
    public const ROLES = ['main' => 'Main model'];
    public const PURPOSES = ['scan' => 'Scan verdicts', 'behaviour' => 'Behaviour', 'honeypots' => 'Honeypots', 'test' => 'Test'];

    /** The decision settings and the main model (Settings → Runtime → AI). */
    public static function settings(): array
    {
        $s = Settings::get('ai', []);
        return array_replace(self::DEFAULTS, is_array($s) ? $s : []);
    }

    /** The effective configuration of a model role: model, base_url, key_enc, daily_cap. */
    public static function model(string $role = 'main'): array
    {
        $s = self::settings();
        return ['role' => 'main', 'model' => (string)$s['model'], 'base_url' => (string)$s['base_url'],
            'key_enc' => (string)$s['key_enc'], 'daily_cap' => (int)$s['daily_cap']];
    }

    public static function configured(string $role = 'main'): bool
    {
        $m = self::model($role);
        return $m['model'] !== '' && ($m['key_enc'] !== '' || self::isLocal($m['base_url']));
    }

    /** Calls allowed now: configured, not in collect mode (main), under the model's daily cap. */
    public static function available(string $role = 'main'): bool
    {
        if (!self::configured($role)) return false;
        if ($role === 'main' && self::settings()['mode'] === 'collect') return false;
        return self::callsToday($role) < self::model($role)['daily_cap'];
    }

    /** API calls of a model in the last 24 h (every call counts, failed ones too). */
    public static function callsToday(string $role = 'main'): int
    {
        return (int)DB::val("SELECT count(*) FROM ai_calls WHERE role = ? AND at > now() - interval '24 hours'", [$role]);
    }

    /** Plain HTTP is accepted only for a service on this box (a local classifier, the test API). */
    public static function isLocal(string $url): bool
    {
        $h = strtolower(trim((string)parse_url($url, PHP_URL_HOST), '[]'));
        return in_array($h, ['127.0.0.1', 'localhost', '::1'], true);
    }

    /** Why a base URL cannot be used, or null. */
    public static function urlProblem(string $url): ?string
    {
        if (!Validate::url($url)) return 'Not a URL.';
        if (parse_url($url, PHP_URL_SCHEME) !== 'https' && !self::isLocal($url)) return 'HTTPS only (plain HTTP only for 127.0.0.1 or localhost).';
        return null;
    }

    /**
     * One chat call that must answer a JSON object. Logged in ai_calls in every case.
     * $ps is the pseudonymiser of the payload: its map is stored with the call (locally).
     * @return array{0: array, 1: int} the decoded object and the id of the logged call
     * @throws RuntimeException on transport or format errors (after logging them)
     */
    public static function call(string $role, string $purpose, string $system, array $payload, ?object $ps = null): array
    {
        $m = self::model($role);
        $request = ['system' => $system, 'user' => $payload];
        $log = ['role' => $role, 'purpose' => $purpose, 'model' => $m['model'], 'request' => $request,
            'pseudonyms' => $ps && method_exists($ps, 'map') ? $ps->map() : []];
        $t0 = microtime(true);
        try {
            if ($p = self::urlProblem($m['base_url'])) throw new RuntimeException("AI API URL: $p");
            $key = $m['key_enc'] !== '' ? Crypto::open($m['key_enc']) : '';
            $body = ['model' => $m['model'], 'temperature' => 0, 'response_format' => ['type' => 'json_object'],
                'messages' => [['role' => 'system', 'content' => $system], ['role' => 'user', 'content' => json_enc($payload)]]];
            if (str_contains((string)parse_url($m['base_url'], PHP_URL_HOST), 'openrouter.ai')) $body['usage'] = ['include' => true];   // cost in the answer
            $headers = ['Content-Type: application/json', 'X-Title: PSPM security scan', 'HTTP-Referer: https://pspm.local/'];
            if ($key !== '') $headers[] = "Authorization: Bearer $key";
            $ch = curl_init(rtrim($m['base_url'], '/') . '/chat/completions');
            curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => json_enc($body), CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 90,
                CURLOPT_CONNECTTIMEOUT => 10, CURLOPT_HTTPHEADER => $headers,
                CURLOPT_PROTOCOLS => self::isLocal($m['base_url']) ? CURLPROTO_HTTP | CURLPROTO_HTTPS : CURLPROTO_HTTPS]);
            $res = curl_exec($ch);
            $log['status'] = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $err = curl_error($ch);
            curl_close($ch);
            if ($key !== '') sodium_memzero($key);
            $log['response'] = $res === false ? null : substr((string)$res, 0, 100000);
            if ($res === false || $log['status'] !== 200) throw new RuntimeException("AI API: HTTP {$log['status']} " . ($err ?: substr((string)$res, 0, 300)));
            $d = json_decode((string)$res, true);
            $content = (string)($d['choices'][0]['message']['content'] ?? '');
            $log['response'] = substr($content, 0, 100000);
            $log['model_answer'] = isset($d['model']) ? (string)$d['model'] : null;
            $log['tokens_in'] = isset($d['usage']['prompt_tokens']) ? (int)$d['usage']['prompt_tokens'] : null;
            $log['tokens_out'] = isset($d['usage']['completion_tokens']) ? (int)$d['usage']['completion_tokens'] : null;
            $log['cost'] = isset($d['usage']['cost']) && is_numeric($d['usage']['cost']) ? (float)$d['usage']['cost'] : null;
            if (preg_match('/\{.*\}/s', $content, $mm)) $content = $mm[0];
            $out = json_decode($content, true);
            if (!is_array($out)) throw new RuntimeException('AI API: the answer is not a JSON object');
            $log['result'] = $out;
            return [$out, self::log($log, $t0)];
        } catch (Throwable $e) {
            $log['error'] = mb_substr($e->getMessage(), 0, 1000);
            self::log($log, $t0);
            throw $e instanceof RuntimeException ? $e : new RuntimeException($e->getMessage(), 0, $e);
        }
    }

    private static function log(array $l, float $t0): int
    {
        return (int)DB::val('INSERT INTO ai_calls (role, purpose, model, model_answer, request, response, result, status, duration_ms, tokens_in, tokens_out, cost, error, pseudonyms)
            VALUES (?, ?, ?, ?, CAST(? AS jsonb), ?, CAST(? AS jsonb), ?, ?, ?, ?, ?, ?, CAST(? AS jsonb)) RETURNING id',
            [$l['role'], $l['purpose'], $l['model'], $l['model_answer'] ?? null, json_enc($l['request']), $l['response'] ?? null,
             isset($l['result']) ? json_enc($l['result']) : null, $l['status'] ?? 0, (int)round((microtime(true) - $t0) * 1000),
             $l['tokens_in'] ?? null, $l['tokens_out'] ?? null, $l['cost'] ?? null, $l['error'] ?? null, json_enc((object)($l['pseudonyms'] ?? []))]);
    }

    /** A fixed, harmless request to check a model's settings (Settings → Test). */
    public static function test(string $role): array
    {
        [$out, $id] = self::call($role, 'test', 'This is a connection test. Answer only this JSON object: {"ok": true}', ['test' => 'pspm']);
        $c = DB::one('SELECT model_answer, duration_ms FROM ai_calls WHERE id = ?', [$id]);
        return ['ok' => ($out['ok'] ?? null) === true, 'answer' => $out, 'model' => $c['model_answer'] ?? null, 'ms' => (int)($c['duration_ms'] ?? 0)];
    }

    /** Stable pseudonyms within one call: ip-1, cert-2, user-3 … (the map stays local). */
    public static function pseudonymiser(): object
    {
        return new class {
            private array $map = [];
            private array $n = [];
            public function of(string $kind, string $value): string
            {
                $k = "$kind\0$value";
                if (!isset($this->map[$k])) { $this->n[$kind] = ($this->n[$kind] ?? 0) + 1; $this->map[$k] = $kind . '-' . $this->n[$kind]; }
                return $this->map[$k];
            }
            public function reverse(string $p): ?string
            {
                foreach ($this->map as $k => $v) if ($v === $p) return explode("\0", $k, 2)[1];
                return null;
            }
            /** pseudonym → real value, for the AI log on this box */
            public function map(): array
            {
                $o = [];
                foreach ($this->map as $k => $v) $o[$v] = explode("\0", $k, 2)[1];
                return $o;
            }
        };
    }

    /** Remove query values and long ids from a path before it leaves the box. */
    public static function scrubPath(string $p): string
    {
        $p = preg_replace('/\?.*$/', '?…', $p) ?? $p;
        $p = preg_replace('#/[0-9a-f]{16,}#i', '/{hex}', $p) ?? $p;
        $p = preg_replace('#/\d{4,}#', '/{n}', $p) ?? $p;
        $p = preg_replace('#/\.pspm/access/[^/]+#', '/.pspm/access/{token}', $p) ?? $p;
        return substr($p, 0, 200);
    }
}
