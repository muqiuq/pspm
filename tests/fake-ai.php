<?php
// A fake OpenAI-compatible API for the smoke test (php -S 127.0.0.1:8099 tests/fake-ai.php).
// It answers from fixed rules, so prompts, answers, the AI log and the decisions can be
// tested without a real key. Every request is appended to /tmp/fake-ai.jsonl.
//
// Model names steer it: fake-500 → HTTP 500, fake-429 → HTTP 429, fake-garbage → not JSON,
// fake-benign → every verdict benign. Otherwise, per purpose (recognised by the instructions):
//   scan verdicts: exploit tags → block 0.95; 21 not-found pages → left out of the answer;
//                  a user agent saying "ignore …" fools it → benign 0.99 (what the injection check prevents)
//   behaviour:     brute force with risk ≥ 90 → attack 0.9, else risky 0.7
//   honeypots:     /.env and /wp-login.php → exact patterns
//   test:          {"ok": true}
declare(strict_types=1);

$path = (string)parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$in = json_decode((string)file_get_contents('php://input'), true) ?: [];
file_put_contents('/tmp/fake-ai.jsonl', json_encode(['path' => $path, 'auth' => $_SERVER['HTTP_AUTHORIZATION'] ?? '', 'body' => $in]) . "\n", FILE_APPEND);
header('Content-Type: application/json');

function out(int $code, mixed $body): never { http_response_code($code); echo is_string($body) ? $body : json_encode($body); exit; }

// a classifier API, Hugging Face style: {"inputs": [...]} → per input a list of labels with scores.
// /classify-broken answers something of another type (the check must fail closed).
if (str_ends_with($path, '/classify')) {
    out(200, array_map(fn($t) => stripos((string)$t, 'ignore') !== false
        ? [['label' => 'INJECTION', 'score' => 0.98], ['label' => 'BENIGN', 'score' => 0.02]]
        : [['label' => 'BENIGN', 'score' => 0.97], ['label' => 'INJECTION', 'score' => 0.03]], (array)($in['inputs'] ?? [])));
}
if (str_ends_with($path, '/classify-broken')) out(200, ['result' => 'everything is fine']);
if (!str_ends_with($path, '/chat/completions')) out(404, ['error' => 'unknown path']);
$model = (string)($in['model'] ?? '');
if ($model === 'fake-500') out(500, ['error' => ['message' => 'internal error (fake)']]);
if ($model === 'fake-429') out(429, ['error' => ['message' => 'rate limited (fake)']]);
$system = (string)($in['messages'][0]['content'] ?? '');
$user = json_decode((string)($in['messages'][1]['content'] ?? '{}'), true) ?: [];

if (str_contains($system, 'connection test')) {
    $answer = ['ok' => true];
} elseif (str_contains($system, 'prompt-injection classifier')) {
    // the chat type of the injection check; fake-check-sloppy leaves out every second item
    $items = [];
    foreach ($user['strings'] ?? [] as $x) {
        if ($model === 'fake-check-sloppy' && $x['i'] % 2 === 1) continue;
        $bad = stripos((string)$x['text'], 'ignore') !== false;
        $items[] = ['i' => $x['i'], 'label' => $bad ? 'injection' : 'safe', 'score' => $bad ? 0.97 : 0.02];
    }
    $answer = ['items' => $items];
} elseif (str_contains($system, 'assess traffic')) {
    $verdicts = [];
    foreach ($user['subjects'] ?? [] as $s) {
        if (($s['not_found'] ?? 0) === 21) continue;   // left out on purpose
        $ua = strtolower(json_encode($s['user_agents'] ?? []) . json_encode($s['untrusted'] ?? []));
        if ($model === 'fake-benign' || str_contains($ua, 'ignore')) $verdicts[] = ['subject' => $s['subject'], 'verdict' => 'benign', 'confidence' => 0.99, 'reason' => 'looks fine'];
        elseif (!empty($s['exploit_tags'])) $verdicts[] = ['subject' => $s['subject'], 'verdict' => 'block', 'confidence' => 0.95, 'reason' => 'exploit attempts'];
        else $verdicts[] = ['subject' => $s['subject'], 'verdict' => 'watch', 'confidence' => 0.5, 'reason' => 'unclear'];
    }
    $answer = ['verdicts' => $verdicts];
} elseif (str_contains($system, 'assess behaviour')) {
    $a = [];
    foreach ($user['findings'] ?? [] as $f) {
        $attack = ($f['pattern'] ?? '') === 'brute_force' && ($f['deterministic_risk'] ?? 0) >= 90;
        $a[] = ['finding' => $f['finding'], 'class' => $attack ? 'attack' : 'risky', 'category' => $f['pattern'] ?? 'other',
            'risk' => $attack ? 95 : 60, 'confidence' => $attack ? 0.9 : 0.7, 'reason' => $attack ? 'credential stuffing' : 'worth a look', 'suggested_action' => 'check'];
    }
    $answer = ['assessments' => $a];
} elseif (str_contains($system, 'honeypot rules')) {
    $p = [];
    foreach ($user['paths'] ?? [] as $x) {
        $xp = $x['path'] ?? ($x['untrusted']['path'][0] ?? '');
        if (in_array($xp, ['/.env', '/wp-login.php'], true)) $p[] = ['host' => '*', 'kind' => 'exact', 'path' => $xp, 'reason' => 'attackers only'];
    }
    $answer = ['patterns' => $p];
} else {
    $answer = ['error' => 'unknown purpose'];
}
$content = $model === 'fake-garbage' ? 'I think this is fine.' : json_encode($answer);
out(200, ['id' => 'fake-' . bin2hex(random_bytes(4)), 'model' => $model . '-2026', 'choices' => [['message' => ['role' => 'assistant', 'content' => $content]]],
    'usage' => ['prompt_tokens' => intdiv(strlen((string)($in['messages'][1]['content'] ?? '')), 4) + 50, 'completion_tokens' => intdiv(strlen($content), 4), 'cost' => 0.00012]]);
