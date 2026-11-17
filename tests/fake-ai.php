<?php
// A fake OpenAI-compatible API for the smoke test (php -S 127.0.0.1:8099 tests/fake-ai.php).
// It answers from fixed rules, so prompts, answers, the AI log and the decisions can be
// tested without a real key. Every request is appended to /tmp/fake-ai.jsonl.
//
// Model names steer it: fake-500 → HTTP 500, fake-429 → HTTP 429, fake-garbage → not JSON,
// fake-benign → every verdict benign, fake-noschema → HTTP 400 for a JSON schema request,
// fake-badtypes → verdicts that are not of the expected type. Otherwise, per purpose (recognised by the instructions):
//   scan verdicts: exploit tags → block 0.95; 41 not-found pages → left out of the answer;
//                  a user agent saying "ignore …" fools it → benign 0.99 (what the injection check prevents)
//   behaviour:     brute force with risk ≥ 90 → attack 0.9, else risky 0.7
//   honeypots:     /.env and /wp-login.php → exact patterns; the verifier confirms them (fake-benign rejects)
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
// a classifier that needs its key (Bearer guard-key), like a hosted endpoint
if (str_ends_with($path, '/classify-auth')) {
    $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if ($auth === '') out(401, ['error' => 'Missing authentication header']);
    if ($auth !== 'Bearer guard-key') out(401, ['error' => 'invalid token']);
    out(200, array_map(fn($t) => stripos((string)$t, 'ignore') !== false ? [['label' => 'INJECTION', 'score' => 0.98]] : [['label' => 'INJECTION', 'score' => 0.02]], (array)($in['inputs'] ?? [])));
}
// a decisions API (OpenRouter /api/alpha/decisions, e.g. typesafe/jev-1.14): typed questions about "state"
if (str_ends_with($path, '/decisions')) {
    if (($_SERVER['HTTP_AUTHORIZATION'] ?? '') === '') out(401, ['error' => ['message' => 'Missing Authentication header', 'code' => 401]]);
    if (!is_string($in['model'] ?? null) || !isset($in['state']) || !is_array($in['questions'] ?? null)) {
        out(400, ['error' => ['message' => json_encode([['expected' => 'string', 'code' => 'invalid_type', 'path' => ['model'], 'message' => 'Invalid input']]), 'code' => 400]]);
    }
    $answers = [];
    foreach ($in['questions'] as $q => $def) {
        if (($in['model'] ?? '') === 'fake-jev-refuse') { $answers[$q] = ['type' => 'refusal']; continue; }
        $text = (string)(is_array($in['state']) ? ($in['state'][$q] ?? '') : $in['state']);
        $answers[$q] = ['type' => 'noul', 'noul' => stripos($text, 'ignore') !== false ? 0.97 : 0.03, 'confidence' => 0.9];
    }
    out(200, ['id' => 'gen-dec-fake', 'model' => $in['model'] . '-20261101', 'provider' => 'TypeSafe', 'answers' => $answers,
        'usage' => ['input_tokens' => 40 * count($answers), 'output_tokens' => count($answers), 'cost' => 0.00001]]);
}
if (!str_ends_with($path, '/chat/completions')) out(404, ['error' => 'unknown path']);
$model = (string)($in['model'] ?? '');
if ($model === 'fake-noschema' && ($in['response_format']['type'] ?? '') === 'json_schema') out(400, ['error' => ['message' => 'response_format json_schema is not supported for this model']]);
if ($model === 'fake-500') out(500, ['error' => ['message' => 'internal error (fake)']]);
if ($model === 'fake-slow') { http_response_code(200); echo ' '; flush(); sleep(12); }   // headers at once, then a model that takes too long
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
        if (($s['not_found'] ?? 0) === 41) continue;   // left out on purpose
        $ua = strtolower(json_encode($s['user_agents'] ?? []) . json_encode($s['untrusted'] ?? []));
        if ($model === 'fake-badtypes') $verdicts[] = ['subject' => $s['subject'], 'verdict' => 'maybe', 'confidence' => 'high'];   // not the expected type
        elseif ($model === 'fake-benign' || str_contains($ua, 'ignore')) $verdicts[] = ['subject' => $s['subject'], 'verdict' => 'benign', 'confidence' => 0.99, 'reason' => 'looks fine'];
        elseif (!empty($s['exploit_tags'])) $verdicts[] = ['subject' => $s['subject'], 'verdict' => 'block', 'confidence' => 0.95, 'reason' => 'exploit attempts'];
        else $verdicts[] = ['subject' => $s['subject'], 'verdict' => 'watch', 'confidence' => 0.5, 'reason' => 'unclear'];
    }
    $answer = ['verdicts' => $verdicts];
} elseif (str_contains($system, 'assess behaviour')) {
    $a = [];
    foreach ($user['findings'] ?? [] as $f) {
        if ($model === 'fake-benign') { $a[] = ['finding' => $f['finding'], 'class' => 'normal', 'risk' => 5, 'confidence' => 0.9, 'reason' => 'normal use']; continue; }
        $attack = ($f['pattern'] ?? '') === 'brute_force' && ($f['deterministic_risk'] ?? 0) >= 90;
        $a[] = ['finding' => $f['finding'], 'class' => $attack ? 'attack' : 'risky', 'category' => $f['pattern'] ?? 'other',
            'risk' => $attack ? 95 : 60, 'confidence' => $attack ? 0.9 : 0.7, 'reason' => $attack ? 'credential stuffing' : 'worth a look', 'suggested_action' => 'check'];
    }
    $answer = ['assessments' => $a];
} elseif (str_contains($system, 'review honeypot rules')) {
    // the verifier on trap proposals: fake-benign rejects every one
    $answer = ['decisions' => array_map(fn($x) => ['p' => $x['p'], 'decision' => $model === 'fake-benign' ? 'reject' : 'confirm', 'reason' => 'checked'], $user['proposals'] ?? [])];
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
