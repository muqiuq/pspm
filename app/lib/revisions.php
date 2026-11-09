<?php
declare(strict_types=1);

/** Working copy → "Ready to apply" → immutable revision (plan §7.7). */
final class Revisions
{
    public static function sha(array $doc): string
    {
        return hash('sha256', json_canonical($doc, false));
    }

    public static function latest(): ?array
    {
        return DB::one('SELECT id, created_at, author, message, sha256 FROM config_revisions ORDER BY id DESC LIMIT 1');
    }

    public static function get(int $id): ?array
    {
        $r = DB::one('SELECT * FROM config_revisions WHERE id = ?', [$id]);
        if ($r) $r['document'] = json_dec($r['document']);
        return $r;
    }

    public static function list(int $limit = 50): array
    {
        return DB::all('SELECT id, created_at, author, message, sha256 FROM config_revisions ORDER BY id DESC LIMIT ?', [$limit]);
    }

    /** Has the working copy changed since the newest revision? */
    public static function workingChanged(): bool
    {
        $l = self::latest();
        return !$l || $l['sha256'] !== self::sha(Model::document());
    }

    /** @return array{0: ?int, 1: array} revision id, or the reasons it cannot be committed */
    public static function commit(string $message): array
    {
        $doc = Model::document();
        $errors = Model::checkDocument($doc);
        if ($errors) return [null, $errors];
        $sha = self::sha($doc);
        $l = self::latest();
        if ($l && $l['sha256'] === $sha) return [(int)$l['id'], []];
        $id = (int)DB::val('INSERT INTO config_revisions (author, message, document, sha256) VALUES (?, ?, ?::jsonb, ?) RETURNING id',
            [Audit::actor(), mb_substr(trim($message), 0, 500), json_canonical($doc, false), $sha]);
        Audit::log('revision.commit', "revision:$id", ['message' => $message]);
        // For the SSH login message (the agent cannot read the DB).
        try { write_atomic(PSPM_STATE . '/revision.json', json_enc(['latest' => $id, 'at' => gmdate('c')]), 0644); } catch (Throwable) {}
        return [$id, []];
    }

    /** What install.sh reads (bin/revision.php). */
    public static function export(?int $id = null): ?array
    {
        $id ??= (int)(self::latest()['id'] ?? 0);
        $r = $id ? self::get($id) : null;
        if (!$r) return null;
        return ['id' => (int)$r['id'], 'sha256' => $r['sha256'], 'author' => $r['author'], 'message' => $r['message'],
            'created_at' => $r['created_at'], 'document' => $r['document']];
    }

    /** Load a revision back into the working copy. */
    public static function revertTo(int $id): void
    {
        $r = self::get($id);
        if (!$r) throw new RuntimeException("no revision $id");
        $doc = $r['document'];
        DB::tx(function () use ($doc, $id) {
            DB::q('DELETE FROM site_hosts');
            DB::q('DELETE FROM sites WHERE NOT (id = ANY(?::uuid[]))', ['{' . implode(',', array_column($doc['sites'], 'id')) . '}']);
            DB::q('DELETE FROM backends WHERE NOT (id = ANY(?::uuid[]))', ['{' . implode(',', array_column($doc['backends'], 'id')) . '}']);
            foreach ($doc['backends'] as $b) {
                $id2 = $b['id']; unset($b['id']);
                DB::q('INSERT INTO backends (id, name, config, updated_by) VALUES (?, ?, ?::jsonb, ?)
                       ON CONFLICT (id) DO UPDATE SET name = excluded.name, config = excluded.config, updated_at = now(), updated_by = excluded.updated_by',
                    [$id2, $b['name'], json_enc($b), Audit::actor()]);
            }
            foreach ($doc['sites'] as $s) {
                $id2 = $s['id']; unset($s['id']);
                DB::q('INSERT INTO sites (id, name, config, updated_by) VALUES (?, ?, ?::jsonb, ?)
                       ON CONFLICT (id) DO UPDATE SET name = excluded.name, config = excluded.config, updated_at = now(), updated_by = excluded.updated_by',
                    [$id2, $s['hosts'][0], json_enc($s), Audit::actor()]);
                foreach ($s['hosts'] as $h) DB::q('INSERT INTO site_hosts (host, site_id) VALUES (?, ?)', [$h, $id2]);
            }
            Settings::saveGlobal($doc['global']);
            Audit::log('revision.revert', "revision:$id");
        });
    }

    public static function applies(int $limit = 20): array
    {
        return DB::all('SELECT * FROM applies ORDER BY finished_at DESC LIMIT ?', [$limit]);
    }

    public static function lastApply(): ?array
    {
        return DB::one("SELECT * FROM applies WHERE result IN ('applied', 'warnings') ORDER BY finished_at DESC LIMIT 1");
    }
}
