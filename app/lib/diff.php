<?php
declare(strict_types=1);

/** Line diffs for the Changes page (working copy vs live, drift vs manifest). */
final class Diff
{
    /** Unified diff of two texts. Empty string when equal. */
    public static function unified(string $a, string $b, string $nameA = 'a', string $nameB = 'b', int $context = 3): string
    {
        if ($a === $b) return '';
        $x = $a === '' ? [] : explode("\n", rtrim($a, "\n"));
        $y = $b === '' ? [] : explode("\n", rtrim($b, "\n"));
        $ops = self::ops($x, $y);
        $out = "--- $nameA\n+++ $nameB\n";
        $n = count($ops);
        $i = 0;
        while ($i < $n) {
            while ($i < $n && $ops[$i][0] === '=') $i++;
            if ($i >= $n) break;
            $start = max(0, $i - $context);
            $end = $i;
            // extend the hunk while changes are close together
            while ($end < $n) {
                if ($ops[$end][0] !== '=') { $end++; continue; }
                $run = 0;
                while ($end + $run < $n && $ops[$end + $run][0] === '=') $run++;
                if ($end + $run >= $n || $run > 2 * $context) { $end = min($n, $end + $context); break; }
                $end += $run;
            }
            $la = $lb = 0; $ca = $cb = 0;
            foreach (array_slice($ops, 0, $start) as $op) { if ($op[0] !== '+') $la++; if ($op[0] !== '-') $lb++; }
            $body = '';
            for ($k = $start; $k < $end; $k++) {
                [$t, $line] = $ops[$k];
                $body .= ($t === '=' ? ' ' : $t) . $line . "\n";
                if ($t !== '+') $ca++;
                if ($t !== '-') $cb++;
            }
            $out .= sprintf("@@ -%d,%d +%d,%d @@\n", $la + 1, $ca, $lb + 1, $cb) . $body;
            $i = $end;
        }
        return $out;
    }

    /** Edit script via LCS; large inputs fall back to a plain replace. */
    private static function ops(array $x, array $y): array
    {
        // trim the common prefix and suffix first (cheap and the usual case)
        $pre = 0;
        while ($pre < count($x) && $pre < count($y) && $x[$pre] === $y[$pre]) $pre++;
        $suf = 0;
        while ($suf < count($x) - $pre && $suf < count($y) - $pre && $x[count($x) - 1 - $suf] === $y[count($y) - 1 - $suf]) $suf++;
        $mx = array_slice($x, $pre, count($x) - $pre - $suf);
        $my = array_slice($y, $pre, count($y) - $pre - $suf);
        $ops = [];
        foreach (array_slice($x, 0, $pre) as $l) $ops[] = ['=', $l];
        if (count($mx) * count($my) > 4_000_000) {
            foreach ($mx as $l) $ops[] = ['-', $l];
            foreach ($my as $l) $ops[] = ['+', $l];
        } else {
            $m = count($mx); $n = count($my);
            $L = array_fill(0, $m + 1, array_fill(0, $n + 1, 0));
            for ($i = $m - 1; $i >= 0; $i--) for ($j = $n - 1; $j >= 0; $j--) {
                $L[$i][$j] = $mx[$i] === $my[$j] ? $L[$i + 1][$j + 1] + 1 : max($L[$i + 1][$j], $L[$i][$j + 1]);
            }
            $i = $j = 0;
            while ($i < $m && $j < $n) {
                if ($mx[$i] === $my[$j]) { $ops[] = ['=', $mx[$i]]; $i++; $j++; }
                elseif ($L[$i + 1][$j] >= $L[$i][$j + 1]) { $ops[] = ['-', $mx[$i++]]; }
                else { $ops[] = ['+', $my[$j++]]; }
            }
            while ($i < $m) $ops[] = ['-', $mx[$i++]];
            while ($j < $n) $ops[] = ['+', $my[$j++]];
        }
        foreach (array_slice($x, count($x) - $suf) as $l) $ops[] = ['=', $l];
        return $ops;
    }

    /** Diff two file maps (path => content). */
    public static function trees(array $a, array $b): array
    {
        $out = [];
        $paths = array_unique(array_merge(array_keys($a), array_keys($b)));
        sort($paths);
        foreach ($paths as $p) {
            $d = self::unified($a[$p] ?? '', $b[$p] ?? '', isset($a[$p]) ? "live/$p" : '/dev/null', isset($b[$p]) ? "new/$p" : '/dev/null');
            if ($d !== '') $out[$p] = ['status' => !isset($a[$p]) ? 'added' : (!isset($b[$p]) ? 'removed' : 'changed'), 'diff' => $d];
        }
        return $out;
    }
}
