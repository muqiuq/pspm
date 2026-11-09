<?php
declare(strict_types=1);

/** Minimal Markdown for the Help pages: headings, paragraphs, lists, code, tables, links, emphasis. */
final class Markdown
{
    public static function render(string $md): string
    {
        $lines = explode("\n", str_replace("\r", '', $md));
        $out = '';
        $i = 0;
        $n = count($lines);
        while ($i < $n) {
            $l = $lines[$i];
            if (preg_match('/^```/', $l)) {
                $code = [];
                for ($i++; $i < $n && !preg_match('/^```/', $lines[$i]); $i++) $code[] = $lines[$i];
                $out .= '<pre class="bg-body-tertiary p-2 border rounded"><code>' . h(implode("\n", $code)) . "</code></pre>\n";
                $i++;
                continue;
            }
            if (preg_match('/^(#{1,4})\s+(.*)$/', $l, $m)) {
                $lv = strlen($m[1]) + 1;
                $out .= "<h$lv>" . self::inline($m[2]) . "</h$lv>\n";
                $i++;
                continue;
            }
            if (preg_match('/^\|/', $l)) {
                $rows = [];
                for (; $i < $n && preg_match('/^\|/', $lines[$i]); $i++) $rows[] = $lines[$i];
                $out .= '<table class="table table-sm table-bordered">';
                foreach ($rows as $k => $r) {
                    if (preg_match('/^\|[\s:|-]+\|$/', $r)) continue;
                    $cells = array_map('trim', explode('|', trim($r, '|')));
                    $tag = $k === 0 ? 'th' : 'td';
                    $out .= '<tr>' . implode('', array_map(fn($c) => "<$tag>" . self::inline($c) . "</$tag>", $cells)) . '</tr>';
                }
                $out .= "</table>\n";
                continue;
            }
            if (preg_match('/^\s*([-*]|\d+\.)\s+/', $l, $m)) {
                $tag = ctype_digit($m[1][0]) ? 'ol' : 'ul';
                $out .= "<$tag>";
                for (; $i < $n && preg_match('/^\s*([-*]|\d+\.)\s+(.*)$/', $lines[$i], $mm); $i++) $out .= '<li>' . self::inline($mm[2]) . '</li>';
                $out .= "</$tag>\n";
                continue;
            }
            if (trim($l) === '') { $i++; continue; }
            $para = [];
            for (; $i < $n && trim($lines[$i]) !== '' && !preg_match('/^(#|```|\||\s*([-*]|\d+\.)\s)/', $lines[$i]); $i++) $para[] = $lines[$i];
            $out .= '<p>' . self::inline(implode(' ', $para)) . "</p>\n";
        }
        return $out;
    }

    private static function inline(string $s): string
    {
        $s = h($s);
        $s = preg_replace('/`([^`]+)`/', '<code>$1</code>', $s);
        $s = preg_replace('/\*\*([^*]+)\*\*/', '<strong>$1</strong>', $s);
        $s = preg_replace('/(?<![\w*])\*([^*]+)\*(?![\w*])/', '<em>$1</em>', $s);
        return preg_replace_callback('/\[([^\]]+)\]\(([^)\s]+)\)/', function ($m) {
            $url = html_entity_decode($m[2]);
            if (!preg_match('#^(/|https?://|\#)#', $url)) return $m[1];
            return '<a href="' . h($url) . '">' . $m[1] . '</a>';
        }, $s);
    }
}
