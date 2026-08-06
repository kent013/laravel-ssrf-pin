# 対応マトリクス: impl-review Round 1

Round 1 の判定は **VERDICT: APPROVED** (Critical 0 / Warning 1 / Suggestion 2)。
APPROVED ではあるが、Warning / Suggestion のうち「テストで pin できるもの」は本ラウンドで取り込んだ。

## [Warning] redirect 2 hop 目以降で Authorization 等の credential header が転送される

- 判断: **見送る** (v0.3 では挙動を変えない。docs + test で固定し、変更するなら v0.4 の breaking change)
- 根拠 (主因は後方互換の一点。Round 2 の指摘を受けて主語を整理した):
  1. **これは v0.3 で作り込んだ欠陥ではなく、v0.2 から継承した既知の挙動である**。
     本改修の受入契約は「body を再送しない」であり、header の扱いは契約の外側にある。
     ここで cross-host header stripping まで入れると、**受入契約の外で v0.2 の挙動を変える**ことになり、
     既存利用者 (redirect 越しに `Authorization` が生きている前提のコード) を静かに壊す。
     後方互換は本改修の非交渉条件であり、これが見送りの決め手である。
  2. (補助) Codex 自身が「後方互換を優先する判断として説明可能」と評価している。
- **採らない根拠** (Round 2 で明示的に補助へ降格した論拠):
  「利用側 (OIDC) は `followRedirects: false` 固定だから実害が無い」は防御境界の根拠にならない。
  package の既定は依然 `followRedirects: true` であり、**consumer が常に正しく false を選ぶことを
  防御の前提にはできない**。したがって「実害が無い」ではなく
  「継承挙動を docs と test で固定し、変えるなら破壊的変更として v0.4 で行う」と言い切る。
- 対応内容: README に「credentials を header に載せるなら `followRedirects: false` を使え」を明記済み
  (§Redirects and bodies の 3 点目)。加えて単体テストで
  「2 hop 目の headers が `['Authorization' => 'Basic zzz']` のみになる」ことを **正確に pin** した
  (= 将来この挙動を変えるときは必ずテストが赤くなる)。
  cross-host での credential header 除去は **v0.4 以降の独立した破壊的変更候補**として本メモに残す。

## [Suggestion] 2 hop 目で Content-Length が落ちることのテストが無い

- 判断: **対応する**
- 根拠: 契約として README に書いた以上、テストで pin されていないのは禁止事項 1 (テストなしの実装完了) に近い。
- 対応内容: `tests/Unit/PinnedHttpClientBodyTest.php` の
  「never resends the request body on the second and later hops」で
  初回 request の headers に `'content-length' => '26'` (小文字) を混ぜ、
  2 hop 目の headers が `['Authorization' => 'Basic zzz']` に**完全一致**することを検証するようにした
  (case-insensitive な除去も同時に pin される)。

## [Suggestion] 「Content-Length を送らない」の wire-level 検証が無い

- 判断: **対応する**
- 根拠: fake transport 経由の検証は「DTO から落ちていること」しか示さない。
  実 curl / 実 server で「wire に body バイトが 1 つも乗らない」ことまで見ておくべき指摘は妥当。
- 対応内容: `tests/Integration/GuzzleCurlTransportBodyTest.php` に
  「puts no body bytes on the wire for the follow-up hop of a redirect」を追加。
  `PinnedRequest::withUrlWithoutBody()` (= `PinnedHttpClient` が 2 hop 目に作る request そのもの) を
  実 curl で送り、ローカル server の観測で `body === ''` / `CONTENT_TYPE` 不在 /
  `CONTENT_LENGTH` が 0 (または不在) であることを確認した。
  router に `content_length` の観測項目を追加している。

## ゲート再実測 (対応後)

- `composer test`: 48 passed (158 assertions)
- `composer phpstan`: level 10, No errors
- `vendor/bin/pint --test`: passed
