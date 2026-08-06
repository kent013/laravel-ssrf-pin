# 対応マトリクス: impl-review Round 2

Round 2 の判定は **VERDICT: APPROVED** (Critical 0 / Warning 0 / Suggestion 3、うち 2 件は
「追加テストは有効でトートロジーではない」という評価であり対応不要)。

## [Suggestion] credential header 見送りの根拠は「後方互換」に主語を寄せて明文化せよ

- 判断: **対応する** (文書のみ。実装・テストは変更なし)
- 根拠: 指摘のとおり。「OIDC 側は `followRedirects: false` 固定だから実害が出ない」は
  **防御境界の根拠にならない** — package の既定は `followRedirects: true` のままであり、
  consumer が常に正しく false を選ぶことを前提にした防御は防御ではない。
  正しい言い方は「v0.2 から継承した既知の挙動を docs + test で固定し、
  変更するなら v0.4 の breaking change として行う」である。
- 対応内容: `impl-review-decisions-round-1.md` の Warning 節を書き直し、
  (a) 主因を後方互換に一本化、(b) 「実害が無い」論拠を明示的に降格し
  「防御境界にはできない」と記載、(c) v0.4 での破壊的変更候補として残す、を反映した。

## [Suggestion] 追加した unit テストの評価

- 判断: **対応不要** (「トートロジーではない。case-insensitive 除去と他 header の残存の両方を
  実際に検証している」という肯定評価)

## [Suggestion] 追加した integration テストの評価

- 判断: **対応不要** (「実 curl + server 観測で wire-level を見ており常に真になる assertion ではない。
  unit が『2 hop 目 DTO がそうなる』を、integration が『その DTO を送ると wire に body が乗らない』を
  分担しており、組み合わせとして十分」という肯定評価)

## v0.4 以降への申し送り

- cross-host redirect での credential header (`Authorization` / `Cookie` / `Proxy-Authorization` 等) の
  除去は **破壊的変更**として v0.4 で扱う。実施するなら「hop の origin (scheme+host+port) が
  初回 hop と異なる場合に限り除去」が定石であり、除去したことを観測できるテストを同時に置くこと。

## 最終ゲート実測

- `composer test`: 48 passed (158 assertions)
- `composer phpstan`: level 10, No errors
- `vendor/bin/pint --test`: passed
