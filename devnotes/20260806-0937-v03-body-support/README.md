# v0.3: request / response body 対応と followRedirects

## 何を足したか (受入契約 1-5)

利用側 (Laravel テンプレート t1) のエンタープライズ OIDC SSO 詳細設計 §施策 1 が定めた 5 項目。
OIDC は discovery JSON / JWKS JSON の取得と token endpoint への form-encoded POST + JSON 応答が
すべて body 依存であり、v0.2 では 1 バイトも実装できなかった。

| # | 契約 | 実装 | テスト |
|---|------|------|--------|
| 1 | `GuzzleCurlTransport` が `PinnedRequest::$body` を Guzzle body に渡し `$contentType` を Content-Type に反映 | `GuzzleCurlTransport::send()` / `buildHeaders()` | `tests/Integration/GuzzleCurlTransportBodyTest.php` (実 curl 3 件) |
| 2 | 応答 body を上限バイト数付きで読む (既定 1 MiB。超過は切り捨てず `BodyTooLarge`) | `ByteLimitedStream` を Guzzle `sink` に注入 | `tests/Unit/ByteLimitedStreamTest.php` (6 件) + Integration 3 件 |
| 3 | `fetch()` に `followRedirects: bool = true`。false で 3xx をそのまま返す | `PinnedHttpClient::fetch()` | `tests/Unit/PinnedHttpClientBodyTest.php` (3 件) |
| 4 | redirect 追従時、2 hop 目以降は body を送らない | `PinnedRequest::withUrlWithoutBody()` + hop ループ | Unit 2 件 + Integration 1 件 (wire-level) |
| 5 | `FakePinnedTransport` が body/contentType を記録し応答 body を返せる | `lastRequest()` / `lastEntry()` 追加 | `tests/Unit/PinnedHttpClientBodyTest.php` |

## 上限がストリーム段階で効く理由 (契約 2 の核心)

Guzzle の curl handler は `CURLOPT_WRITEFUNCTION` から `$sink->write($chunk)` を呼び、
その戻り値をそのまま libcurl へ返す。libcurl は**渡した長さと異なる戻り値を書き込みエラーと見なし
転送をその場で中断する** (`CURLE_WRITE_ERROR`)。`ByteLimitedStream::write()` は上限を跨ぐ chunk に
対して 0 を返すので、上限超過の応答は**読み切られず、メモリにも載らない**。
「読み切ってから strlen で測る」形では防御にならない、というのが本契約の主旨である。

副次効果として、Guzzle 既定の `decode_content` により curl が透過的に展開したあとのバイト列が
sink に届くため、上限は**展開後**のバイト数に掛かる (圧縮爆弾も同じ上限で止まる)。

## 後方互換

新規フィールド・新規引数はすべて**既定値つきの末尾追加**。
`tests/Unit/BackwardCompatibilityTest.php` が v0.2 の positional 呼び出し
(`new PinnedRequest($m,$u,$h,$t)` / `new PinnedResponse($s,$h,$f,$hop)` /
`fetch($req,$deadline)` / `new GuzzleCurlTransport`) と既存 enum case を pin する。

## Codex レビュー (gpt-5.5 / high / label impl-review)

- Round 1: `impl-review-round-1.md` — **APPROVED** (Critical 0 / Warning 1 / Suggestion 2)
- Round 2: `impl-review-round-2.md` — **APPROVED** (Critical 0 / Warning 0)
- 対応マトリクス: `codex-history/impl-review-decisions-round-{1,2}.md`

## 積み残し (v0.4 候補・破壊的変更)

cross-host redirect での credential header (`Authorization` / `Cookie` 等) の除去。
v0.2 から継承した挙動であり v0.3 の契約外なので見送った。詳細は
`codex-history/impl-review-decisions-round-2.md` の申し送りを参照。
