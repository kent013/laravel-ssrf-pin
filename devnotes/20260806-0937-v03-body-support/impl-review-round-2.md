新しい blocking な指摘はありません。追加テストは、Round 1 の「テストで pin できるもの」に対して有効に働いています。

[Suggestion] [impl-review-decisions-round-1.md](/Users/ishitoya/repository/laravel-ssrf-pin/devnotes/20260806-0937-v03-body-support/codex-history/impl-review-decisions-round-1.md)  
`Authorization` 等の credential header を hop 越え転送する件の「見送り」判断自体は妥当です。ただし根拠の置き方は少し整理した方がよいです。妥当性を支える主因は「v0.3 の受入契約外であり、ここで cross-host header stripping まで入れると既存挙動を壊しうる」という後方互換制約です。  
一方で、「body より深刻度が低い」「OIDC 側では `followRedirects: false` 固定なので実害は出ない」は補助的な説明に留めるべきです。パッケージ自体の既定値は依然 `true` で、consumer が常に正しく `false` を選ぶことを防御境界にはできません。ここは「既知の inherited behavior を docs + test で固定し、変更するなら v0.4 の breaking change」と言い切るのが一番筋が通っています。

**テスト評価**

[Suggestion] [PinnedHttpClientBodyTest.php](/Users/ishitoya/repository/laravel-ssrf-pin/tests/Unit/PinnedHttpClientBodyTest.php)  
`never resends the request body on the second and later hops` の更新は有効です。これはトートロジーではありません。初回 request に `Content-Type` と小文字 `content-length` を明示的に混ぜた上で、2 hop 目の `headers` が `['Authorization' => 'Basic zzz']` に完全一致することを見ているので、`withUrlWithoutBody()` の case-insensitive 除去と「他の header は残る」の両方を実際に検証しています。

[Suggestion] [GuzzleCurlTransportBodyTest.php](/Users/ishitoya/repository/laravel-ssrf-pin/tests/Integration/GuzzleCurlTransportBodyTest.php)  
`puts no body bytes on the wire for the follow-up hop of a redirect` も有効です。これは fake transport ではなく実 curl とローカル server 観測なので、`body === ''`、`CONTENT_TYPE` 不在、`CONTENT_LENGTH` が `0` または不在、を wire-level で見ています。常に真になる assertion ではありません。  
厳密にはこの test 単体では「redirect loop の中で `PinnedHttpClient` がその request を作った」ことまでは証明していませんが、その点は上の unit test が埋めています。つまり、unit で「2 hop 目 DTO がそうなる」、integration で「その DTO を transport に渡すと wire に body が乗らない」を分担しており、組み合わせとして十分です。

**結論**

credential header 問題を v0.3 で見送る判断は、後方互換と受入契約の制約下では妥当です。やるべきことは既にほぼ揃っていて、今の差分に追加で要求するなら「見送り理由の主語を compatibility に寄せて明文化する」程度です。実装変更を要求する段階ではありません。

VERDICT: APPROVED