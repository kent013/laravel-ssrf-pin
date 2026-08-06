**Findings**

[Warning] [src/PinnedHttpClient.php:76]( /Users/ishitoya/repository/laravel-ssrf-pin/src/PinnedHttpClient.php:76 )  
redirect 2 hop 目以降で `Authorization` 等の credential header がそのまま転送されます。`withUrlWithoutBody()` は body / contentType / `Content-Type` / `Content-Length` だけを落とすため、`Authorization: Basic ...` を使う OIDC token endpoint が 302/307 で攻撃者管理の許可ホストへ redirect した場合、body の `client_secret` は漏れませんが header credential は漏れます。  
ただしこれは提示文どおり v0.2 からの挙動維持で、README に `followRedirects: false` を使うべき場面が明記されています。後方互換を優先する判断として説明可能ですが、OIDC 用途では呼び出し側の既定運用を `followRedirects: false` に固定する必要があります。

[Suggestion] [src/Dtos/PinnedRequest.php:39]( /Users/ishitoya/repository/laravel-ssrf-pin/src/Dtos/PinnedRequest.php:39 ) / [tests/Unit/PinnedHttpClientBodyTest.php:132]( /Users/ishitoya/repository/laravel-ssrf-pin/tests/Unit/PinnedHttpClientBodyTest.php:132 )  
2 hop 目で `Content-Type` を落とす検証はありますが、`Content-Length` を落とす検証がありません。実装は case-insensitive に両方除去しているのでコード上は正しいです。契約として明記しているなら `Content-Length` もテストで pin した方がよいです。

[Suggestion] [src/Transport/GuzzleCurlTransport.php:76]( /Users/ishitoya/repository/laravel-ssrf-pin/src/Transport/GuzzleCurlTransport.php:76 )  
実 transport では POST の body を落としても、Guzzle 側が空 body に対して `Content-Length: 0` を生成する可能性があります。これは secret 漏洩ではなく、受入契約 4 の本質である「body を送らない」は満たします。ただし README の「without `Content-Length` headers」を wire-level 契約にするなら、実 curl の redirect 2 hop 目を観測する integration test が必要です。

**確認結果**

SSRF の正典経路は維持されています。`PinnedHttpClient` は各 hop で inspect → `CurlResolveEntry` → transport の順に通しており、`GuzzleCurlTransport` は引き続き内部生成の `CurlHandler` と `CURLOPT_RESOLVE` を使っています。`followRedirects: false` でも初回 hop の guard は通るため、非追従モードが pin を迂回する経路にはなっていません。

body 上限の設計は成立しています。`sink` に `ByteLimitedStream` を渡し、上限を跨ぐ chunk で `write()` が短い戻り値 `0` を返すため、Guzzle curl handler 経由で libcurl の write error になり、読み切り前に中断されます。成功パスでも `hasExceededLimit()` を再確認しており、切り詰め body を成功として返す構造にはなっていません。

後方互換も、提示差分上は守られています。`PinnedRequest` / `PinnedResponse` は trailing default parameter 追加、`fetch()` は第 3 引数 default `true`、`new GuzzleCurlTransport` も無引数で構築可能です。既存 enum case の値も変更されていません。

受入契約 5 項目は概ね対応するテストがあります。特に body 送信、response body、`BodyTooLarge`、非追従 redirect、2 hop 目 body 除去、fake transport 記録はトートロジーだけではなく実装経路を検証しています。上記の `Content-Length` wire-level だけは補強余地です。

VERDICT: APPROVED