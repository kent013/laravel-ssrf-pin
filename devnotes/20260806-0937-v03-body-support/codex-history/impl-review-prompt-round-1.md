【このパッケージの使命 (North Star)】

`kent013/laravel-ssrf-pin` の使命は **アプリケーション層の SSRF 防御を 1 本の正典経路に閉じること**である。
「URL を検査した IP にだけ接続する (`CURLOPT_RESOLVE` による pin)」「redirect の hop ごとに再検査する
(DNS rebinding / TOCTOU 対策)」「curl が使えない環境では fail-secure する」の 3 つが不変条件であり、
利用側 (家系の複数アプリ) がこの経路を迂回できないことが価値の源泉である。
機能追加は**この不変条件を 1 つも弱めない範囲でのみ**許される。

【禁止事項】

1. テストなしの実装完了報告 (不変条件は対応するテストへの登録まで含めて「実装済み」)
2. PHPStan エラーの widen (型を緩めて黙らせる)・baseline 化・`@phpstan-ignore`
3. 既存テストを削除して上書きすること
4. 記録・成果物をリポジトリ外に置くこと (devnotes が正本)
5. SSRF 防御経路を 2 本に増やすこと (pin を通らない外向き HTTP 経路を作らない)
6. 上限・検査を「後から測る」形にすること (防御は fail-closed かつ発生源で効かせる)

【思考原則 — 全議論に適用】
まず仮説を立てろ。何を検証したいのか、なぜそう考えるのか、どうなれば成功と判断するのかを明確にしてから手を動かせ。仮説なき改善はただの試行錯誤であり、結果から学ぶことができない。

データに真摯に向き合え。成果だけでなく、多様性の変化、構造の揺らぎ、想定外のパターン — 全てが判断材料になる。数値を見て即座に閾値を弄るな。何が起きているのかを理解し、なぜそうなったのかを考え、どの方向に進むべきかを判断してから手を動かせ。

先人の知恵を探せ。自分たちだけで登る必要はない。乗るべき巨人の肩があるなら乗れ。

機能の名前に立ち返れ。名前はその機能が果たすべき役割を示している。現在の設計がその役割を果たしているか、常に問え。

仕組みが機能していない段階で値を弄るな。閾値チューニングやフィールド追加は、設計の方向性が正しいと確認できてから行え。方向性が間違っているなら、値をいくら調整しても意味はない。設計そのものを見直せ。成果が出なければ早期に見切り、次の仮説へ進め。

【ツール使用制限】
コマンド実行・ファイル書き込みは一切行わず、提供されたテキストの分析に集中すること。ファイル読み込みは許可。

---

# system: あなたの役割

あなたはセキュリティに厳格な PHP パッケージのレビュアである。
対象は `kent013/laravel-ssrf-pin` の **v0.3 実装差分** (branch `feat/v0.3-body-support`)。
cwd はこのパッケージのリポジトリなので、必要なら `src/` `tests/` `README.md` を直接読んでよい
(読み込みのみ。コマンド実行・書き込みは禁止)。

## レビュー観点 (この 4 点を軸に判定する)

1. **SSRF 防御を弱めていないか** — per-hop の URL 検査と DNS pin (`CURLOPT_RESOLVE`) の仕組みが
   壊れていないか。body 対応で新たな迂回経路・情報漏洩経路 (リダイレクト先への secret 漏洩、
   メモリ枯渇 DoS) を作っていないか。
2. **後方互換を壊していないか** — v0.2 の公開 API (`PinnedRequest` / `PinnedResponse` の
   positional コンストラクタ、`PinnedHttpClient::fetch($request, $deadline)` の 2 引数呼び出し、
   `new GuzzleCurlTransport` の無引数構築、`TransportError` / `SsrfDenyReason` の既存 case 値) が
   そのまま動くか。
3. **受入契約 5 項目を満たすか** (下記「受入契約」)。各項目に対応するテストが実在し、
   かつ**そのテストが本当にその契約を検証しているか** (トートロジーになっていないか)。
4. **body 上限がストリーム段階で効くか** — 「読み切ってから strlen で測る」形になっていないか。
   巨大応答が read 完了・メモリ確保される前に中断されることが、コードの構造から言えるか。

## 出力形式

- 指摘は **[Critical] / [Warning] / [Suggestion]** のいずれかでラベル付けし、
  該当ファイル・行・根拠 (なぜそれが問題か、どう悪用/破綻するか) を具体的に書くこと。
- 推測で断定しない。確認が必要な点は「確認事項」として分けること。
- 最後に必ず **判定行**を単独で書くこと: `VERDICT: APPROVED` または `VERDICT: CHANGES_REQUESTED`。
- Critical が 0 件で、Warning が「実装を変えずに済む説明可能なもの」だけなら APPROVED でよい。

---

# user: レビュー対象

## 背景

利用側 (Laravel テンプレート t1) にエンタープライズ OIDC SSO を実装する必要がある。
OIDC は discovery JSON / JWKS JSON の取得と token endpoint への form-encoded POST + JSON 応答が
すべて body 依存であるのに対し、v0.2 は
`PinnedRequest` に body が無く、`PinnedResponse` に body が無く、`GuzzleCurlTransport` が
`getBody()` を捨てており、`fetch()` に redirect 非追従の口が無かった。
本差分はその 5 点を **v0.2 互換のまま**足すものである。

## 受入契約 (利用側の詳細設計が定めた仕様。これが正)

1. `GuzzleCurlTransport` が `PinnedRequest::$body` を Guzzle の body に渡し、
   `$contentType` を Content-Type ヘッダに反映する。
2. 応答 body を**上限バイト数付き**で読む (`maxBodyBytes` 既定 1 MiB。
   超過は切り捨てず `PinnedFailure(TransportError::BodyTooLarge)` として失敗させる)。
   上限判定は「読み切ってから測る」のではなく**ストリームを上限まで読んで超過を検出する**形にする。
3. `PinnedHttpClient::fetch()` に `followRedirects: bool = true` を追加し、
   false のとき 3xx を追従せずそのまま `PinnedResponse` で返す。
4. redirect 追従時、**2 hop 目以降は body を送らない** (契約として固定する。
   307/308 の semantics には踏み込まない)。
5. `Testing\FakePinnedTransport` が body / contentType を記録し、応答 body を返せる。

## 実装方針の要点 (レビューで検証してほしい前提)

- 上限は Guzzle の `sink` オプションに `ByteLimitedStream` を渡して掛けている。
  Guzzle の curl handler は `CURLOPT_WRITEFUNCTION` から `$sink->write($chunk)` を呼び、
  その戻り値をそのまま libcurl に返す。libcurl は「渡した長さと異なる戻り値」を
  書き込みエラーと見なし転送を即中断する (`CURLE_WRITE_ERROR`)。
  したがって上限は chunk 到着時点で効き、超過応答は読み切られない、という設計である。
  **この前提が実際に成立しているか**を厳しく見てほしい (成立しないなら Critical)。
- 上限を跨ぐ chunk は 1 バイトも書かない (切り詰めた body を成功として返さないため)。
- 例外化しない実装差分に備え、成功パスでも `hasExceededLimit()` を再確認している。
- 契約 4 は `PinnedRequest::withUrlWithoutBody()` で body/contentType に加え
  `Content-Type` / `Content-Length` ヘッダも落としている。
  一方、`Authorization` 等のその他ヘッダは v0.2 同様 hop をまたいで転送される
  (これは v0.2 からの挙動変更を避けるための判断で、README に「credentials を持つなら
  `followRedirects: false` を使え」と明記した)。この判断の是非も評価してほしい。

## 検証済みのゲート結果 (実測)

- `composer test`: 47 passed (153 assertions) — Unit + Integration (実 curl + ローカル `php -S`)
- `composer phpstan`: level 10, No errors
- `vendor/bin/pint --test`: passed

## 差分 (git diff、staged 全体)

```diff
diff --git a/README.md b/README.md
index 4255056..ee0967b 100644
--- a/README.md
+++ b/README.md
@@ -38,11 +38,82 @@ if ($result instanceof PinnedFailure) {
 
 The neutral `SsrfDenyReason` enum is meant to be mapped (via `match`) into your application's own reason vocabulary — this package does not absorb app-specific taxonomies.
 
+## Request and response bodies (v0.3)
+
+`PinnedRequest` can carry a body, and `PinnedResponse` exposes the response body. Both additions are
+**default-valued trailing parameters**, so every v0.2 positional call site keeps working unchanged.
+
+```php
+$result = $client->fetch(
+    new PinnedRequest(
+        method: 'POST',
+        url: 'https://idp.example.com/oauth2/token',
+        headers: ['Accept' => 'application/json'],
+        body: http_build_query(['grant_type' => 'authorization_code', 'code' => $code]),
+        contentType: 'application/x-www-form-urlencoded',
+    ),
+    Deadline::afterSeconds(10),
+    followRedirects: false,
+);
+
+if ($result instanceof PinnedResponse) {
+    $json = json_decode($result->body, true);
+}
+```
+
+- `contentType` is applied as the `Content-Type` header and **wins** over any `Content-Type` entry in
+  `headers` (so there is exactly one).
+- A request without `body` sends no body at all (unchanged v0.2 behaviour).
+
+### Response body size limit (fail-closed, enforced while streaming)
+
+`GuzzleCurlTransport` reads the response body into a **byte-limited sink**
+(`maxBodyBytes`, default 1 MiB; configurable via `config('ssrf-pin.max_body_bytes')`).
+
+The limit is enforced **at the stream stage**, not after the fact: the sink is wired to libcurl's write
+callback, and a chunk that would cross the limit is refused with a short write, which makes libcurl
+abort the transfer immediately (`CURLE_WRITE_ERROR`). An oversized response is therefore never read to
+completion and never held in memory. Measuring the size after buffering would not be a defense at all.
+
+An oversized response is **not truncated** — it fails with
+`PinnedFailure(TransportError::BodyTooLarge)`. Truncated JSON/JWKS must never look like a success.
+
+Because Guzzle enables transparent content decoding, the limit applies to **decompressed** bytes, so a
+compression bomb is stopped by the same limit.
+
+### Redirects and bodies
+
+- `followRedirects` (default `true`) preserves v0.2 behaviour. Pass `false` to get the `3xx` response
+  back as-is (status, headers, body) without following it. Use this whenever the fetched URL or
+  document will be **trusted afterwards** (OIDC discovery, JWKS, token endpoints): a `302` to another
+  host must not be silently followed and then treated as the origin's answer.
+- **The request body is sent on the first hop only.** When a redirect is followed, hop 2 and later are
+  issued without `body`/`contentType` (and without `Content-Type`/`Content-Length` headers). This is a
+  fixed contract, independent of 307/308 semantics: re-sending a body would hand credentials
+  (`client_secret`, assertions) to an attacker-chosen redirect target.
+- Other headers **are** forwarded across hops. If your headers carry credentials (e.g.
+  `Authorization`), use `followRedirects: false` rather than relying on the hop loop.
+
 ## Design
 
 - **Guard** (`UrlSafetyInspector`): scheme/port allowlist, credential rejection, host normalization (IDN, trailing dot, zone-id, strict-canonical IPv4, octal/hex/decimal rejection, IPv4-mapped IPv6), deny CIDRs (loopback/private/link-local/multicast/reserved), A+AAAA resolution with all-records validation.
 - **Pin** (`GuzzleCurlTransport`): connects via an internally-constructed Guzzle `CurlHandler` only; `CURLOPT_RESOLVE` is a **required** argument of `PinnedCurlTransportInterface::send()` so pin cannot be bypassed; fail-secure (`CurlHandlerUnavailable`) when curl/libcurl is unusable.
-- **Hop loop** (`PinnedHttpClient`): `allow_redirects=false` + explicit loop; every hop goes through the same inspect → pin → send pipeline; per-hop deadline budget; scheme-downgrade rejection; max-hops cap.
+- **Hop loop** (`PinnedHttpClient`): `allow_redirects=false` + explicit loop; every hop goes through the same inspect → pin → send pipeline; per-hop deadline budget; scheme-downgrade rejection; max-hops cap; body sent on the first hop only; optional non-following mode (`followRedirects: false`).
+- **Body limit** (`ByteLimitedStream`): the response sink refuses the chunk that would cross `maxBodyBytes`, aborting the transfer inside libcurl's write callback (fail-closed, never truncating).
+
+## Testing
+
+`Kent013\SsrfPin\Testing\FakePinnedTransport` records every `PinnedRequest` it receives (including
+`body` / `contentType`, reachable via `lastRequest()`) and returns whatever `PinnedResponse` /
+`PinnedFailure` your responder produces — so consumers can pin the body contract without real curl.
+
+```php
+$transport = new FakePinnedTransport(
+    fn (PinnedRequest $r) => new PinnedResponse(200, [], $r->url, [], '{"issuer":"https://idp.example.com"}'),
+);
+$client = new PinnedHttpClient(app(UrlSafetyInspector::class), $transport);
+// ... $transport->lastRequest()?->body
+```
 
 ## License
 
diff --git a/composer.json b/composer.json
index 1de50e2..ea1e03d 100644
--- a/composer.json
+++ b/composer.json
@@ -13,7 +13,9 @@
         "php": "^8.2",
         "ext-curl": "*",
         "guzzlehttp/guzzle": "^7.5",
+        "guzzlehttp/psr7": "^2.4",
         "illuminate/support": "^11.0|^12.0|^13.0",
+        "psr/http-message": "^1.1 || ^2.0",
         "webmozart/assert": "^1.11 || ^2.0"
     },
     "require-dev": {
diff --git a/config/ssrf-pin.php b/config/ssrf-pin.php
index 93c6512..28d6505 100644
--- a/config/ssrf-pin.php
+++ b/config/ssrf-pin.php
@@ -12,6 +12,10 @@ return [
     // redirect 追従の最大 hop 数。
     'max_redirect_hops' => 5,
 
+    // 応答 body の上限バイト数（既定 1 MiB）。超過は切り捨てず TransportError::BodyTooLarge で
+    // 失敗させる。上限は curl の write callback 段階で効くので、巨大応答は読み切られない。
+    'max_body_bytes' => 1_048_576,
+
     // アプリ拡張用の追加 deny CIDR（例: 自社内部レンジ）。
     'additional_deny_cidrs' => [],
 
diff --git a/src/Dtos/PinnedRequest.php b/src/Dtos/PinnedRequest.php
index 7d8a12f..6b8e7fc 100644
--- a/src/Dtos/PinnedRequest.php
+++ b/src/Dtos/PinnedRequest.php
@@ -5,17 +5,48 @@ declare(strict_types=1);
 namespace Kent013\SsrfPin\Dtos;
 
 /**
- * pin 済み fetch の入力。method 非依存（HEAD/GET/任意）。
+ * pin 済み fetch の入力。method 非依存（HEAD/GET/POST/任意）。
+ *
+ * v0.3: `$body` / `$contentType` を追加（既定値つきの末尾追加なので v0.2 の positional
+ * 呼び出しはそのまま動く）。redirect 追従時は **2 hop 目以降に body を送らない**
+ * （`PinnedHttpClient` が hop ごとに body を落とす。README「Redirects and bodies」）。
  */
 final readonly class PinnedRequest
 {
     /**
      * @param  array<string, string>  $headers
+     * @param  string|null  $body  request body（例: `application/x-www-form-urlencoded` の POST）。GET/HEAD では null。
+     * @param  string|null  $contentType  `$body` の Content-Type。指定時は `$headers` の同名エントリより優先される。
      */
     public function __construct(
         public string $method,
         public string $url,
         public array $headers = [],
         public float $connectTimeout = 2.0,
+        public ?string $body = null,
+        public ?string $contentType = null,
     ) {}
+
+    /** URL だけ差し替えた複製（body/contentType は保持する）。 */
+    public function withUrl(string $url): self
+    {
+        return new self($this->method, $url, $this->headers, $this->connectTimeout, $this->body, $this->contentType);
+    }
+
+    /**
+     * URL を差し替え、body / contentType を落とした複製（redirect の 2 hop 目以降で使う）。
+     * body を送らない以上 Content-Type / Content-Length ヘッダも意味を持たないので併せて取り除く。
+     */
+    public function withUrlWithoutBody(string $url): self
+    {
+        $headers = [];
+        foreach ($this->headers as $name => $value) {
+            if (strcasecmp($name, 'Content-Type') === 0 || strcasecmp($name, 'Content-Length') === 0) {
+                continue;
+            }
+            $headers[$name] = $value;
+        }
+
+        return new self($this->method, $url, $headers, $this->connectTimeout);
+    }
 }
diff --git a/src/Dtos/PinnedResponse.php b/src/Dtos/PinnedResponse.php
index 1e0221c..198a106 100644
--- a/src/Dtos/PinnedResponse.php
+++ b/src/Dtos/PinnedResponse.php
@@ -6,18 +6,25 @@ namespace Kent013\SsrfPin\Dtos;
 
 /**
  * pin 済み fetch の成功結果（最終 hop の response）。
+ *
+ * v0.3: `$body` を追加（既定値つきの末尾追加なので v0.2 の positional 呼び出しはそのまま動く）。
+ * body は transport の上限バイト数（既定 1 MiB）以内であることが保証される。
+ * 上限を超えた応答は **切り詰めずに** `PinnedFailure(TransportError::BodyTooLarge)` になるため、
+ * ここに「途中まで」の body が入ることはない。
  */
 final readonly class PinnedResponse
 {
     /**
      * @param  array<string, list<string>>  $headers
      * @param  list<string>  $hopUrls  guard を通過した各 hop の URL（順序保持）。
+     * @param  string  $body  応答 body（上限内の全量）。HEAD や body 無し応答では空文字。
      */
     public function __construct(
         public int $status,
         public array $headers,
         public string $finalUrl,
         public array $hopUrls,
+        public string $body = '',
     ) {}
 
     public function header(string $name): ?string
diff --git a/src/Enums/TransportError.php b/src/Enums/TransportError.php
index adc470e..fef69e6 100644
--- a/src/Enums/TransportError.php
+++ b/src/Enums/TransportError.php
@@ -13,5 +13,7 @@ enum TransportError: string
     case Timeout = 'timeout';
     case ConnectFailed = 'connect_failed';
     case TlsError = 'tls_error';
+    /** 応答 body が transport の上限バイト数を超えた（切り詰めずに失敗させる。v0.3 で追加）。 */
+    case BodyTooLarge = 'body_too_large';
     case Unknown = 'unknown';
 }
diff --git a/src/PinnedHttpClient.php b/src/PinnedHttpClient.php
index f71f03e..bd03391 100644
--- a/src/PinnedHttpClient.php
+++ b/src/PinnedHttpClient.php
@@ -30,7 +30,13 @@ final class PinnedHttpClient
         private readonly int $maxRedirectHops = 5,
     ) {}
 
-    public function fetch(PinnedRequest $request, Deadline $deadline): PinnedResponse|PinnedFailure
+    /**
+     * @param  bool  $followRedirects  false のとき 3xx を追従せずそのまま返す（v0.3 で追加）。
+     *                                 取得した URL/文書を再利用する呼び出し側（OIDC discovery / JWKS /
+     *                                 token など）は false にして、302 で別ホストへ逃げた応答を
+     *                                 誤って信頼しないようにする。
+     */
+    public function fetch(PinnedRequest $request, Deadline $deadline, bool $followRedirects = true): PinnedResponse|PinnedFailure
     {
         if (! $this->transport->isAvailable()) {
             return new PinnedFailure(SsrfDenyReason::CurlHandlerUnavailable, $request->url, 0);
@@ -67,7 +73,12 @@ final class PinnedHttpClient
                 $decision->validatedIps,
             );
 
-            $hopRequest = new PinnedRequest($request->method, $current, $request->headers, $request->connectTimeout);
+            // 契約: body は初回 hop でしか送らない。redirect 先へ認証情報付き body を
+            // 再送すると、攻撃者が誘導した別ホストへ secret が漏れる（307/308 の semantics
+            // には踏み込まず「2 hop 目以降は送らない」で統一する）。
+            $hopRequest = $hop === 0
+                ? $request->withUrl($current)
+                : $request->withUrlWithoutBody($current);
             $result = $this->transport->send($hopRequest, $entry, $deadline);
             if ($result instanceof PinnedFailure) {
                 return new PinnedFailure($result->cause, $current, $hop);
@@ -75,13 +86,18 @@ final class PinnedHttpClient
 
             $status = $result->status;
             if ($status < 300 || $status >= 400) {
-                return new PinnedResponse($status, $result->headers, $current, $hopUrls);
+                return new PinnedResponse($status, $result->headers, $current, $hopUrls, $result->body);
+            }
+
+            // followRedirects=false: 3xx を追従せずそのまま返す（呼び出し側が判断する）。
+            if (! $followRedirects) {
+                return new PinnedResponse($status, $result->headers, $current, $hopUrls, $result->body);
             }
 
             // 3xx: Location 追従
             $location = $result->header('Location');
             if ($location === null || $location === '') {
-                return new PinnedResponse($status, $result->headers, $current, $hopUrls);
+                return new PinnedResponse($status, $result->headers, $current, $hopUrls, $result->body);
             }
 
             $next = $this->resolveAbsoluteUrl($current, $location);
diff --git a/src/SsrfPinServiceProvider.php b/src/SsrfPinServiceProvider.php
index 93c6392..6e02e69 100644
--- a/src/SsrfPinServiceProvider.php
+++ b/src/SsrfPinServiceProvider.php
@@ -19,7 +19,15 @@ final class SsrfPinServiceProvider extends ServiceProvider
         $this->mergeConfigFrom(__DIR__.'/../config/ssrf-pin.php', 'ssrf-pin');
 
         $this->app->bind(DnsResolverInterface::class, SystemDnsResolver::class);
-        $this->app->bind(PinnedCurlTransportInterface::class, GuzzleCurlTransport::class);
+
+        $this->app->bind(PinnedCurlTransportInterface::class, function (Application $app): GuzzleCurlTransport {
+            /** @var array{max_body_bytes?: int} $config */
+            $config = $app->make(ConfigRepository::class)->get('ssrf-pin', []);
+
+            return new GuzzleCurlTransport(
+                $config['max_body_bytes'] ?? GuzzleCurlTransport::DEFAULT_MAX_BODY_BYTES,
+            );
+        });
 
         $this->app->singleton(UrlSafetyInspector::class, function (Application $app): UrlSafetyInspector {
             /** @var array{allowed_schemes?: list<string>, allowed_ports?: list<int>, additional_deny_cidrs?: list<string>, deny_ip_literals?: bool} $config */
diff --git a/src/Testing/FakePinnedTransport.php b/src/Testing/FakePinnedTransport.php
index 5f07665..7e92750 100644
--- a/src/Testing/FakePinnedTransport.php
+++ b/src/Testing/FakePinnedTransport.php
@@ -17,6 +17,9 @@ use Kent013\SsrfPin\Dtos\PinnedResponse;
  *
  * - `$responder` で (PinnedRequest, CurlResolveEntry) → PinnedResponse|PinnedFailure を返す。
  * - 受領した request / resolve entry を記録（pin が検証済み IP で適用されたかを検証可能）。
+ *   request は body / contentType を含む丸ごとの DTO なので、`lastRequest()` で
+ *   「body が transport まで届いたか」「redirect の 2 hop 目に body が再送されていないか」を検証できる。
+ * - 応答 body は `new PinnedResponse(..., body: '...')` で自由に注入できる。
  * - `$available=false` で curl 不在の fail-secure 経路を再現できる。
  */
 final class FakePinnedTransport implements PinnedCurlTransportInterface
@@ -42,6 +45,22 @@ final class FakePinnedTransport implements PinnedCurlTransportInterface
         return $this->available;
     }
 
+    /** 直近に受領した request（body / contentType の到達検証に使う）。未送信なら null。 */
+    public function lastRequest(): ?PinnedRequest
+    {
+        $last = end($this->calls);
+
+        return $last === false ? null : $last['request'];
+    }
+
+    /** 直近に受領した pin entry。未送信なら null。 */
+    public function lastEntry(): ?CurlResolveEntry
+    {
+        $last = end($this->calls);
+
+        return $last === false ? null : $last['entry'];
+    }
+
     public function send(PinnedRequest $request, CurlResolveEntry $entry, Deadline $deadline): PinnedResponse|PinnedFailure
     {
         $this->calls[] = ['request' => $request, 'entry' => $entry];
diff --git a/src/Transport/ByteLimitedStream.php b/src/Transport/ByteLimitedStream.php
new file mode 100644
index 0000000..2fea50f
--- /dev/null
+++ b/src/Transport/ByteLimitedStream.php
@@ -0,0 +1,163 @@
+<?php
+
+declare(strict_types=1);
+
+namespace Kent013\SsrfPin\Transport;
+
+use Psr\Http\Message\StreamInterface;
+use Webmozart\Assert\Assert;
+
+/**
+ * 書き込み総量に上限を課す PSR-7 stream decorator（応答 body の DoS 面を閉じる）。
+ *
+ * 使い方は Guzzle の `sink` オプション。Guzzle の curl handler は
+ * `CURLOPT_WRITEFUNCTION` から `$sink->write($chunk)` を呼び、その戻り値を
+ * そのまま libcurl へ返す。libcurl は **渡した長さと異なる戻り値を書き込みエラーと見なし
+ * 転送をその場で中断する**（`CURLE_WRITE_ERROR`）。したがって上限判定は
+ * 「全部読んでから strlen で測る」のではなく **chunk が届いた時点**で効き、
+ * 上限超過の応答はネットワークから読み切られることも、メモリに載ることもない。
+ *
+ * 上限を跨いだ chunk は 1 バイトも書き込まない（切り詰めた body を握らせないため。
+ * 呼び出し側は `hasExceededLimit()` を見て `TransportError::BodyTooLarge` を返す）。
+ *
+ * 注意: 内側 stream に届くのは curl が復号したあとのバイト列である（Guzzle 既定の
+ * `decode_content` により gzip 等は透過的に展開される）。つまり上限は
+ * **展開後**のバイト数に掛かるので、圧縮爆弾も同じ上限で止まる。
+ */
+final class ByteLimitedStream implements StreamInterface
+{
+    private int $written = 0;
+
+    private bool $exceeded = false;
+
+    /**
+     * @param  StreamInterface  $stream  実バッファ（通常 `php://temp`）。
+     * @param  int  $maxBytes  書き込みを許す総バイト数（0 以上）。
+     */
+    public function __construct(
+        private readonly StreamInterface $stream,
+        private readonly int $maxBytes,
+    ) {
+        Assert::greaterThanEq($maxBytes, 0);
+    }
+
+    /** 上限を超える書き込みが発生したか（= 転送を中断させたか）。 */
+    public function hasExceededLimit(): bool
+    {
+        return $this->exceeded;
+    }
+
+    /** 実際にバッファへ書き込んだバイト数（常に `$maxBytes` 以下）。 */
+    public function writtenBytes(): int
+    {
+        return $this->written;
+    }
+
+    /**
+     * @param  string  $string
+     */
+    public function write($string): int
+    {
+        $length = strlen($string);
+        if ($length === 0) {
+            return 0;
+        }
+
+        if ($this->exceeded || $this->written + $length > $this->maxBytes) {
+            // 短い戻り値（0）で libcurl に書き込みエラーを通知し、転送を中断させる。
+            // 部分書き込みはしない（切り詰められた body を成功として扱わせない）。
+            $this->exceeded = true;
+
+            return 0;
+        }
+
+        $written = $this->stream->write($string);
+        $this->written += $written;
+
+        return $written;
+    }
+
+    public function __toString(): string
+    {
+        if ($this->stream->isSeekable()) {
+            $this->stream->rewind();
+        }
+
+        return $this->stream->getContents();
+    }
+
+    public function close(): void
+    {
+        $this->stream->close();
+    }
+
+    public function detach()
+    {
+        return $this->stream->detach();
+    }
+
+    public function getSize(): ?int
+    {
+        return $this->stream->getSize();
+    }
+
+    public function tell(): int
+    {
+        return $this->stream->tell();
+    }
+
+    public function eof(): bool
+    {
+        return $this->stream->eof();
+    }
+
+    public function isSeekable(): bool
+    {
+        return $this->stream->isSeekable();
+    }
+
+    /**
+     * @param  int  $offset
+     * @param  int  $whence
+     */
+    public function seek($offset, $whence = SEEK_SET): void
+    {
+        $this->stream->seek($offset, $whence);
+    }
+
+    public function rewind(): void
+    {
+        $this->stream->rewind();
+    }
+
+    public function isWritable(): bool
+    {
+        return $this->stream->isWritable();
+    }
+
+    public function isReadable(): bool
+    {
+        return $this->stream->isReadable();
+    }
+
+    /**
+     * @param  int  $length
+     */
+    public function read($length): string
+    {
+        return $this->stream->read($length);
+    }
+
+    public function getContents(): string
+    {
+        return $this->stream->getContents();
+    }
+
+    /**
+     * @param  string|null  $key
+     */
+    public function getMetadata($key = null): mixed
+    {
+        return $this->stream->getMetadata($key);
+    }
+}
diff --git a/src/Transport/GuzzleCurlTransport.php b/src/Transport/GuzzleCurlTransport.php
index 70c1c55..924dfa6 100644
--- a/src/Transport/GuzzleCurlTransport.php
+++ b/src/Transport/GuzzleCurlTransport.php
@@ -9,6 +9,7 @@ use GuzzleHttp\Exception\ConnectException;
 use GuzzleHttp\Exception\GuzzleException;
 use GuzzleHttp\Handler\CurlHandler;
 use GuzzleHttp\HandlerStack;
+use GuzzleHttp\Psr7\Utils;
 use Kent013\SsrfPin\Contracts\PinnedCurlTransportInterface;
 use Kent013\SsrfPin\Dtos\CurlResolveEntry;
 use Kent013\SsrfPin\Dtos\Deadline;
@@ -17,6 +18,7 @@ use Kent013\SsrfPin\Dtos\PinnedRequest;
 use Kent013\SsrfPin\Dtos\PinnedResponse;
 use Kent013\SsrfPin\Enums\SsrfDenyReason;
 use Kent013\SsrfPin\Enums\TransportError;
+use Webmozart\Assert\Assert;
 
 /**
  * libcurl の CURLOPT_RESOLVE で pin する唯一の本番 transport。
@@ -25,9 +27,14 @@ use Kent013\SsrfPin\Enums\TransportError;
  *  - ext-curl 不在、または複数アドレス CURLOPT_RESOLVE 非対応の libcurl では isAvailable()=false。
  *  - Guzzle Client は**内部で CurlHandler を明示構築**して使う（stream handler への fallback で
  *    pin が黙殺される穴を構造的に排除）。外部から任意 Client を注入させない。
+ *  - 応答 body は `ByteLimitedStream` を sink にして読む。上限超過は**切り詰めずに**
+ *    `TransportError::BodyTooLarge` で失敗させる（巨大応答によるメモリ枯渇を防ぐ）。
  */
 final class GuzzleCurlTransport implements PinnedCurlTransportInterface
 {
+    /** 応答 body の既定上限（1 MiB）。discovery / JWKS / token 応答には十分で、DoS 面は閉じる。 */
+    public const int DEFAULT_MAX_BODY_BYTES = 1_048_576;
+
     /** 複数アドレス CURLOPT_RESOLVE が安定的に使える最小 libcurl（7.21.3+ で RESOLVE 導入、余裕を見て 7.40）。 */
     private const int MIN_LIBCURL_VERSION = 0x072800; // 7.40.0
 
@@ -35,8 +42,13 @@ final class GuzzleCurlTransport implements PinnedCurlTransportInterface
 
     private readonly bool $available;
 
-    public function __construct()
+    /**
+     * @param  int  $maxBodyBytes  応答 body の上限バイト数（0 以上）。超過は BodyTooLarge。
+     */
+    public function __construct(private readonly int $maxBodyBytes = self::DEFAULT_MAX_BODY_BYTES)
     {
+        Assert::greaterThanEq($maxBodyBytes, 0);
+
         $this->available = $this->detectAvailability();
         $this->client = new Client([
             'handler' => HandlerStack::create(new CurlHandler),
@@ -61,24 +73,71 @@ final class GuzzleCurlTransport implements PinnedCurlTransportInterface
             return new PinnedFailure(TransportError::Timeout, $request->url, 0);
         }
 
+        // 応答 body は上限つき sink に受ける。上限超過は write 段階（curl の write callback）で
+        // 検出され転送はその場で中断される（読み切ってから測るのでは防御にならない）。
+        $sink = new ByteLimitedStream(Utils::streamFor(''), $this->maxBodyBytes);
+
+        $options = [
+            'headers' => $this->buildHeaders($request),
+            'connect_timeout' => min($request->connectTimeout, $remaining),
+            'timeout' => $remaining,
+            'allow_redirects' => false,
+            'sink' => $sink,
+            'curl' => [CURLOPT_RESOLVE => [$entry->toCurlFormat()]],
+        ];
+        if ($request->body !== null) {
+            $options['body'] = $request->body;
+        }
+
         try {
-            $response = $this->client->request($request->method, $request->url, [
-                'headers' => $request->headers,
-                'connect_timeout' => min($request->connectTimeout, $remaining),
-                'timeout' => $remaining,
-                'allow_redirects' => false,
-                'curl' => [CURLOPT_RESOLVE => [$entry->toCurlFormat()]],
-            ]);
+            $response = $this->client->request($request->method, $request->url, $options);
         } catch (ConnectException $e) {
+            if ($sink->hasExceededLimit()) {
+                return new PinnedFailure(TransportError::BodyTooLarge, $request->url, 0);
+            }
+
             return new PinnedFailure($this->classifyConnectError($e), $request->url, 0);
         } catch (GuzzleException) {
+            // 上限超過による中断は curl の書き込みエラー（CURLE_WRITE_ERROR）として現れる。
+            if ($sink->hasExceededLimit()) {
+                return new PinnedFailure(TransportError::BodyTooLarge, $request->url, 0);
+            }
+
             return new PinnedFailure(TransportError::Unknown, $request->url, 0);
         }
 
+        // 中断が例外化しない実装差分に備えた保険（切り詰めた body は絶対に成功として返さない）。
+        if ($sink->hasExceededLimit()) {
+            return new PinnedFailure(TransportError::BodyTooLarge, $request->url, 0);
+        }
+
         /** @var array<string, list<string>> $headers */
         $headers = $response->getHeaders();
 
-        return new PinnedResponse($response->getStatusCode(), $headers, $request->url, []);
+        return new PinnedResponse($response->getStatusCode(), $headers, $request->url, [], (string) $sink);
+    }
+
+    /**
+     * `contentType` を Content-Type ヘッダに反映する（明示指定は headers の同名エントリより優先）。
+     *
+     * @return array<string, string>
+     */
+    private function buildHeaders(PinnedRequest $request): array
+    {
+        if ($request->contentType === null) {
+            return $request->headers;
+        }
+
+        $headers = [];
+        foreach ($request->headers as $name => $value) {
+            if (strcasecmp($name, 'Content-Type') === 0) {
+                continue;
+            }
+            $headers[$name] = $value;
+        }
+        $headers['Content-Type'] = $request->contentType;
+
+        return $headers;
     }
 
     private function classifyConnectError(ConnectException $e): TransportError
diff --git a/tests/Integration/GuzzleCurlTransportBodyTest.php b/tests/Integration/GuzzleCurlTransportBodyTest.php
new file mode 100644
index 0000000..99808b3
--- /dev/null
+++ b/tests/Integration/GuzzleCurlTransportBodyTest.php
@@ -0,0 +1,205 @@
+<?php
+
+declare(strict_types=1);
+
+use Kent013\SsrfPin\Dtos\CurlResolveEntry;
+use Kent013\SsrfPin\Dtos\Deadline;
+use Kent013\SsrfPin\Dtos\PinnedFailure;
+use Kent013\SsrfPin\Dtos\PinnedRequest;
+use Kent013\SsrfPin\Dtos\PinnedResponse;
+use Kent013\SsrfPin\Enums\TransportError;
+use Kent013\SsrfPin\Transport\GuzzleCurlTransport;
+
+/**
+ * 実 curl での body 往復（受入契約 1・2）。
+ *
+ * ローカル server を 127.0.0.1 に立て、DNS 上存在しない host `pinned.invalid` を
+ * CURLOPT_RESOLVE で pin する（既存 Integration テストと同じ観測ベース検証）。
+ * router は次を返す:
+ *  - `/echo`  : 受け取った method / Content-Type / request body をそのまま返す
+ *  - `/big`   : `?bytes=N` で N バイトの応答 body を返す
+ */
+beforeEach(function () {
+    if (! extension_loaded('curl')) {
+        $this->markTestSkipped('ext-curl 不在');
+    }
+
+    $sock = @stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
+    if ($sock === false) {
+        $this->markTestSkipped('ローカル socket を開けない');
+    }
+    $name = stream_socket_get_name($sock, false);
+    fclose($sock);
+    $port = (int) substr((string) $name, (int) strrpos((string) $name, ':') + 1);
+
+    $docroot = sys_get_temp_dir().'/ssrf-pin-body-it-'.$port;
+    @mkdir($docroot);
+    file_put_contents($docroot.'/router.php', <<<'PHP'
+<?php
+$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
+if ($path === '/big') {
+    $bytes = (int) ($_GET['bytes'] ?? 0);
+    header('Content-Type: application/octet-stream');
+    $chunk = str_repeat('a', 8192);
+    while ($bytes > 0) {
+        $n = min($bytes, 8192);
+        echo substr($chunk, 0, $n);
+        $bytes -= $n;
+    }
+    return true;
+}
+header('Content-Type: application/json');
+echo json_encode([
+    'method' => $_SERVER['REQUEST_METHOD'] ?? '',
+    'content_type' => $_SERVER['CONTENT_TYPE'] ?? null,
+    'body' => file_get_contents('php://input'),
+]);
+return true;
+PHP);
+
+    $this->itPort = $port;
+    $this->itProc = proc_open(
+        sprintf('exec php -S 127.0.0.1:%d %s', $port, escapeshellarg($docroot.'/router.php')),
+        [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']],
+        $pipes,
+    );
+    set_error_handler(static fn (): bool => true);
+    try {
+        for ($i = 0; $i < 50; $i++) {
+            $c = fsockopen('127.0.0.1', $port, $e1, $e2, 0.1);
+            if ($c !== false) {
+                fclose($c);
+                break;
+            }
+            usleep(50_000);
+        }
+    } finally {
+        restore_error_handler();
+    }
+});
+
+afterEach(function () {
+    if (isset($this->itProc) && is_resource($this->itProc)) {
+        proc_terminate($this->itProc);
+        proc_close($this->itProc);
+    }
+});
+
+// --- 受入契約 1: request body / contentType が実際に送られる ---
+
+it('sends the request body and content type over the pinned connection', function () {
+    $transport = new GuzzleCurlTransport;
+    $entry = new CurlResolveEntry('pinned.invalid', $this->itPort, ['127.0.0.1']);
+
+    $result = $transport->send(
+        new PinnedRequest(
+            'POST',
+            "http://pinned.invalid:{$this->itPort}/echo",
+            body: 'grant_type=authorization_code&code=abc',
+            contentType: 'application/x-www-form-urlencoded',
+        ),
+        $entry,
+        Deadline::afterSeconds(10),
+    );
+
+    expect($result)->toBeInstanceOf(PinnedResponse::class)
+        ->and($result->status)->toBe(200);
+
+    /** @var array{method: string, content_type: string|null, body: string} $echo */
+    $echo = json_decode($result->body, true);
+
+    expect($echo['method'])->toBe('POST')
+        ->and($echo['content_type'])->toBe('application/x-www-form-urlencoded')
+        ->and($echo['body'])->toBe('grant_type=authorization_code&code=abc');
+})->group('integration');
+
+it('lets an explicit contentType win over a Content-Type header entry', function () {
+    $transport = new GuzzleCurlTransport;
+    $entry = new CurlResolveEntry('pinned.invalid', $this->itPort, ['127.0.0.1']);
+
+    $result = $transport->send(
+        new PinnedRequest(
+            'POST',
+            "http://pinned.invalid:{$this->itPort}/echo",
+            ['content-type' => 'text/plain'],
+            body: '{"a":1}',
+            contentType: 'application/json',
+        ),
+        $entry,
+        Deadline::afterSeconds(10),
+    );
+
+    expect($result)->toBeInstanceOf(PinnedResponse::class);
+
+    /** @var array{content_type: string|null} $echo */
+    $echo = json_decode($result->body, true);
+    expect($echo['content_type'])->toBe('application/json');
+})->group('integration');
+
+it('sends no body when the request has none', function () {
+    $transport = new GuzzleCurlTransport;
+    $entry = new CurlResolveEntry('pinned.invalid', $this->itPort, ['127.0.0.1']);
+
+    $result = $transport->send(
+        new PinnedRequest('GET', "http://pinned.invalid:{$this->itPort}/echo"),
+        $entry,
+        Deadline::afterSeconds(10),
+    );
+
+    expect($result)->toBeInstanceOf(PinnedResponse::class);
+
+    /** @var array{method: string, body: string, content_type: string|null} $echo */
+    $echo = json_decode($result->body, true);
+    expect($echo['method'])->toBe('GET')
+        ->and($echo['body'])->toBe('')
+        ->and($echo['content_type'])->toBeNull();
+})->group('integration');
+
+// --- 受入契約 2: 応答 body は上限バイト数付きで読む ---
+
+it('reads the response body up to the configured limit', function () {
+    $transport = new GuzzleCurlTransport(maxBodyBytes: 65536);
+    $entry = new CurlResolveEntry('pinned.invalid', $this->itPort, ['127.0.0.1']);
+
+    $result = $transport->send(
+        new PinnedRequest('GET', "http://pinned.invalid:{$this->itPort}/big?bytes=65536"),
+        $entry,
+        Deadline::afterSeconds(10),
+    );
+
+    expect($result)->toBeInstanceOf(PinnedResponse::class)
+        ->and(strlen($result->body))->toBe(65536);
+})->group('integration');
+
+it('fails with BodyTooLarge instead of truncating when the response exceeds the limit', function () {
+    $transport = new GuzzleCurlTransport(maxBodyBytes: 4096);
+    $entry = new CurlResolveEntry('pinned.invalid', $this->itPort, ['127.0.0.1']);
+
+    $result = $transport->send(
+        new PinnedRequest('GET', "http://pinned.invalid:{$this->itPort}/big?bytes=8388608"),
+        $entry,
+        Deadline::afterSeconds(10),
+    );
+
+    expect($result)->toBeInstanceOf(PinnedFailure::class)
+        ->and($result->cause)->toBe(TransportError::BodyTooLarge)
+        ->and($result->isDeny())->toBeFalse();
+})->group('integration');
+
+it('aborts an oversized transfer without buffering it (peak memory stays bounded)', function () {
+    $transport = new GuzzleCurlTransport(maxBodyBytes: 4096);
+    $entry = new CurlResolveEntry('pinned.invalid', $this->itPort, ['127.0.0.1']);
+
+    $before = memory_get_usage(true);
+    $result = $transport->send(
+        // 64 MiB の応答。上限が「読み切ってから測る」実装なら 64 MiB を確保してしまう。
+        new PinnedRequest('GET', "http://pinned.invalid:{$this->itPort}/big?bytes=67108864"),
+        $entry,
+        Deadline::afterSeconds(30),
+    );
+    $growth = memory_get_usage(true) - $before;
+
+    expect($result)->toBeInstanceOf(PinnedFailure::class)
+        ->and($result->cause)->toBe(TransportError::BodyTooLarge)
+        ->and($growth)->toBeLessThan(8 * 1024 * 1024);
+})->group('integration');
diff --git a/tests/Unit/BackwardCompatibilityTest.php b/tests/Unit/BackwardCompatibilityTest.php
new file mode 100644
index 0000000..544099b
--- /dev/null
+++ b/tests/Unit/BackwardCompatibilityTest.php
@@ -0,0 +1,75 @@
+<?php
+
+declare(strict_types=1);
+
+use Kent013\SsrfPin\Dtos\Deadline;
+use Kent013\SsrfPin\Dtos\PinnedRequest;
+use Kent013\SsrfPin\Dtos\PinnedResponse;
+use Kent013\SsrfPin\PinnedHttpClient;
+use Kent013\SsrfPin\Testing\FakeDnsResolver;
+use Kent013\SsrfPin\Testing\FakePinnedTransport;
+use Kent013\SsrfPin\Transport\GuzzleCurlTransport;
+use Kent013\SsrfPin\UrlSafetyInspector;
+
+/**
+ * v0.2 の公開 API を v0.3 が壊していないことの pin。
+ * 新規フィールド・新規引数はすべて「既定値つきで末尾に追加」でなければならない。
+ */
+it('keeps the v0.2 positional constructor of PinnedRequest working', function () {
+    $request = new PinnedRequest('HEAD', 'https://example.test/', ['Accept' => '*/*'], 3.0);
+
+    expect($request->method)->toBe('HEAD')
+        ->and($request->url)->toBe('https://example.test/')
+        ->and($request->headers)->toBe(['Accept' => '*/*'])
+        ->and($request->connectTimeout)->toBe(3.0)
+        ->and($request->body)->toBeNull()
+        ->and($request->contentType)->toBeNull();
+});
+
+it('keeps the v0.2 positional constructor of PinnedResponse working', function () {
+    $response = new PinnedResponse(204, ['X-Test' => ['1']], 'https://example.test/', ['https://example.test/']);
+
+    expect($response->status)->toBe(204)
+        ->and($response->finalUrl)->toBe('https://example.test/')
+        ->and($response->hopUrls)->toBe(['https://example.test/'])
+        ->and($response->header('x-test'))->toBe('1')
+        ->and($response->body)->toBe('');
+});
+
+it('keeps the v0.2 two-argument fetch() signature working and follows redirects by default', function () {
+    $inspector = new UrlSafetyInspector(new FakeDnsResolver([
+        'a.test' => ['93.184.216.34'],
+        'b.test' => ['93.184.216.35'],
+    ]));
+    $t = new FakePinnedTransport(fn (PinnedRequest $r): PinnedResponse => match (true) {
+        str_contains($r->url, 'a.test') => new PinnedResponse(302, ['Location' => ['https://b.test/']], $r->url, []),
+        default => new PinnedResponse(200, [], $r->url, []),
+    });
+
+    $result = (new PinnedHttpClient($inspector, $t))->fetch(
+        new PinnedRequest('GET', 'https://a.test/'),
+        Deadline::afterSeconds(5),
+    );
+
+    expect($result)->toBeInstanceOf(PinnedResponse::class)
+        ->and($result->status)->toBe(200)
+        ->and($t->calls)->toHaveCount(2);
+});
+
+it('keeps GuzzleCurlTransport constructible without arguments', function () {
+    expect(new GuzzleCurlTransport)->toBeInstanceOf(GuzzleCurlTransport::class);
+});
+
+it('exposes followRedirects as the third parameter of fetch() (consumer contract pin)', function () {
+    $parameters = (new ReflectionMethod(PinnedHttpClient::class, 'fetch'))->getParameters();
+
+    expect($parameters[2]->getName())->toBe('followRedirects')
+        ->and($parameters[2]->isDefaultValueAvailable())->toBeTrue()
+        ->and($parameters[2]->getDefaultValue())->toBeTrue();
+});
+
+it('exposes the v0.3 body properties consumers pin against', function () {
+    expect(property_exists(PinnedRequest::class, 'body'))->toBeTrue()
+        ->and(property_exists(PinnedRequest::class, 'contentType'))->toBeTrue()
+        ->and(property_exists(PinnedResponse::class, 'body'))->toBeTrue();
+});
diff --git a/tests/Unit/ByteLimitedStreamTest.php b/tests/Unit/ByteLimitedStreamTest.php
new file mode 100644
index 0000000..5573c57
--- /dev/null
+++ b/tests/Unit/ByteLimitedStreamTest.php
@@ -0,0 +1,82 @@
+<?php
+
+declare(strict_types=1);
+
+use GuzzleHttp\Psr7\Utils;
+use Kent013\SsrfPin\Transport\ByteLimitedStream;
+
+/**
+ * 受入契約 2（応答 body の上限）の中核。
+ *
+ * 「読み切ってから測る」のでは防御にならないため、上限判定は **write（= curl の
+ * CURLOPT_WRITEFUNCTION）段階**で効かなければならない。curl は write callback が
+ * 渡されたバイト数と異なる値を返すと転送を即座に中断する（CURLE_WRITE_ERROR）。
+ * ここではその「短い戻り値」と「バッファが上限を超えて育たないこと」を直接検証する。
+ */
+it('accepts writes up to the limit and buffers them verbatim', function () {
+    $stream = new ByteLimitedStream(Utils::streamFor(''), 10);
+
+    expect($stream->write('12345'))->toBe(5)
+        ->and($stream->write('67890'))->toBe(5)
+        ->and($stream->hasExceededLimit())->toBeFalse()
+        ->and($stream->writtenBytes())->toBe(10)
+        ->and((string) $stream)->toBe('1234567890');
+});
+
+it('aborts the transfer with a short write when a chunk crosses the limit', function () {
+    $stream = new ByteLimitedStream(Utils::streamFor(''), 10);
+
+    // 上限を跨ぐ chunk。curl は「渡した長さと違う値」を受け取って転送を中断する。
+    $written = $stream->write('123456789012345');
+
+    expect($written)->toBeLessThan(15)
+        ->and($stream->hasExceededLimit())->toBeTrue()
+        ->and($stream->writtenBytes())->toBeLessThanOrEqual(10);
+});
+
+it('never lets the buffer grow past the limit even under repeated writes', function () {
+    $stream = new ByteLimitedStream(Utils::streamFor(''), 8);
+
+    for ($i = 0; $i < 100; $i++) {
+        $stream->write(str_repeat('x', 1024));
+    }
+
+    expect($stream->hasExceededLimit())->toBeTrue()
+        ->and($stream->writtenBytes())->toBeLessThanOrEqual(8)
+        ->and(strlen((string) $stream))->toBeLessThanOrEqual(8);
+});
+
+it('keeps rejecting once the limit has been exceeded', function () {
+    $stream = new ByteLimitedStream(Utils::streamFor(''), 4);
+    $stream->write('abcdef');
+
+    expect($stream->write('g'))->toBe(0)
+        ->and($stream->hasExceededLimit())->toBeTrue();
+});
+
+it('treats a zero-length write as a no-op success (curl may pass empty chunks)', function () {
+    $stream = new ByteLimitedStream(Utils::streamFor(''), 4);
+
+    expect($stream->write(''))->toBe(0)
+        ->and($stream->hasExceededLimit())->toBeFalse();
+});
+
+it('delegates the remaining StreamInterface surface to the inner stream', function () {
+    $stream = new ByteLimitedStream(Utils::streamFor(''), 16);
+    $stream->write('hello');
+
+    expect($stream->isSeekable())->toBeTrue()
+        ->and($stream->isWritable())->toBeTrue()
+        ->and($stream->isReadable())->toBeTrue()
+        ->and($stream->getSize())->toBe(5)
+        ->and($stream->tell())->toBe(5)
+        ->and($stream->eof())->toBeFalse();
+
+    $stream->rewind();
+    expect($stream->read(5))->toBe('hello')
+        ->and($stream->getMetadata('seekable'))->toBeTrue();
+
+    $stream->seek(0);
+    expect($stream->getContents())->toBe('hello')
+        ->and($stream->detach())->not->toBeNull();
+});
diff --git a/tests/Unit/PinnedHttpClientBodyTest.php b/tests/Unit/PinnedHttpClientBodyTest.php
new file mode 100644
index 0000000..bd49fb6
--- /dev/null
+++ b/tests/Unit/PinnedHttpClientBodyTest.php
@@ -0,0 +1,175 @@
+<?php
+
+declare(strict_types=1);
+
+use Kent013\SsrfPin\Dtos\Deadline;
+use Kent013\SsrfPin\Dtos\PinnedFailure;
+use Kent013\SsrfPin\Dtos\PinnedRequest;
+use Kent013\SsrfPin\Dtos\PinnedResponse;
+use Kent013\SsrfPin\Enums\SsrfDenyReason;
+use Kent013\SsrfPin\PinnedHttpClient;
+use Kent013\SsrfPin\Testing\FakeDnsResolver;
+use Kent013\SsrfPin\Testing\FakePinnedTransport;
+use Kent013\SsrfPin\UrlSafetyInspector;
+
+/**
+ * v0.3 の body / followRedirects 契約（受入契約 3・4・5）。
+ */
+function bodyClient(UrlSafetyInspector $inspector, FakePinnedTransport $t, int $maxHops = 5): PinnedHttpClient
+{
+    return new PinnedHttpClient($inspector, $t, $maxHops);
+}
+
+function publicInspector(): UrlSafetyInspector
+{
+    return new UrlSafetyInspector(new FakeDnsResolver([
+        'a.test' => ['93.184.216.34'],
+        'b.test' => ['93.184.216.35'],
+    ]));
+}
+
+// --- 受入契約 5: FakePinnedTransport が body/contentType を記録し応答 body を返せる ---
+
+it('carries the request body and content type through to the transport', function () {
+    $t = new FakePinnedTransport(
+        fn (PinnedRequest $r): PinnedResponse => new PinnedResponse(200, [], $r->url, [], '{"access_token":"t"}'),
+    );
+
+    $result = bodyClient(publicInspector(), $t)->fetch(
+        new PinnedRequest(
+            'POST',
+            'https://a.test/token',
+            ['Accept' => 'application/json'],
+            body: 'grant_type=authorization_code',
+            contentType: 'application/x-www-form-urlencoded',
+        ),
+        Deadline::afterSeconds(5),
+    );
+
+    expect($t->lastRequest()?->body)->toBe('grant_type=authorization_code')
+        ->and($t->lastRequest()?->contentType)->toBe('application/x-www-form-urlencoded')
+        ->and($t->lastRequest()?->method)->toBe('POST')
+        ->and($result)->toBeInstanceOf(PinnedResponse::class)
+        ->and($result->body)->toBe('{"access_token":"t"}');
+});
+
+it('exposes the response body of the final hop', function () {
+    $t = new FakePinnedTransport(fn (PinnedRequest $r): PinnedResponse => match (true) {
+        str_contains($r->url, 'a.test') => new PinnedResponse(302, ['Location' => ['https://b.test/final']], $r->url, [], 'moved'),
+        default => new PinnedResponse(200, [], $r->url, [], 'final-body'),
+    });
+
+    $result = bodyClient(publicInspector(), $t)->fetch(
+        new PinnedRequest('GET', 'https://a.test/start'),
+        Deadline::afterSeconds(5),
+    );
+
+    expect($result)->toBeInstanceOf(PinnedResponse::class)
+        ->and($result->body)->toBe('final-body')
+        ->and($result->hopUrls)->toBe(['https://a.test/start', 'https://b.test/final']);
+});
+
+// --- 受入契約 3: followRedirects: false で 3xx を追従せずそのまま返す ---
+
+it('returns the 3xx response as-is when followRedirects is false', function () {
+    $t = new FakePinnedTransport(
+        fn (PinnedRequest $r): PinnedResponse => new PinnedResponse(302, ['Location' => ['https://b.test/next']], $r->url, [], 'moved'),
+    );
+
+    $result = bodyClient(publicInspector(), $t)->fetch(
+        new PinnedRequest('GET', 'https://a.test/start'),
+        Deadline::afterSeconds(5),
+        followRedirects: false,
+    );
+
+    expect($result)->toBeInstanceOf(PinnedResponse::class)
+        ->and($result->status)->toBe(302)
+        ->and($result->body)->toBe('moved')
+        ->and($result->finalUrl)->toBe('https://a.test/start')
+        ->and($result->hopUrls)->toBe(['https://a.test/start'])
+        ->and($result->header('Location'))->toBe('https://b.test/next')
+        ->and($t->calls)->toHaveCount(1);
+});
+
+it('still applies the guard on the first hop when followRedirects is false', function () {
+    $inspector = new UrlSafetyInspector(new FakeDnsResolver(['evil.test' => ['127.0.0.1']]));
+    $t = new FakePinnedTransport;
+
+    $result = bodyClient($inspector, $t)->fetch(
+        new PinnedRequest('GET', 'https://evil.test/'),
+        Deadline::afterSeconds(5),
+        followRedirects: false,
+    );
+
+    expect($result)->toBeInstanceOf(PinnedFailure::class)
+        ->and($result->cause)->toBe(SsrfDenyReason::Loopback)
+        ->and($t->calls)->toBe([]);
+});
+
+it('does not follow redirects even when the target would be allowed', function () {
+    $t = new FakePinnedTransport(
+        fn (PinnedRequest $r): PinnedResponse => new PinnedResponse(307, ['Location' => ['https://b.test/next']], $r->url, [], ''),
+    );
+
+    $result = bodyClient(publicInspector(), $t)->fetch(
+        new PinnedRequest('POST', 'https://a.test/token', body: 'x=1'),
+        Deadline::afterSeconds(5),
+        followRedirects: false,
+    );
+
+    expect($result)->toBeInstanceOf(PinnedResponse::class)
+        ->and($result->status)->toBe(307)
+        ->and($t->calls)->toHaveCount(1);
+});
+
+// --- 受入契約 4: redirect 追従時、2 hop 目以降は body を送らない ---
+
+it('never resends the request body on the second and later hops', function () {
+    $t = new FakePinnedTransport(fn (PinnedRequest $r): PinnedResponse => match (true) {
+        str_contains($r->url, 'a.test') => new PinnedResponse(307, ['Location' => ['https://b.test/next']], $r->url, [], ''),
+        default => new PinnedResponse(200, [], $r->url, [], 'ok'),
+    });
+
+    $result = bodyClient(publicInspector(), $t)->fetch(
+        new PinnedRequest(
+            'POST',
+            'https://a.test/token',
+            ['Authorization' => 'Basic zzz', 'Content-Type' => 'application/x-www-form-urlencoded'],
+            body: 'client_secret=super-secret',
+            contentType: 'application/x-www-form-urlencoded',
+        ),
+        Deadline::afterSeconds(5),
+    );
+
+    expect($result)->toBeInstanceOf(PinnedResponse::class)
+        ->and($t->calls)->toHaveCount(2)
+        ->and($t->calls[0]['request']->body)->toBe('client_secret=super-secret')
+        ->and($t->calls[0]['request']->contentType)->toBe('application/x-www-form-urlencoded')
+        // 2 hop 目には body も Content-Type も渡らない（リダイレクト先への body 漏洩防止）。
+        ->and($t->calls[1]['request']->body)->toBeNull()
+        ->and($t->calls[1]['request']->contentType)->toBeNull()
+        ->and($t->calls[1]['request']->headers)->not->toHaveKey('Content-Type');
+});
+
+it('keeps the body on the first hop only, across a long redirect chain', function () {
+    $inspector = new UrlSafetyInspector(new FakeDnsResolver(['loop.test' => ['93.184.216.34']]));
+    $t = new FakePinnedTransport(fn (PinnedRequest $r): PinnedResponse => new PinnedResponse(
+        302,
+        ['Location' => ['https://loop.test/next']],
+        $r->url,
+        [],
+        '',
+    ));
+
+    bodyClient($inspector, $t, maxHops: 4)->fetch(
+        new PinnedRequest('POST', 'https://loop.test/0', body: 'secret'),
+        Deadline::afterSeconds(5),
+    );
+
+    expect($t->calls)->toHaveCount(4)
+        ->and($t->calls[0]['request']->body)->toBe('secret');
+
+    foreach (array_slice($t->calls, 1) as $call) {
+        expect($call['request']->body)->toBeNull();
+    }
+});
```
