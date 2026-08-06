# Round 2: Round 1 指摘への対応報告

Round 1 で APPROVED を頂いたが、Warning 1 / Suggestion 2 のうち「テストで pin できるもの」を
本ラウンドで取り込んだ。**実装コード (`src/`) は 1 行も変えていない。差分はテストのみ**である。

対応マトリクスは `devnotes/20260806-0937-v03-body-support/codex-history/impl-review-decisions-round-1.md`
に保存済み (下に全文を再掲する)。

確認してほしいのは次の 2 点だけである:

1. 追加したテストが、指摘した観点 (2 hop 目の Content-Length 除去 / wire-level で body が乗らないこと) を
   **実際に検証できているか** (トートロジーや、常に真になる assertion になっていないか)。
2. Warning (credential header の hop 越え転送) を「見送る」とした根拠が妥当か。
   妥当でなければ、v0.3 の受入契約と後方互換の制約の下で何をすべきかを具体的に述べてほしい。

最後に必ず判定行を単独で書くこと: `VERDICT: APPROVED` または `VERDICT: CHANGES_REQUESTED`。

## ゲート再実測 (対応後)

- `composer test`: 48 passed (158 assertions)
- `composer phpstan`: level 10, No errors
- `vendor/bin/pint --test`: passed

---

## 対応マトリクス (全文)

# 対応マトリクス: impl-review Round 1

Round 1 の判定は **VERDICT: APPROVED** (Critical 0 / Warning 1 / Suggestion 2)。
APPROVED ではあるが、Warning / Suggestion のうち「テストで pin できるもの」は本ラウンドで取り込んだ。

## [Warning] redirect 2 hop 目以降で Authorization 等の credential header が転送される

- 判断: **見送る** (挙動は変えない。文書と契約で閉じる)
- 根拠:
  1. 本改修の受入契約は「body を再送しない」であり、header の扱いは v0.2 の挙動そのものである。
     ここで cross-host の header 除去まで踏み込むと、**受入契約の外側で v0.2 の挙動を変える**ことになり、
     既存利用者 (同一ホスト間 redirect で `Authorization` が生きている前提のコード) を静かに壊しうる。
     後方互換は本改修の非交渉条件である。
  2. 漏洩面としての深刻度は body より低い。body には `client_secret` / assertion が乗るのに対し、
     header credential を使う経路 (token endpoint の client_secret_basic) は
     **本 feature の設計上 `followRedirects: false` 固定**であり、そもそも 2 hop 目が発生しない。
  3. Codex 自身が「後方互換を優先する判断として説明可能」と評価している。
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

---

## 追加/変更したテスト (該当箇所のみ)

### tests/Unit/PinnedHttpClientBodyTest.php (変更)

```php
it('never resends the request body on the second and later hops', function () {
    $t = new FakePinnedTransport(fn (PinnedRequest $r): PinnedResponse => match (true) {
        str_contains($r->url, 'a.test') => new PinnedResponse(307, ['Location' => ['https://b.test/next']], $r->url, [], ''),
        default => new PinnedResponse(200, [], $r->url, [], 'ok'),
    });

    $result = bodyClient(publicInspector(), $t)->fetch(
        new PinnedRequest(
            'POST',
            'https://a.test/token',
            [
                'Authorization' => 'Basic zzz',
                'Content-Type' => 'application/x-www-form-urlencoded',
                'content-length' => '26',
            ],
            body: 'client_secret=super-secret',
            contentType: 'application/x-www-form-urlencoded',
        ),
        Deadline::afterSeconds(5),
    );

    expect($result)->toBeInstanceOf(PinnedResponse::class)
        ->and($t->calls)->toHaveCount(2)
        ->and($t->calls[0]['request']->body)->toBe('client_secret=super-secret')
        ->and($t->calls[0]['request']->contentType)->toBe('application/x-www-form-urlencoded')
        // 2 hop 目には body も Content-Type も渡らない（リダイレクト先への body 漏洩防止）。
        ->and($t->calls[1]['request']->body)->toBeNull()
        ->and($t->calls[1]['request']->contentType)->toBeNull()
        // Content-Type / Content-Length は大文字小文字を問わず落ちる。Authorization は v0.2 同様残る。
        ->and($t->calls[1]['request']->headers)->toBe(['Authorization' => 'Basic zzz']);
});
```

### tests/Integration/GuzzleCurlTransportBodyTest.php (追加 + router に content_length 観測を追加)

```php
it('puts no body bytes on the wire for the follow-up hop of a redirect', function () {
    // PinnedHttpClient が 2 hop 目に送るのと同一の request（withUrlWithoutBody の結果）を
    // 実 curl で送り、server 側の観測で「body なし・Content-Type なし」を確認する。
    $original = new PinnedRequest(
        'POST',
        "http://pinned.invalid:{$this->itPort}/token",
        ['Authorization' => 'Basic zzz', 'Content-Type' => 'application/x-www-form-urlencoded'],
        body: 'client_secret=super-secret',
        contentType: 'application/x-www-form-urlencoded',
    );
    $followUp = $original->withUrlWithoutBody("http://pinned.invalid:{$this->itPort}/echo");

    $transport = new GuzzleCurlTransport;
    $result = $transport->send(
        $followUp,
        new CurlResolveEntry('pinned.invalid', $this->itPort, ['127.0.0.1']),
        Deadline::afterSeconds(10),
    );

    expect($result)->toBeInstanceOf(PinnedResponse::class);

    /** @var array{method: string, content_type: string|null, content_length: string|null, body: string} $echo */
    $echo = json_decode($result->body, true);

    expect($echo['method'])->toBe('POST')
        ->and($echo['body'])->toBe('')
        ->and($echo['content_type'])->toBeNull()
        // Content-Length は「無い」か「0」のいずれか。いずれにせよ body は wire に乗らない。
        ->and((int) ($echo['content_length'] ?? 0))->toBe(0);
})->group('integration');
```

router の観測項目 (php -S のルータスクリプト):

```php
header('Content-Type: application/json');
echo json_encode([
    'method' => $_SERVER['REQUEST_METHOD'] ?? '',
    'content_type' => $_SERVER['CONTENT_TYPE'] ?? null,
    'content_length' => $_SERVER['CONTENT_LENGTH'] ?? null,
    'body' => file_get_contents('php://input'),
]);
```
