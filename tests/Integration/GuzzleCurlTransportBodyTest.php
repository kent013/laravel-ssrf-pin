<?php

declare(strict_types=1);

use Kent013\SsrfPin\Dtos\CurlResolveEntry;
use Kent013\SsrfPin\Dtos\Deadline;
use Kent013\SsrfPin\Dtos\PinnedFailure;
use Kent013\SsrfPin\Dtos\PinnedRequest;
use Kent013\SsrfPin\Dtos\PinnedResponse;
use Kent013\SsrfPin\Enums\TransportError;
use Kent013\SsrfPin\Transport\GuzzleCurlTransport;

/**
 * 実 curl での body 往復（受入契約 1・2）。
 *
 * ローカル server を 127.0.0.1 に立て、DNS 上存在しない host `pinned.invalid` を
 * CURLOPT_RESOLVE で pin する（既存 Integration テストと同じ観測ベース検証）。
 * router は次を返す:
 *  - `/echo`  : 受け取った method / Content-Type / request body をそのまま返す
 *  - `/big`   : `?bytes=N` で N バイトの応答 body を返す
 */
beforeEach(function () {
    if (! extension_loaded('curl')) {
        $this->markTestSkipped('ext-curl 不在');
    }

    $sock = @stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    if ($sock === false) {
        $this->markTestSkipped('ローカル socket を開けない');
    }
    $name = stream_socket_get_name($sock, false);
    fclose($sock);
    $port = (int) substr((string) $name, (int) strrpos((string) $name, ':') + 1);

    $docroot = sys_get_temp_dir().'/ssrf-pin-body-it-'.$port;
    @mkdir($docroot);
    file_put_contents($docroot.'/router.php', <<<'PHP'
<?php
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if ($path === '/big') {
    $bytes = (int) ($_GET['bytes'] ?? 0);
    header('Content-Type: application/octet-stream');
    $chunk = str_repeat('a', 8192);
    while ($bytes > 0) {
        $n = min($bytes, 8192);
        echo substr($chunk, 0, $n);
        $bytes -= $n;
    }
    return true;
}
header('Content-Type: application/json');
echo json_encode([
    'method' => $_SERVER['REQUEST_METHOD'] ?? '',
    'content_type' => $_SERVER['CONTENT_TYPE'] ?? null,
    'content_length' => $_SERVER['CONTENT_LENGTH'] ?? null,
    'body' => file_get_contents('php://input'),
]);
return true;
PHP);

    $this->itPort = $port;
    $this->itProc = proc_open(
        sprintf('exec php -S 127.0.0.1:%d %s', $port, escapeshellarg($docroot.'/router.php')),
        [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']],
        $pipes,
    );
    set_error_handler(static fn (): bool => true);
    try {
        for ($i = 0; $i < 50; $i++) {
            $c = fsockopen('127.0.0.1', $port, $e1, $e2, 0.1);
            if ($c !== false) {
                fclose($c);
                break;
            }
            usleep(50_000);
        }
    } finally {
        restore_error_handler();
    }
});

afterEach(function () {
    if (isset($this->itProc) && is_resource($this->itProc)) {
        proc_terminate($this->itProc);
        proc_close($this->itProc);
    }
});

// --- 受入契約 1: request body / contentType が実際に送られる ---

it('sends the request body and content type over the pinned connection', function () {
    $transport = new GuzzleCurlTransport;
    $entry = new CurlResolveEntry('pinned.invalid', $this->itPort, ['127.0.0.1']);

    $result = $transport->send(
        new PinnedRequest(
            'POST',
            "http://pinned.invalid:{$this->itPort}/echo",
            body: 'grant_type=authorization_code&code=abc',
            contentType: 'application/x-www-form-urlencoded',
        ),
        $entry,
        Deadline::afterSeconds(10),
    );

    expect($result)->toBeInstanceOf(PinnedResponse::class)
        ->and($result->status)->toBe(200);

    /** @var array{method: string, content_type: string|null, body: string} $echo */
    $echo = json_decode($result->body, true);

    expect($echo['method'])->toBe('POST')
        ->and($echo['content_type'])->toBe('application/x-www-form-urlencoded')
        ->and($echo['body'])->toBe('grant_type=authorization_code&code=abc');
})->group('integration');

it('lets an explicit contentType win over a Content-Type header entry', function () {
    $transport = new GuzzleCurlTransport;
    $entry = new CurlResolveEntry('pinned.invalid', $this->itPort, ['127.0.0.1']);

    $result = $transport->send(
        new PinnedRequest(
            'POST',
            "http://pinned.invalid:{$this->itPort}/echo",
            ['content-type' => 'text/plain'],
            body: '{"a":1}',
            contentType: 'application/json',
        ),
        $entry,
        Deadline::afterSeconds(10),
    );

    expect($result)->toBeInstanceOf(PinnedResponse::class);

    /** @var array{content_type: string|null} $echo */
    $echo = json_decode($result->body, true);
    expect($echo['content_type'])->toBe('application/json');
})->group('integration');

it('sends no body when the request has none', function () {
    $transport = new GuzzleCurlTransport;
    $entry = new CurlResolveEntry('pinned.invalid', $this->itPort, ['127.0.0.1']);

    $result = $transport->send(
        new PinnedRequest('GET', "http://pinned.invalid:{$this->itPort}/echo"),
        $entry,
        Deadline::afterSeconds(10),
    );

    expect($result)->toBeInstanceOf(PinnedResponse::class);

    /** @var array{method: string, body: string, content_type: string|null} $echo */
    $echo = json_decode($result->body, true);
    expect($echo['method'])->toBe('GET')
        ->and($echo['body'])->toBe('')
        ->and($echo['content_type'])->toBeNull();
})->group('integration');

// --- 受入契約 4 の wire-level 確認: 2 hop 目に body が 1 バイトも乗らない ---

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

// --- 受入契約 2: 応答 body は上限バイト数付きで読む ---

it('reads the response body up to the configured limit', function () {
    $transport = new GuzzleCurlTransport(maxBodyBytes: 65536);
    $entry = new CurlResolveEntry('pinned.invalid', $this->itPort, ['127.0.0.1']);

    $result = $transport->send(
        new PinnedRequest('GET', "http://pinned.invalid:{$this->itPort}/big?bytes=65536"),
        $entry,
        Deadline::afterSeconds(10),
    );

    expect($result)->toBeInstanceOf(PinnedResponse::class)
        ->and(strlen($result->body))->toBe(65536);
})->group('integration');

it('fails with BodyTooLarge instead of truncating when the response exceeds the limit', function () {
    $transport = new GuzzleCurlTransport(maxBodyBytes: 4096);
    $entry = new CurlResolveEntry('pinned.invalid', $this->itPort, ['127.0.0.1']);

    $result = $transport->send(
        new PinnedRequest('GET', "http://pinned.invalid:{$this->itPort}/big?bytes=8388608"),
        $entry,
        Deadline::afterSeconds(10),
    );

    expect($result)->toBeInstanceOf(PinnedFailure::class)
        ->and($result->cause)->toBe(TransportError::BodyTooLarge)
        ->and($result->isDeny())->toBeFalse();
})->group('integration');

it('aborts an oversized transfer without buffering it (peak memory stays bounded)', function () {
    $transport = new GuzzleCurlTransport(maxBodyBytes: 4096);
    $entry = new CurlResolveEntry('pinned.invalid', $this->itPort, ['127.0.0.1']);

    $before = memory_get_usage(true);
    $result = $transport->send(
        // 64 MiB の応答。上限が「読み切ってから測る」実装なら 64 MiB を確保してしまう。
        new PinnedRequest('GET', "http://pinned.invalid:{$this->itPort}/big?bytes=67108864"),
        $entry,
        Deadline::afterSeconds(30),
    );
    $growth = memory_get_usage(true) - $before;

    expect($result)->toBeInstanceOf(PinnedFailure::class)
        ->and($result->cause)->toBe(TransportError::BodyTooLarge)
        ->and($growth)->toBeLessThan(8 * 1024 * 1024);
})->group('integration');
