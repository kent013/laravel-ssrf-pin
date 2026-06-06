<?php

declare(strict_types=1);

use Kent013\SsrfPin\Dtos\CurlResolveEntry;
use Kent013\SsrfPin\Dtos\Deadline;
use Kent013\SsrfPin\Dtos\PinnedRequest;
use Kent013\SsrfPin\Dtos\PinnedResponse;
use Kent013\SsrfPin\Transport\GuzzleCurlTransport;

/**
 * 実 curl での pin 実証。ローカル server を 127.0.0.1 に立て、DNS 上は存在しない host
 * `pinned.invalid` を CURLOPT_RESOLVE で 127.0.0.1 に pin する。pin が効けば 200 が返り、
 * 効かなければ host 解決不能で接続失敗する（= pin の観測ベース検証）。
 */
beforeEach(function () {
    if (! extension_loaded('curl')) {
        $this->markTestSkipped('ext-curl 不在');
    }

    // 空きポートを取得
    $sock = @stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    if ($sock === false) {
        $this->markTestSkipped('ローカル socket を開けない');
    }
    $name = stream_socket_get_name($sock, false);
    fclose($sock);
    $port = (int) substr((string) $name, (int) strrpos((string) $name, ':') + 1);

    $docroot = sys_get_temp_dir().'/ssrf-pin-it-'.$port;
    @mkdir($docroot);
    file_put_contents($docroot.'/index.php', "<?php echo 'PINNED_OK';");

    $this->itPort = $port;
    $this->itProc = proc_open(
        sprintf('exec php -S 127.0.0.1:%d -t %s', $port, escapeshellarg($docroot)),
        [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']],
        $pipes,
    );
    // server 起動待ち（起動前の "Connection refused" 警告は握りつぶす）
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

it('connects to the pinned IP for a host that does not resolve in DNS', function () {
    $transport = new GuzzleCurlTransport;
    expect($transport->isAvailable())->toBeTrue();

    $entry = new CurlResolveEntry('pinned.invalid', $this->itPort, ['127.0.0.1']);
    $result = $transport->send(
        new PinnedRequest('GET', "http://pinned.invalid:{$this->itPort}/"),
        $entry,
        Deadline::afterSeconds(5),
    );

    expect($result)->toBeInstanceOf(PinnedResponse::class)
        ->and($result->status)->toBe(200);
})->group('integration');
