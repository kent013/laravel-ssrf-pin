<?php

declare(strict_types=1);

use Kent013\SsrfPin\Dtos\Deadline;
use Kent013\SsrfPin\Dtos\PinnedFailure;
use Kent013\SsrfPin\Dtos\PinnedRequest;
use Kent013\SsrfPin\Dtos\PinnedResponse;
use Kent013\SsrfPin\Enums\SsrfDenyReason;
use Kent013\SsrfPin\Enums\TransportError;
use Kent013\SsrfPin\PinnedHttpClient;
use Kent013\SsrfPin\Tests\Support\FakeDnsResolver;
use Kent013\SsrfPin\Tests\Support\RecordingTransport;
use Kent013\SsrfPin\UrlSafetyInspector;

function client(UrlSafetyInspector $inspector, RecordingTransport $t, int $maxHops = 5): PinnedHttpClient
{
    return new PinnedHttpClient($inspector, $t, $maxHops);
}

it('pins the connection to the validated IP set (rebinding defense)', function () {
    // 検査時に public IP を返す resolver。pin entry はこの検証済み IP からのみ生成される。
    $inspector = new UrlSafetyInspector(new FakeDnsResolver(['ok.test' => ['93.184.216.34']]));
    $t = new RecordingTransport(true, new PinnedResponse(200, [], 'http://ok.test', []));

    $result = client($inspector, $t)->fetch(new PinnedRequest('HEAD', 'http://ok.test'), Deadline::afterSeconds(5));

    expect($result)->toBeInstanceOf(PinnedResponse::class)
        ->and($t->receivedEntries)->toHaveCount(1)
        ->and($t->receivedEntries[0]->host)->toBe('ok.test')
        ->and($t->receivedEntries[0]->port)->toBe(80)
        ->and($t->receivedEntries[0]->ips)->toBe(['93.184.216.34'])
        ->and($t->receivedEntries[0]->toCurlFormat())->toBe('ok.test:80:93.184.216.34');
});

it('fails secure when transport is unavailable', function () {
    $inspector = new UrlSafetyInspector(new FakeDnsResolver(['ok.test' => ['93.184.216.34']]));
    $t = new RecordingTransport(false);

    $result = client($inspector, $t)->fetch(new PinnedRequest('HEAD', 'http://ok.test'), Deadline::afterSeconds(5));

    expect($result)->toBeInstanceOf(PinnedFailure::class)
        ->and($result->cause)->toBe(SsrfDenyReason::CurlHandlerUnavailable);
});

it('re-validates each redirect hop and denies a hop that resolves to a private IP', function () {
    $inspector = new UrlSafetyInspector(new FakeDnsResolver([
        'a.test' => ['93.184.216.34'],
        'b.test' => ['127.0.0.1'], // redirect 先が loopback
    ]));
    $t = new RecordingTransport(true, new PinnedResponse(302, ['Location' => ['http://b.test/']], 'http://a.test', []));

    $result = client($inspector, $t)->fetch(new PinnedRequest('GET', 'http://a.test'), Deadline::afterSeconds(5));

    expect($result)->toBeInstanceOf(PinnedFailure::class)
        ->and($result->cause)->toBe(SsrfDenyReason::Loopback)
        ->and($result->hopIndex)->toBe(1);
});

it('rejects https->http scheme downgrade on redirect', function () {
    $inspector = new UrlSafetyInspector(new FakeDnsResolver([
        'a.test' => ['93.184.216.34'],
        'b.test' => ['93.184.216.35'],
    ]));
    $t = new RecordingTransport(true, new PinnedResponse(301, ['Location' => ['http://b.test/']], 'https://a.test', []));

    $result = client($inspector, $t)->fetch(new PinnedRequest('GET', 'https://a.test'), Deadline::afterSeconds(5));

    expect($result)->toBeInstanceOf(PinnedFailure::class)
        ->and($result->cause)->toBe(SsrfDenyReason::SchemeDowngrade);
});

it('stops after max redirect hops', function () {
    $inspector = new UrlSafetyInspector(new FakeDnsResolver(['loop.test' => ['93.184.216.34']]));
    $t = new RecordingTransport(
        true,
        new PinnedResponse(302, ['Location' => ['http://loop.test/']], 'http://loop.test', []),
        new PinnedResponse(302, ['Location' => ['http://loop.test/']], 'http://loop.test', []),
    );

    $result = client($inspector, $t, maxHops: 2)->fetch(new PinnedRequest('GET', 'http://loop.test'), Deadline::afterSeconds(5));

    expect($result)->toBeInstanceOf(PinnedFailure::class)
        ->and($result->cause)->toBe(SsrfDenyReason::TooManyRedirects);
});

it('returns Timeout when deadline is exhausted', function () {
    $inspector = new UrlSafetyInspector(new FakeDnsResolver(['ok.test' => ['93.184.216.34']]));
    $t = new RecordingTransport(true);

    $result = client($inspector, $t)->fetch(new PinnedRequest('GET', 'http://ok.test'), Deadline::afterSeconds(0));

    expect($result)->toBeInstanceOf(PinnedFailure::class)
        ->and($result->cause)->toBe(TransportError::Timeout);
});
