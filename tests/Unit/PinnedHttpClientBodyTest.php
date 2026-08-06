<?php

declare(strict_types=1);

use Kent013\SsrfPin\Dtos\Deadline;
use Kent013\SsrfPin\Dtos\PinnedFailure;
use Kent013\SsrfPin\Dtos\PinnedRequest;
use Kent013\SsrfPin\Dtos\PinnedResponse;
use Kent013\SsrfPin\Enums\SsrfDenyReason;
use Kent013\SsrfPin\PinnedHttpClient;
use Kent013\SsrfPin\Testing\FakeDnsResolver;
use Kent013\SsrfPin\Testing\FakePinnedTransport;
use Kent013\SsrfPin\UrlSafetyInspector;

/**
 * v0.3 の body / followRedirects 契約（受入契約 3・4・5）。
 */
function bodyClient(UrlSafetyInspector $inspector, FakePinnedTransport $t, int $maxHops = 5): PinnedHttpClient
{
    return new PinnedHttpClient($inspector, $t, $maxHops);
}

function publicInspector(): UrlSafetyInspector
{
    return new UrlSafetyInspector(new FakeDnsResolver([
        'a.test' => ['93.184.216.34'],
        'b.test' => ['93.184.216.35'],
    ]));
}

// --- 受入契約 5: FakePinnedTransport が body/contentType を記録し応答 body を返せる ---

it('carries the request body and content type through to the transport', function () {
    $t = new FakePinnedTransport(
        fn (PinnedRequest $r): PinnedResponse => new PinnedResponse(200, [], $r->url, [], '{"access_token":"t"}'),
    );

    $result = bodyClient(publicInspector(), $t)->fetch(
        new PinnedRequest(
            'POST',
            'https://a.test/token',
            ['Accept' => 'application/json'],
            body: 'grant_type=authorization_code',
            contentType: 'application/x-www-form-urlencoded',
        ),
        Deadline::afterSeconds(5),
    );

    expect($t->lastRequest()?->body)->toBe('grant_type=authorization_code')
        ->and($t->lastRequest()?->contentType)->toBe('application/x-www-form-urlencoded')
        ->and($t->lastRequest()?->method)->toBe('POST')
        ->and($result)->toBeInstanceOf(PinnedResponse::class)
        ->and($result->body)->toBe('{"access_token":"t"}');
});

it('exposes the response body of the final hop', function () {
    $t = new FakePinnedTransport(fn (PinnedRequest $r): PinnedResponse => match (true) {
        str_contains($r->url, 'a.test') => new PinnedResponse(302, ['Location' => ['https://b.test/final']], $r->url, [], 'moved'),
        default => new PinnedResponse(200, [], $r->url, [], 'final-body'),
    });

    $result = bodyClient(publicInspector(), $t)->fetch(
        new PinnedRequest('GET', 'https://a.test/start'),
        Deadline::afterSeconds(5),
    );

    expect($result)->toBeInstanceOf(PinnedResponse::class)
        ->and($result->body)->toBe('final-body')
        ->and($result->hopUrls)->toBe(['https://a.test/start', 'https://b.test/final']);
});

// --- 受入契約 3: followRedirects: false で 3xx を追従せずそのまま返す ---

it('returns the 3xx response as-is when followRedirects is false', function () {
    $t = new FakePinnedTransport(
        fn (PinnedRequest $r): PinnedResponse => new PinnedResponse(302, ['Location' => ['https://b.test/next']], $r->url, [], 'moved'),
    );

    $result = bodyClient(publicInspector(), $t)->fetch(
        new PinnedRequest('GET', 'https://a.test/start'),
        Deadline::afterSeconds(5),
        followRedirects: false,
    );

    expect($result)->toBeInstanceOf(PinnedResponse::class)
        ->and($result->status)->toBe(302)
        ->and($result->body)->toBe('moved')
        ->and($result->finalUrl)->toBe('https://a.test/start')
        ->and($result->hopUrls)->toBe(['https://a.test/start'])
        ->and($result->header('Location'))->toBe('https://b.test/next')
        ->and($t->calls)->toHaveCount(1);
});

it('still applies the guard on the first hop when followRedirects is false', function () {
    $inspector = new UrlSafetyInspector(new FakeDnsResolver(['evil.test' => ['127.0.0.1']]));
    $t = new FakePinnedTransport;

    $result = bodyClient($inspector, $t)->fetch(
        new PinnedRequest('GET', 'https://evil.test/'),
        Deadline::afterSeconds(5),
        followRedirects: false,
    );

    expect($result)->toBeInstanceOf(PinnedFailure::class)
        ->and($result->cause)->toBe(SsrfDenyReason::Loopback)
        ->and($t->calls)->toBe([]);
});

it('does not follow redirects even when the target would be allowed', function () {
    $t = new FakePinnedTransport(
        fn (PinnedRequest $r): PinnedResponse => new PinnedResponse(307, ['Location' => ['https://b.test/next']], $r->url, [], ''),
    );

    $result = bodyClient(publicInspector(), $t)->fetch(
        new PinnedRequest('POST', 'https://a.test/token', body: 'x=1'),
        Deadline::afterSeconds(5),
        followRedirects: false,
    );

    expect($result)->toBeInstanceOf(PinnedResponse::class)
        ->and($result->status)->toBe(307)
        ->and($t->calls)->toHaveCount(1);
});

// --- 受入契約 4: redirect 追従時、2 hop 目以降は body を送らない ---

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

it('keeps the body on the first hop only, across a long redirect chain', function () {
    $inspector = new UrlSafetyInspector(new FakeDnsResolver(['loop.test' => ['93.184.216.34']]));
    $t = new FakePinnedTransport(fn (PinnedRequest $r): PinnedResponse => new PinnedResponse(
        302,
        ['Location' => ['https://loop.test/next']],
        $r->url,
        [],
        '',
    ));

    bodyClient($inspector, $t, maxHops: 4)->fetch(
        new PinnedRequest('POST', 'https://loop.test/0', body: 'secret'),
        Deadline::afterSeconds(5),
    );

    expect($t->calls)->toHaveCount(4)
        ->and($t->calls[0]['request']->body)->toBe('secret');

    foreach (array_slice($t->calls, 1) as $call) {
        expect($call['request']->body)->toBeNull();
    }
});
