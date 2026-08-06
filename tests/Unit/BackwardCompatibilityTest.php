<?php

declare(strict_types=1);

use Kent013\SsrfPin\Dtos\Deadline;
use Kent013\SsrfPin\Dtos\PinnedRequest;
use Kent013\SsrfPin\Dtos\PinnedResponse;
use Kent013\SsrfPin\PinnedHttpClient;
use Kent013\SsrfPin\Testing\FakeDnsResolver;
use Kent013\SsrfPin\Testing\FakePinnedTransport;
use Kent013\SsrfPin\Transport\GuzzleCurlTransport;
use Kent013\SsrfPin\UrlSafetyInspector;

/**
 * v0.2 の公開 API を v0.3 が壊していないことの pin。
 * 新規フィールド・新規引数はすべて「既定値つきで末尾に追加」でなければならない。
 */
it('keeps the v0.2 positional constructor of PinnedRequest working', function () {
    $request = new PinnedRequest('HEAD', 'https://example.test/', ['Accept' => '*/*'], 3.0);

    expect($request->method)->toBe('HEAD')
        ->and($request->url)->toBe('https://example.test/')
        ->and($request->headers)->toBe(['Accept' => '*/*'])
        ->and($request->connectTimeout)->toBe(3.0)
        ->and($request->body)->toBeNull()
        ->and($request->contentType)->toBeNull();
});

it('keeps the v0.2 positional constructor of PinnedResponse working', function () {
    $response = new PinnedResponse(204, ['X-Test' => ['1']], 'https://example.test/', ['https://example.test/']);

    expect($response->status)->toBe(204)
        ->and($response->finalUrl)->toBe('https://example.test/')
        ->and($response->hopUrls)->toBe(['https://example.test/'])
        ->and($response->header('x-test'))->toBe('1')
        ->and($response->body)->toBe('');
});

it('keeps the v0.2 two-argument fetch() signature working and follows redirects by default', function () {
    $inspector = new UrlSafetyInspector(new FakeDnsResolver([
        'a.test' => ['93.184.216.34'],
        'b.test' => ['93.184.216.35'],
    ]));
    $t = new FakePinnedTransport(fn (PinnedRequest $r): PinnedResponse => match (true) {
        str_contains($r->url, 'a.test') => new PinnedResponse(302, ['Location' => ['https://b.test/']], $r->url, []),
        default => new PinnedResponse(200, [], $r->url, []),
    });

    $result = (new PinnedHttpClient($inspector, $t))->fetch(
        new PinnedRequest('GET', 'https://a.test/'),
        Deadline::afterSeconds(5),
    );

    expect($result)->toBeInstanceOf(PinnedResponse::class)
        ->and($result->status)->toBe(200)
        ->and($t->calls)->toHaveCount(2);
});

it('keeps GuzzleCurlTransport constructible without arguments', function () {
    expect(new GuzzleCurlTransport)->toBeInstanceOf(GuzzleCurlTransport::class);
});

it('exposes followRedirects as the third parameter of fetch() (consumer contract pin)', function () {
    $parameters = (new ReflectionMethod(PinnedHttpClient::class, 'fetch'))->getParameters();

    expect($parameters[2]->getName())->toBe('followRedirects')
        ->and($parameters[2]->isDefaultValueAvailable())->toBeTrue()
        ->and($parameters[2]->getDefaultValue())->toBeTrue();
});

it('exposes the v0.3 body properties consumers pin against', function () {
    expect(property_exists(PinnedRequest::class, 'body'))->toBeTrue()
        ->and(property_exists(PinnedRequest::class, 'contentType'))->toBeTrue()
        ->and(property_exists(PinnedResponse::class, 'body'))->toBeTrue();
});
