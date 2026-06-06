<?php

declare(strict_types=1);

use Kent013\SsrfPin\Enums\SsrfDenyReason;
use Kent013\SsrfPin\Testing\FakeDnsResolver;
use Kent013\SsrfPin\UrlSafetyInspector;

function inspector(array $a = [], array $aaaa = []): UrlSafetyInspector
{
    return new UrlSafetyInspector(new FakeDnsResolver($a, $aaaa));
}

it('allows a public host and returns all resolved IPs', function () {
    $d = inspector(['example.com' => ['93.184.216.34']], ['example.com' => ['2606:2800:220:1:248:1893:25c8:1946']])
        ->inspect('https://example.com/path');

    expect($d->allowed)->toBeTrue()
        ->and($d->normalizedHost)->toBe('example.com')
        ->and($d->port)->toBe(443)
        ->and($d->validatedIps)->toContain('93.184.216.34')
        ->and($d->validatedIps)->toContain('2606:2800:220:1:248:1893:25c8:1946');
});

it('rejects non-http(s) schemes', function () {
    expect(inspector()->inspect('ftp://example.com')->reason)->toBe(SsrfDenyReason::SchemeNotAllowed);
    expect(inspector()->inspect('file:///etc/passwd')->reason)->toBe(SsrfDenyReason::SchemeNotAllowed);
});

it('rejects credentials in URL', function () {
    expect(inspector(['example.com' => ['93.184.216.34']])->inspect('https://user:pass@example.com')->reason)
        ->toBe(SsrfDenyReason::CredentialInUrl);
});

it('rejects disallowed ports', function () {
    expect(inspector(['example.com' => ['93.184.216.34']])->inspect('https://example.com:8080')->reason)
        ->toBe(SsrfDenyReason::DisallowedPort);
});

it('denies private / loopback / link-local / multicast IP literals', function () {
    expect(inspector()->inspect('http://127.0.0.1')->reason)->toBe(SsrfDenyReason::Loopback);
    expect(inspector()->inspect('http://10.0.0.5')->reason)->toBe(SsrfDenyReason::PrivateRange);
    expect(inspector()->inspect('http://192.168.1.1')->reason)->toBe(SsrfDenyReason::PrivateRange);
    expect(inspector()->inspect('http://169.254.169.254')->reason)->toBe(SsrfDenyReason::LinkLocal);
    expect(inspector()->inspect('http://224.0.0.1')->reason)->toBe(SsrfDenyReason::Multicast);
});

it('denies hosts that resolve to private IPs', function () {
    $d = inspector(['evil.test' => ['169.254.169.254']])->inspect('http://evil.test');
    expect($d->reason)->toBe(SsrfDenyReason::LinkLocal);
});

it('denies if ANY resolved IP is private (all-records validation)', function () {
    $d = inspector(['mix.test' => ['93.184.216.34', '127.0.0.1']])->inspect('http://mix.test');
    expect($d->reason)->toBe(SsrfDenyReason::Loopback);
});

it('treats localhost and *.localhost as loopback without DNS', function () {
    expect(inspector()->inspect('http://localhost')->reason)->toBe(SsrfDenyReason::Loopback);
    expect(inspector()->inspect('http://api.localhost')->reason)->toBe(SsrfDenyReason::Loopback);
});

it('rejects non-canonical / octal / hex / decimal IPv4-like hosts', function () {
    foreach (['http://127.1', 'http://127.0.1', 'http://2130706433', 'http://0x7f.0.0.1', 'http://0177.0.0.1'] as $url) {
        expect(inspector()->inspect($url)->reason)->toBe(SsrfDenyReason::InvalidHost, "for {$url}");
    }
});

it('normalizes IPv4-mapped IPv6 and denies if mapped target is private', function () {
    expect(inspector()->inspect('http://[::ffff:127.0.0.1]')->reason)->toBe(SsrfDenyReason::Loopback);
});

it('rejects IPv6 zone ids', function () {
    expect(inspector()->inspect('http://[fe80::1%25eth0]')->reason)->toBe(SsrfDenyReason::InvalidHost);
});

it('strips trailing dot and lowercases host', function () {
    $d = inspector(['example.com' => ['93.184.216.34']])->inspect('http://Example.COM./');
    expect($d->allowed)->toBeTrue()->and($d->normalizedHost)->toBe('example.com');
});

it('fails DNS resolution when no records', function () {
    expect(inspector()->inspect('http://no-records.test')->reason)->toBe(SsrfDenyReason::DnsResolutionFailed);
});

it('allows IPv6-only public hosts (not fail-closed)', function () {
    $d = inspector([], ['v6.test' => ['2606:2800:220:1:248:1893:25c8:1946']])->inspect('http://v6.test');
    expect($d->allowed)->toBeTrue()->and($d->validatedIps)->toBe(['2606:2800:220:1:248:1893:25c8:1946']);
});

it('denies IP literals when denyIpLiterals is enabled', function () {
    $i = new UrlSafetyInspector(new FakeDnsResolver, denyIpLiterals: true);
    expect($i->inspect('http://93.184.216.34')->reason)->toBe(SsrfDenyReason::IpLiteralNotAllowed);
    // hostname 経路は影響なし
    $i2 = new UrlSafetyInspector(new FakeDnsResolver(['ok.test' => ['93.184.216.34']]), denyIpLiterals: true);
    expect($i2->inspect('http://ok.test')->allowed)->toBeTrue();
});
