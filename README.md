# laravel-ssrf-pin

**SSRF-safe outbound HTTP for Laravel** — validates URLs/IPs and **pins each connection to the checked IP** via libcurl `CURLOPT_RESOLVE`, re-checking every redirect hop to defeat **DNS rebinding (TOCTOU)**.

> ⚠️ This is **application-layer defense-in-depth**, not a replacement for network-level egress controls / cloud metadata protection (IMDSv2, blocking `169.254.169.254`). Per OWASP, network controls are the primary defense.

## Why

A common SSRF guard resolves a hostname, checks the IP is public, then hands the hostname back to the HTTP client — which **re-resolves** at connect time. An attacker-controlled DNS can return a safe IP for the check and an internal IP for the actual connection (DNS rebinding). This package closes that window by **connecting only to the IP it validated** (`CURLOPT_RESOLVE`), and by **re-validating every redirect hop**.

## Requires

- PHP `^8.2`, `ext-curl`, libcurl `>= 7.40` (multi-address `CURLOPT_RESOLVE`).
- `ext-intl` (suggested) for IDN/punycode host normalization. Without it, non-ASCII hosts are denied (fail-secure).

## Usage

```php
use Kent013\SsrfPin\PinnedHttpClient;
use Kent013\SsrfPin\Dtos\Deadline;
use Kent013\SsrfPin\Dtos\PinnedRequest;
use Kent013\SsrfPin\Dtos\PinnedResponse;
use Kent013\SsrfPin\Dtos\PinnedFailure;

$client = app(PinnedHttpClient::class);

$result = $client->fetch(
    new PinnedRequest(method: 'HEAD', url: $userProvidedUrl),
    Deadline::afterSeconds(10),
);

if ($result instanceof PinnedFailure) {
    // map $result->cause (SsrfDenyReason | TransportError) to your app's vocabulary
} else {
    // $result instanceof PinnedResponse — $result->status, etc.
}
```

The neutral `SsrfDenyReason` enum is meant to be mapped (via `match`) into your application's own reason vocabulary — this package does not absorb app-specific taxonomies.

## Request and response bodies (v0.3)

`PinnedRequest` can carry a body, and `PinnedResponse` exposes the response body. Both additions are
**default-valued trailing parameters**, so every v0.2 positional call site keeps working unchanged.

```php
$result = $client->fetch(
    new PinnedRequest(
        method: 'POST',
        url: 'https://idp.example.com/oauth2/token',
        headers: ['Accept' => 'application/json'],
        body: http_build_query(['grant_type' => 'authorization_code', 'code' => $code]),
        contentType: 'application/x-www-form-urlencoded',
    ),
    Deadline::afterSeconds(10),
    followRedirects: false,
);

if ($result instanceof PinnedResponse) {
    $json = json_decode($result->body, true);
}
```

- `contentType` is applied as the `Content-Type` header and **wins** over any `Content-Type` entry in
  `headers` (so there is exactly one).
- A request without `body` sends no body at all (unchanged v0.2 behaviour).

### Response body size limit (fail-closed, enforced while streaming)

`GuzzleCurlTransport` reads the response body into a **byte-limited sink**
(`maxBodyBytes`, default 1 MiB; configurable via `config('ssrf-pin.max_body_bytes')`).

The limit is enforced **at the stream stage**, not after the fact: the sink is wired to libcurl's write
callback, and a chunk that would cross the limit is refused with a short write, which makes libcurl
abort the transfer immediately (`CURLE_WRITE_ERROR`). An oversized response is therefore never read to
completion and never held in memory. Measuring the size after buffering would not be a defense at all.

An oversized response is **not truncated** — it fails with
`PinnedFailure(TransportError::BodyTooLarge)`. Truncated JSON/JWKS must never look like a success.

Because Guzzle enables transparent content decoding, the limit applies to **decompressed** bytes, so a
compression bomb is stopped by the same limit.

### Redirects and bodies

- `followRedirects` (default `true`) preserves v0.2 behaviour. Pass `false` to get the `3xx` response
  back as-is (status, headers, body) without following it. Use this whenever the fetched URL or
  document will be **trusted afterwards** (OIDC discovery, JWKS, token endpoints): a `302` to another
  host must not be silently followed and then treated as the origin's answer.
- **The request body is sent on the first hop only.** When a redirect is followed, hop 2 and later are
  issued without `body`/`contentType` (and without `Content-Type`/`Content-Length` headers). This is a
  fixed contract, independent of 307/308 semantics: re-sending a body would hand credentials
  (`client_secret`, assertions) to an attacker-chosen redirect target.
- Other headers **are** forwarded across hops. If your headers carry credentials (e.g.
  `Authorization`), use `followRedirects: false` rather than relying on the hop loop.

## Design

- **Guard** (`UrlSafetyInspector`): scheme/port allowlist, credential rejection, host normalization (IDN, trailing dot, zone-id, strict-canonical IPv4, octal/hex/decimal rejection, IPv4-mapped IPv6), deny CIDRs (loopback/private/link-local/multicast/reserved), A+AAAA resolution with all-records validation.
- **Pin** (`GuzzleCurlTransport`): connects via an internally-constructed Guzzle `CurlHandler` only; `CURLOPT_RESOLVE` is a **required** argument of `PinnedCurlTransportInterface::send()` so pin cannot be bypassed; fail-secure (`CurlHandlerUnavailable`) when curl/libcurl is unusable.
- **Hop loop** (`PinnedHttpClient`): `allow_redirects=false` + explicit loop; every hop goes through the same inspect → pin → send pipeline; per-hop deadline budget; scheme-downgrade rejection; max-hops cap; body sent on the first hop only; optional non-following mode (`followRedirects: false`).
- **Body limit** (`ByteLimitedStream`): the response sink refuses the chunk that would cross `maxBodyBytes`, aborting the transfer inside libcurl's write callback (fail-closed, never truncating).

## Testing

`Kent013\SsrfPin\Testing\FakePinnedTransport` records every `PinnedRequest` it receives (including
`body` / `contentType`, reachable via `lastRequest()`) and returns whatever `PinnedResponse` /
`PinnedFailure` your responder produces — so consumers can pin the body contract without real curl.

```php
$transport = new FakePinnedTransport(
    fn (PinnedRequest $r) => new PinnedResponse(200, [], $r->url, [], '{"issuer":"https://idp.example.com"}'),
);
$client = new PinnedHttpClient(app(UrlSafetyInspector::class), $transport);
// ... $transport->lastRequest()?->body
```

## License

MIT
