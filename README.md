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

## Design

- **Guard** (`UrlSafetyInspector`): scheme/port allowlist, credential rejection, host normalization (IDN, trailing dot, zone-id, strict-canonical IPv4, octal/hex/decimal rejection, IPv4-mapped IPv6), deny CIDRs (loopback/private/link-local/multicast/reserved), A+AAAA resolution with all-records validation.
- **Pin** (`GuzzleCurlTransport`): connects via an internally-constructed Guzzle `CurlHandler` only; `CURLOPT_RESOLVE` is a **required** argument of `PinnedCurlTransportInterface::send()` so pin cannot be bypassed; fail-secure (`CurlHandlerUnavailable`) when curl/libcurl is unusable.
- **Hop loop** (`PinnedHttpClient`): `allow_redirects=false` + explicit loop; every hop goes through the same inspect → pin → send pipeline; per-hop deadline budget; scheme-downgrade rejection; max-hops cap.

## License

MIT
