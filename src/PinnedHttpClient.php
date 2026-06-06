<?php

declare(strict_types=1);

namespace Kent013\SsrfPin;

use GuzzleHttp\Psr7\UriResolver;
use GuzzleHttp\Psr7\Utils;
use Kent013\SsrfPin\Contracts\PinnedCurlTransportInterface;
use Kent013\SsrfPin\Dtos\CurlResolveEntry;
use Kent013\SsrfPin\Dtos\Deadline;
use Kent013\SsrfPin\Dtos\PinnedFailure;
use Kent013\SsrfPin\Dtos\PinnedRequest;
use Kent013\SsrfPin\Dtos\PinnedResponse;
use Kent013\SsrfPin\Enums\SsrfDenyReason;
use Kent013\SsrfPin\Enums\TransportError;
use Throwable;

/**
 * 検査済み IP に pin しながら redirect を hop ごとに再検査する SSRF-safe fetch クライアント。
 *
 * 各 hop は必ず inspect()→CurlResolveEntry 生成→transport.send() の同一 pipeline を通る
 * （redirect 先も同様に再検査）。allow_redirects は無効化し、自前ループで追従する。
 */
final class PinnedHttpClient
{
    public function __construct(
        private readonly UrlSafetyInspector $inspector,
        private readonly PinnedCurlTransportInterface $transport,
        private readonly int $maxRedirectHops = 5,
    ) {}

    public function fetch(PinnedRequest $request, Deadline $deadline): PinnedResponse|PinnedFailure
    {
        if (! $this->transport->isAvailable()) {
            return new PinnedFailure(SsrfDenyReason::CurlHandlerUnavailable, $request->url, 0);
        }

        $current = $request->url;
        /** @var list<string> $hopUrls */
        $hopUrls = [];

        for ($hop = 0; $hop < $this->maxRedirectHops; $hop++) {
            if ($deadline->isExpired()) {
                return new PinnedFailure(TransportError::Timeout, $current, $hop);
            }

            $decision = $this->inspector->inspect($current);
            if (! $decision->allowed) {
                return new PinnedFailure(
                    $decision->reason ?? SsrfDenyReason::InvalidHost,
                    $current,
                    $hop,
                );
            }

            $hopUrls[] = $current;

            // 検査結果（normalizedHost+port+全 validatedIps）からのみ pin entry を生成。
            // allow 時は常に揃うが、型安全のため明示ガード（揃わなければ fail-secure）。
            if ($decision->normalizedHost === null || $decision->port === null || $decision->validatedIps === []) {
                return new PinnedFailure(SsrfDenyReason::InvalidHost, $current, $hop);
            }
            $entry = new CurlResolveEntry(
                $decision->normalizedHost,
                $decision->port,
                $decision->validatedIps,
            );

            $hopRequest = new PinnedRequest($request->method, $current, $request->headers, $request->connectTimeout);
            $result = $this->transport->send($hopRequest, $entry, $deadline);
            if ($result instanceof PinnedFailure) {
                return new PinnedFailure($result->cause, $current, $hop);
            }

            $status = $result->status;
            if ($status < 300 || $status >= 400) {
                return new PinnedResponse($status, $result->headers, $current, $hopUrls);
            }

            // 3xx: Location 追従
            $location = $result->header('Location');
            if ($location === null || $location === '') {
                return new PinnedResponse($status, $result->headers, $current, $hopUrls);
            }

            $next = $this->resolveAbsoluteUrl($current, $location);
            if ($next === null) {
                return new PinnedFailure(SsrfDenyReason::InvalidHost, $current, $hop);
            }

            if ($this->isSchemeDowngrade($current, $next)) {
                return new PinnedFailure(SsrfDenyReason::SchemeDowngrade, $current, $hop);
            }

            $current = $next;
        }

        return new PinnedFailure(SsrfDenyReason::TooManyRedirects, $current, $this->maxRedirectHops);
    }

    private function resolveAbsoluteUrl(string $base, string $location): ?string
    {
        try {
            return (string) UriResolver::resolve(Utils::uriFor($base), Utils::uriFor($location));
        } catch (Throwable) {
            return null;
        }
    }

    private function isSchemeDowngrade(string $current, string $next): bool
    {
        $currentScheme = strtolower((string) parse_url($current, PHP_URL_SCHEME));
        $nextScheme = strtolower((string) parse_url($next, PHP_URL_SCHEME));

        return $currentScheme === 'https' && $nextScheme === 'http';
    }
}
