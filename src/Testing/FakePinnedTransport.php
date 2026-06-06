<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Testing;

use Closure;
use Kent013\SsrfPin\Contracts\PinnedCurlTransportInterface;
use Kent013\SsrfPin\Dtos\CurlResolveEntry;
use Kent013\SsrfPin\Dtos\Deadline;
use Kent013\SsrfPin\Dtos\PinnedFailure;
use Kent013\SsrfPin\Dtos\PinnedRequest;
use Kent013\SsrfPin\Dtos\PinnedResponse;

/**
 * 消費者（aigenba / spirux）が PinnedHttpClient を実 curl なしでテストするための出荷 fake。
 *
 * - `$responder` で (PinnedRequest, CurlResolveEntry) → PinnedResponse|PinnedFailure を返す。
 * - 受領した request / resolve entry を記録（pin が検証済み IP で適用されたかを検証可能）。
 * - `$available=false` で curl 不在の fail-secure 経路を再現できる。
 */
final class FakePinnedTransport implements PinnedCurlTransportInterface
{
    /** @var list<array{request: PinnedRequest, entry: CurlResolveEntry}> */
    public array $calls = [];

    /** @var Closure(PinnedRequest, CurlResolveEntry): (PinnedResponse|PinnedFailure) */
    private Closure $responder;

    /**
     * @param  (callable(PinnedRequest, CurlResolveEntry): (PinnedResponse|PinnedFailure))|null  $responder
     */
    public function __construct(?callable $responder = null, private bool $available = true)
    {
        $this->responder = $responder !== null
            ? Closure::fromCallable($responder)
            : static fn (PinnedRequest $r): PinnedResponse => new PinnedResponse(200, [], $r->url, []);
    }

    public function isAvailable(): bool
    {
        return $this->available;
    }

    public function send(PinnedRequest $request, CurlResolveEntry $entry, Deadline $deadline): PinnedResponse|PinnedFailure
    {
        $this->calls[] = ['request' => $request, 'entry' => $entry];

        return ($this->responder)($request, $entry);
    }
}
