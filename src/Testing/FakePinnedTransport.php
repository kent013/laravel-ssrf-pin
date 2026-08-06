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
 *   request は body / contentType を含む丸ごとの DTO なので、`lastRequest()` で
 *   「body が transport まで届いたか」「redirect の 2 hop 目に body が再送されていないか」を検証できる。
 * - 応答 body は `new PinnedResponse(..., body: '...')` で自由に注入できる。
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

    /** 直近に受領した request（body / contentType の到達検証に使う）。未送信なら null。 */
    public function lastRequest(): ?PinnedRequest
    {
        $last = end($this->calls);

        return $last === false ? null : $last['request'];
    }

    /** 直近に受領した pin entry。未送信なら null。 */
    public function lastEntry(): ?CurlResolveEntry
    {
        $last = end($this->calls);

        return $last === false ? null : $last['entry'];
    }

    public function send(PinnedRequest $request, CurlResolveEntry $entry, Deadline $deadline): PinnedResponse|PinnedFailure
    {
        $this->calls[] = ['request' => $request, 'entry' => $entry];

        return ($this->responder)($request, $entry);
    }
}
