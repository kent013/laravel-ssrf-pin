<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Tests\Support;

use Kent013\SsrfPin\Contracts\PinnedCurlTransportInterface;
use Kent013\SsrfPin\Dtos\CurlResolveEntry;
use Kent013\SsrfPin\Dtos\Deadline;
use Kent013\SsrfPin\Dtos\PinnedFailure;
use Kent013\SsrfPin\Dtos\PinnedRequest;
use Kent013\SsrfPin\Dtos\PinnedResponse;

/**
 * テスト用 transport。受領した CurlResolveEntry を記録し、スクリプトした結果を順に返す。
 * 「pin entry が検証済み IP からのみ生成される」ことの検証に使う（pin を無視できない fake）。
 */
final class RecordingTransport implements PinnedCurlTransportInterface
{
    /** @var list<CurlResolveEntry> */
    public array $receivedEntries = [];

    /** @var list<PinnedResponse|PinnedFailure> */
    private array $scripted;

    private int $index = 0;

    public function __construct(
        private readonly bool $available = true,
        PinnedResponse|PinnedFailure ...$scripted,
    ) {
        $this->scripted = array_values($scripted);
    }

    public function isAvailable(): bool
    {
        return $this->available;
    }

    public function send(PinnedRequest $request, CurlResolveEntry $entry, Deadline $deadline): PinnedResponse|PinnedFailure
    {
        $this->receivedEntries[] = $entry;
        $result = $this->scripted[$this->index] ?? null;
        $this->index++;

        return $result ?? new PinnedResponse(200, [], $request->url, []);
    }
}
