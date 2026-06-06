<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Contracts;

use Kent013\SsrfPin\Dtos\CurlResolveEntry;
use Kent013\SsrfPin\Dtos\Deadline;
use Kent013\SsrfPin\Dtos\PinnedFailure;
use Kent013\SsrfPin\Dtos\PinnedRequest;
use Kent013\SsrfPin\Dtos\PinnedResponse;

/**
 * pin を必ず適用する transport の契約。
 *
 * `CurlResolveEntry` を**必須引数**にすることで「検証済み IP に pin する」ことを型で強制する。
 * 実装は受領した entry を必ず `CURLOPT_RESOLVE` に適用しなければならない（pin の迂回不能化）。
 * curl ハンドラを使えない実装/環境は `isAvailable()=false` を返し、呼び出し側で fail-secure させる。
 */
interface PinnedCurlTransportInterface
{
    /**
     * 単一 hop の送信（redirect は追従しない／呼び出し側が hop ループを回す）。
     */
    public function send(PinnedRequest $request, CurlResolveEntry $entry, Deadline $deadline): PinnedResponse|PinnedFailure;

    /**
     * 複数アドレス CURLOPT_RESOLVE を満たす curl が使えるか（libcurl version gate 含む）。
     * false の場合、PinnedHttpClient は CurlHandlerUnavailable で fail-secure する。
     */
    public function isAvailable(): bool;
}
