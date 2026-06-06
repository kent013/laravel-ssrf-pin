<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Dtos;

use Kent013\SsrfPin\Enums\SsrfDenyReason;
use Kent013\SsrfPin\Enums\TransportError;

/**
 * pin 済み fetch の失敗結果。deny（SsrfDenyReason）または transport 失敗（TransportError）。
 * `$hopIndex` は失敗が起きた hop（0=初回）。呼び出し側が redirect 文脈の判定に使う。
 */
final readonly class PinnedFailure
{
    public function __construct(
        public SsrfDenyReason|TransportError $cause,
        public string $atUrl,
        public int $hopIndex,
    ) {}

    public function isDeny(): bool
    {
        return $this->cause instanceof SsrfDenyReason;
    }
}
