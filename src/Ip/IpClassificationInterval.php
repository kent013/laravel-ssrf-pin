<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Ip;

use Kent013\SsrfPin\Enums\Reachability;
use Kent013\SsrfPin\Enums\SsrfDenyReason;

/**
 * 分類表の 1 区間（両端を含む）。
 *
 * 端点は `inet_pton` のバイナリ表現で保持する。比較は固定長のバイナリ文字列比較
 * （`strcmp`）だけで完結し、**IP の文字列表現を切ったり前方一致したりしない**。
 */
final class IpClassificationInterval
{
    /**
     * @param  string  $startBinary  inet_pton した下端（4 or 16 bytes、両端を含む）
     * @param  string  $endBinary  inet_pton した上端（同上）
     */
    public function __construct(
        public readonly string $startBinary,
        public readonly string $endBinary,
        public readonly string $name,
        public readonly bool $globallyReachable,
        public readonly ?SsrfDenyReason $denyReason,
    ) {}

    public function contains(string $binary): bool
    {
        return strcmp($binary, $this->startBinary) >= 0
            && strcmp($binary, $this->endBinary) <= 0;
    }

    public function reachability(): Reachability
    {
        return $this->globallyReachable
            ? Reachability::PublicUnicast
            : Reachability::NotGloballyReachable;
    }
}
