<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Dtos;

use Kent013\SsrfPin\Enums\SsrfDenyReason;

/**
 * URL/IP 検査の結果。allow 時は正規化 host と検証済み IP 群を保持する。
 */
final readonly class UrlSafetyDecision
{
    /**
     * @param  list<string>  $validatedIps  検証済み（public）IP 群（A+AAAA）。
     */
    private function __construct(
        public bool $allowed,
        public ?SsrfDenyReason $reason,
        public ?string $normalizedHost,
        public array $validatedIps,
        public ?int $port,
    ) {}

    /**
     * @param  list<string>  $validatedIps
     */
    public static function allow(string $normalizedHost, array $validatedIps, int $port): self
    {
        return new self(true, null, $normalizedHost, $validatedIps, $port);
    }

    /**
     * @param  list<string>  $validatedIps
     */
    public static function deny(SsrfDenyReason $reason, ?string $normalizedHost = null, array $validatedIps = []): self
    {
        return new self(false, $reason, $normalizedHost, $validatedIps, null);
    }
}
