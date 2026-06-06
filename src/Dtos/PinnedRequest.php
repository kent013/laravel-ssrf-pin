<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Dtos;

/**
 * pin 済み fetch の入力。method 非依存（HEAD/GET/任意）。
 */
final readonly class PinnedRequest
{
    /**
     * @param  array<string, string>  $headers
     */
    public function __construct(
        public string $method,
        public string $url,
        public array $headers = [],
        public float $connectTimeout = 2.0,
    ) {}
}
