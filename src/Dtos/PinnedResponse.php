<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Dtos;

/**
 * pin 済み fetch の成功結果（最終 hop の response）。
 */
final readonly class PinnedResponse
{
    /**
     * @param  array<string, list<string>>  $headers
     * @param  list<string>  $hopUrls  guard を通過した各 hop の URL（順序保持）。
     */
    public function __construct(
        public int $status,
        public array $headers,
        public string $finalUrl,
        public array $hopUrls,
    ) {}

    public function header(string $name): ?string
    {
        foreach ($this->headers as $key => $values) {
            if (strcasecmp($key, $name) === 0) {
                return $values[0] ?? null;
            }
        }

        return null;
    }
}
