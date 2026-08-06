<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Dtos;

/**
 * pin 済み fetch の成功結果（最終 hop の response）。
 *
 * v0.3: `$body` を追加（既定値つきの末尾追加なので v0.2 の positional 呼び出しはそのまま動く）。
 * body は transport の上限バイト数（既定 1 MiB）以内であることが保証される。
 * 上限を超えた応答は **切り詰めずに** `PinnedFailure(TransportError::BodyTooLarge)` になるため、
 * ここに「途中まで」の body が入ることはない。
 */
final readonly class PinnedResponse
{
    /**
     * @param  array<string, list<string>>  $headers
     * @param  list<string>  $hopUrls  guard を通過した各 hop の URL（順序保持）。
     * @param  string  $body  応答 body（上限内の全量）。HEAD や body 無し応答では空文字。
     */
    public function __construct(
        public int $status,
        public array $headers,
        public string $finalUrl,
        public array $hopUrls,
        public string $body = '',
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
