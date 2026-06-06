<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Dtos;

/**
 * 単調増加クロック（hrtime）ベースの絶対期限。hop ごとの残時間算出に使う。
 *
 * `Date::now()` 等の wall-clock に依存せず、システム時刻変更の影響を受けない。
 */
final readonly class Deadline
{
    /** @param int $deadlineNs hrtime(true) 基準の絶対期限（ナノ秒） */
    private function __construct(private int $deadlineNs) {}

    public static function afterSeconds(float $seconds): self
    {
        $now = hrtime(true);

        return new self($now + (int) round($seconds * 1_000_000_000));
    }

    /** 残り秒（負にはしない）。 */
    public function remainingSeconds(): float
    {
        $remainingNs = $this->deadlineNs - hrtime(true);

        return $remainingNs <= 0 ? 0.0 : $remainingNs / 1_000_000_000;
    }

    public function isExpired(): bool
    {
        return $this->remainingSeconds() <= 0.0;
    }

    /** 残時間を上限に cap した timeout 秒（最低 0）。 */
    public function cappedBy(float $seconds): float
    {
        return min($seconds, $this->remainingSeconds());
    }
}
