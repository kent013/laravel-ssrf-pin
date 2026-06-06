<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Testing;

use Kent013\SsrfPin\Contracts\DnsResolverInterface;

/**
 * 消費者がテストで host→IP を固定するための出荷 fake DNS resolver。
 */
final class FakeDnsResolver implements DnsResolverInterface
{
    /**
     * @param  array<string, list<string>>  $aRecords
     * @param  array<string, list<string>>  $aaaaRecords
     */
    public function __construct(
        private array $aRecords = [],
        private array $aaaaRecords = [],
    ) {}

    public function resolveA(string $host): array
    {
        return $this->aRecords[$host] ?? [];
    }

    public function resolveAaaa(string $host): array
    {
        return $this->aaaaRecords[$host] ?? [];
    }
}
