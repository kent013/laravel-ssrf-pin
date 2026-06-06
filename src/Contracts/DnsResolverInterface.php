<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Contracts;

/**
 * host 名の DNS 解決を抽象化（テストで fake 注入可能にする）。
 */
interface DnsResolverInterface
{
    /**
     * A レコード（IPv4）を解決する。
     *
     * @return list<string>
     */
    public function resolveA(string $host): array;

    /**
     * AAAA レコード（IPv6）を解決する。
     *
     * @return list<string>
     */
    public function resolveAaaa(string $host): array;
}
