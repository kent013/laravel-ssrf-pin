<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Dns;

use Kent013\SsrfPin\Contracts\DnsResolverInterface;

/**
 * `dns_get_record` ベースの既定 DNS resolver。
 */
final class SystemDnsResolver implements DnsResolverInterface
{
    public function resolveA(string $host): array
    {
        return $this->resolve($host, DNS_A, 'ip');
    }

    public function resolveAaaa(string $host): array
    {
        return $this->resolve($host, DNS_AAAA, 'ipv6');
    }

    /**
     * @return list<string>
     */
    private function resolve(string $host, int $type, string $key): array
    {
        $records = @dns_get_record($host, $type);
        if ($records === false) {
            return [];
        }

        $ips = [];
        foreach ($records as $record) {
            if (isset($record[$key]) && is_string($record[$key]) && $record[$key] !== '') {
                $ips[] = $record[$key];
            }
        }

        return array_values(array_unique($ips));
    }
}
