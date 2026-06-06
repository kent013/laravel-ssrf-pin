<?php

declare(strict_types=1);

namespace Kent013\SsrfPin;

use Kent013\SsrfPin\Contracts\DnsResolverInterface;
use Kent013\SsrfPin\Dtos\UrlSafetyDecision;
use Kent013\SsrfPin\Enums\SsrfDenyReason;

/**
 * URL/IP 安全性検査の SSOT（spirux UrlSafetyGuard + aigenba SsrfGuard の和集合）。
 *
 * 手順（early return）:
 *  1. parse_url
 *  2. scheme allowlist
 *  3. credential (user/pass) 拒否
 *  4. port allowlist
 *  5. host 正規化（bracket / zone id / 末尾ドット / lowercase / IDN→ASCII or fail-secure）
 *  6. localhost / *.localhost → Loopback
 *  7. IP literal（strict canonical のみ）→ classify
 *  8. 非 canonical な数値/8進/16進 IPv4-like → InvalidHost
 *  9. DNS 解決 A+AAAA → 全件 classify → 全 public なら allow（全 IP を pin 対象に）
 */
final class UrlSafetyInspector
{
    /** @var list<string> */
    private const array DENY_CIDRS_V4 = [
        '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
        '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.168.0.0/16',
        '198.18.0.0/15', '224.0.0.0/4', '240.0.0.0/4', '255.255.255.255/32',
    ];

    /** @var list<string> */
    private const array DENY_CIDRS_V6 = [
        '::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8',
        '64:ff9b::/96', '100::/64', '2001::/23',
    ];

    /**
     * @param  list<string>  $allowedSchemes
     * @param  list<int>  $allowedPorts
     * @param  list<string>  $additionalDenyCidrs  アプリ拡張用の追加 deny CIDR。
     */
    public function __construct(
        private readonly DnsResolverInterface $dnsResolver,
        private readonly array $allowedSchemes = ['http', 'https'],
        private readonly array $allowedPorts = [80, 443],
        private readonly array $additionalDenyCidrs = [],
    ) {}

    public function inspect(string $url): UrlSafetyDecision
    {
        $parts = parse_url($url);
        if (! is_array($parts)) {
            return UrlSafetyDecision::deny(SsrfDenyReason::InvalidHost);
        }

        $scheme = isset($parts['scheme']) ? strtolower($parts['scheme']) : '';
        if (! in_array($scheme, $this->allowedSchemes, true)) {
            return UrlSafetyDecision::deny(SsrfDenyReason::SchemeNotAllowed);
        }

        if (isset($parts['user']) || isset($parts['pass'])) {
            return UrlSafetyDecision::deny(SsrfDenyReason::CredentialInUrl);
        }

        $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);
        if (! in_array($port, $this->allowedPorts, true)) {
            return UrlSafetyDecision::deny(SsrfDenyReason::DisallowedPort);
        }

        $host = $this->normalizeHost($parts['host'] ?? null);
        if ($host === null) {
            return UrlSafetyDecision::deny(SsrfDenyReason::InvalidHost);
        }

        if ($host === 'localhost' || str_ends_with($host, '.localhost')) {
            return UrlSafetyDecision::deny(SsrfDenyReason::Loopback, $host, ['127.0.0.1']);
        }

        // IP literal（filter_var が通すのは canonical のみ）
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            $reason = $this->classifyIp($host);
            if ($reason !== null) {
                return UrlSafetyDecision::deny($reason, $host, [$host]);
            }

            return UrlSafetyDecision::allow($host, [$host], $port);
        }

        // 非 canonical な数値/8進/16進 IPv4-like host（127.1 / 2130706433 / 0x7f.0.0.1 / 0177.0.0.1）
        if (preg_match('/^(\d+|0x[0-9a-f]+)(\.(\d+|0x[0-9a-f]+))*$/i', $host) === 1) {
            return UrlSafetyDecision::deny(SsrfDenyReason::InvalidHost, $host);
        }

        $ipv4 = $this->dnsResolver->resolveA($host);
        $ipv6 = $this->dnsResolver->resolveAaaa($host);
        $ips = array_values(array_unique([...$ipv4, ...$ipv6]));
        if ($ips === []) {
            return UrlSafetyDecision::deny(SsrfDenyReason::DnsResolutionFailed, $host);
        }

        foreach ($ips as $ip) {
            $reason = $this->classifyIp($ip);
            if ($reason !== null) {
                return UrlSafetyDecision::deny($reason, $host, $ips);
            }
        }

        return UrlSafetyDecision::allow($host, $ips, $port);
    }

    /**
     * host 正規化。失敗（不正/zone id/IDN 変換不可）は null。
     */
    private function normalizeHost(?string $hostRaw): ?string
    {
        if ($hostRaw === null || $hostRaw === '') {
            return null;
        }

        if (str_contains($hostRaw, '%')) {
            return null; // IPv6 zone id (fe80::1%eth0)
        }

        if (str_starts_with($hostRaw, '[') && str_ends_with($hostRaw, ']')) {
            $hostRaw = substr($hostRaw, 1, -1);
        }

        $hostRaw = rtrim($hostRaw, '.');
        if ($hostRaw === '') {
            return null;
        }

        // 非 ASCII を含む場合は IDN→ASCII（ext-intl）。無ければ fail-secure で拒否。
        if (preg_match('/[^\x00-\x7F]/', $hostRaw) === 1) {
            if (! function_exists('idn_to_ascii')) {
                return null;
            }
            $ascii = idn_to_ascii(
                $hostRaw,
                IDNA_NONTRANSITIONAL_TO_ASCII | IDNA_CHECK_BIDI | IDNA_CHECK_CONTEXTJ,
                INTL_IDNA_VARIANT_UTS46,
            );
            if ($ascii === false || $ascii === '') {
                return null;
            }
            $hostRaw = $ascii;
        }

        return strtolower($hostRaw);
    }

    private function classifyIp(string $ip): ?SsrfDenyReason
    {
        $ip = $this->normalizeMappedIpv4($ip);
        $isV4 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
        $isV6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;

        foreach ($this->additionalDenyCidrs as $cidr) {
            if (($isV4 && str_contains($cidr, '.') && $this->ipv4InCidr($ip, $cidr))
                || ($isV6 && str_contains($cidr, ':') && $this->ipv6InCidr($ip, $cidr))) {
                return SsrfDenyReason::Reserved;
            }
        }

        if ($isV4) {
            foreach (self::DENY_CIDRS_V4 as $cidr) {
                if ($this->ipv4InCidr($ip, $cidr)) {
                    return $this->cidrReason($cidr);
                }
            }

            return null;
        }

        if ($isV6) {
            foreach (self::DENY_CIDRS_V6 as $cidr) {
                if ($this->ipv6InCidr($ip, $cidr)) {
                    return $this->cidrReason($cidr);
                }
            }

            return null;
        }

        return SsrfDenyReason::InvalidHost;
    }

    /** IPv4-mapped IPv6（::ffff:x.y.z.w / hex form）を IPv4 へ。 */
    private function normalizeMappedIpv4(string $ip): string
    {
        if (preg_match('/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i', $ip, $m) === 1) {
            return $m[1];
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            $bin = inet_pton($ip);
            if ($bin !== false && strlen($bin) === 16
                && substr($bin, 0, 10) === str_repeat("\0", 10)
                && substr($bin, 10, 2) === "\xff\xff") {
                $tail = substr($bin, 12, 4);

                return sprintf('%d.%d.%d.%d', ord($tail[0]), ord($tail[1]), ord($tail[2]), ord($tail[3]));
            }
        }

        return $ip;
    }

    private function ipv4InCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bitsStr] = explode('/', $cidr, 2);
        $bits = (int) $bitsStr;
        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);
        if ($ipLong === false || $subnetLong === false) {
            return false;
        }
        if ($bits === 0) {
            return true;
        }
        $mask = -1 << (32 - $bits);

        return ($ipLong & $mask) === ($subnetLong & $mask);
    }

    private function ipv6InCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bitsStr] = explode('/', $cidr, 2);
        $bits = (int) $bitsStr;
        $ipBin = inet_pton($ip);
        $subnetBin = inet_pton($subnet);
        if ($ipBin === false || $subnetBin === false) {
            return false;
        }
        $bytes = intdiv($bits, 8);
        $remainder = $bits % 8;
        if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($subnetBin, 0, $bytes)) {
            return false;
        }
        if ($remainder === 0) {
            return true;
        }
        $maskByte = chr((0xFF << (8 - $remainder)) & 0xFF);

        return (substr($ipBin, $bytes, 1) & $maskByte) === (substr($subnetBin, $bytes, 1) & $maskByte);
    }

    private function cidrReason(string $cidr): SsrfDenyReason
    {
        return match (true) {
            str_starts_with($cidr, '127.') || $cidr === '::1/128' => SsrfDenyReason::Loopback,
            str_starts_with($cidr, '169.254.') || str_starts_with($cidr, 'fe80::') => SsrfDenyReason::LinkLocal,
            str_starts_with($cidr, '224.') || str_starts_with($cidr, 'ff00::') => SsrfDenyReason::Multicast,
            str_starts_with($cidr, '10.') || str_starts_with($cidr, '172.16.')
                || str_starts_with($cidr, '192.168.') || str_starts_with($cidr, '100.64.')
                || str_starts_with($cidr, 'fc00::') => SsrfDenyReason::PrivateRange,
            default => SsrfDenyReason::Reserved,
        };
    }
}
