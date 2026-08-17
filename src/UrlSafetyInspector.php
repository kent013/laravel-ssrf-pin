<?php

declare(strict_types=1);

namespace Kent013\SsrfPin;

use Kent013\SsrfPin\Contracts\DnsResolverInterface;
use Kent013\SsrfPin\Dtos\UrlSafetyDecision;
use Kent013\SsrfPin\Enums\Reachability;
use Kent013\SsrfPin\Enums\SsrfDenyReason;
use Kent013\SsrfPin\Ip\IpClassificationTable;

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
 *
 * v0.4: IP の判定は**列挙型の拒否リストではなく完全区間分類**である
 * （{@see IpClassificationTable}）。**「公開到達可能」と分類できた区間だけを許可**し、
 * それ以外（非到達区間・非正準表記・表に当たらない値）はすべて拒否に倒す。
 */
final class UrlSafetyInspector
{
    private readonly IpClassificationTable $classificationTable;

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
        private readonly bool $denyIpLiterals = false,
        ?IpClassificationTable $classificationTable = null,
    ) {
        $this->classificationTable = $classificationTable ?? IpClassificationTable::default();
    }

    /** 判定に使っている分類表の版（IANA Special-Purpose Address Registry の発行日）。 */
    public function classificationRegistryVersion(): string
    {
        return $this->classificationTable->registryVersion();
    }

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
            if ($this->denyIpLiterals) {
                return UrlSafetyDecision::deny(SsrfDenyReason::IpLiteralNotAllowed, $host, [$host]);
            }
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

    /**
     * 許可なら null、拒否ならその理由を返す。
     *
     * **一致しなければ Public、ではない。** 分類表がその IP を「公開到達可能」と
     * 明示した場合だけ null（許可）を返し、それ以外はすべて拒否に倒す。
     * 判定経路は `inet_pton` のバイナリ比較だけで、IP の文字列比較を使わない。
     */
    private function classifyIp(string $ip): ?SsrfDenyReason
    {
        $ip = $this->normalizeMappedIpv4($ip);

        // アプリが足した追加 deny（CIDR 表記の入力なので文字列を解釈する経路。
        // 既定は空で、判定の本体はこの下の完全区間分類である）。
        $isV4 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
        $isV6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        foreach ($this->additionalDenyCidrs as $cidr) {
            if (($isV4 && str_contains($cidr, '.') && $this->ipv4InCidr($ip, $cidr))
                || ($isV6 && str_contains($cidr, ':') && $this->ipv6InCidr($ip, $cidr))) {
                return SsrfDenyReason::Reserved;
            }
        }

        $interval = $this->classificationTable->intervalFor($ip);
        if ($interval === null) {
            // 分類表が壊れている / 正準な IP 表記でない。既定拒否に倒す。
            return SsrfDenyReason::NotGloballyReachable;
        }

        return match ($interval->reachability()) {
            Reachability::PublicUnicast => null,
            Reachability::NotGloballyReachable => $interval->denyReason ?? SsrfDenyReason::NotGloballyReachable,
            Reachability::Unclassified => SsrfDenyReason::NotGloballyReachable,
        };
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
}
