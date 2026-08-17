<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Ip;

use Kent013\SsrfPin\Enums\SsrfDenyReason;
use RuntimeException;
use Webmozart\Assert\Assert;

/**
 * IP 到達性の**完全区間分類表**（v0.4）。
 *
 * 分類は「アドレス空間の完全な分割」である。**一致しなければ Public、ではない。**
 * `resources/ip-classification.json` を単一ソースとして読み、load 時に次を検査する:
 *
 *   - 区間が昇順で、隣接区間に**隙間が無い**（IPv4 は 0.0.0.0〜255.255.255.255、
 *     IPv6 は ::〜ffff:…:ffff を覆う）
 *   - 区間が**重複しない**
 *   - 各区間に `globally_reachable` があり、false の区間は `deny_reason` を持つ
 *
 * どれかが崩れたら例外を投げる（**黙って fail-open させない**）。
 *
 * 探索は端点のバイナリ（`inet_pton`）二分探索で、**IP の文字列比較を一切使わない**。
 */
final class IpClassificationTable
{
    private static ?self $default = null;

    /**
     * @param  list<IpClassificationInterval>  $ipv4
     * @param  list<IpClassificationInterval>  $ipv6
     */
    private function __construct(
        private readonly array $ipv4,
        private readonly array $ipv6,
        private readonly string $registryVersion,
    ) {}

    /** 同梱の分類表（`resources/ip-classification.json`）。プロセス内で 1 度だけ読む。 */
    public static function default(): self
    {
        return self::$default ??= self::fromFile(self::defaultPath());
    }

    public static function defaultPath(): string
    {
        return dirname(__DIR__, 2).'/resources/ip-classification.json';
    }

    public static function fromFile(string $path): self
    {
        $raw = @file_get_contents($path);
        if ($raw === false) {
            throw new RuntimeException("ip classification table not readable: {$path}");
        }

        return self::fromJson($raw);
    }

    public static function fromJson(string $raw): self
    {
        /** @var mixed $decoded */
        $decoded = json_decode($raw, true);
        Assert::isArray($decoded, 'ip classification table must be a JSON object');
        Assert::keyExists($decoded, 'registry_version');
        Assert::stringNotEmpty($decoded['registry_version'], 'registry_version must be a non-empty string');
        Assert::keyExists($decoded, 'ipv4');
        Assert::keyExists($decoded, 'ipv6');
        Assert::isList($decoded['ipv4'], 'ipv4 must be a list of intervals');
        Assert::isList($decoded['ipv6'], 'ipv6 must be a list of intervals');

        $ipv4 = self::buildFamily($decoded['ipv4'], 4, '0.0.0.0', '255.255.255.255');
        $ipv6 = self::buildFamily($decoded['ipv6'], 16, '::', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');

        return new self($ipv4, $ipv6, $decoded['registry_version']);
    }

    public function registryVersion(): string
    {
        return $this->registryVersion;
    }

    /** @return list<IpClassificationInterval> */
    public function ipv4Intervals(): array
    {
        return $this->ipv4;
    }

    /** @return list<IpClassificationInterval> */
    public function ipv6Intervals(): array
    {
        return $this->ipv6;
    }

    /**
     * 正準表記の IP がどの区間に当たるかを返す。
     *
     * 分類表が全空間を覆っている限り、正準な IP に対して null は返らない。
     * null は「正準表記ではない」か「表が壊れている」を意味し、呼び出し側は拒否に倒す。
     */
    public function intervalFor(string $ip): ?IpClassificationInterval
    {
        $binary = @inet_pton($ip);
        if ($binary === false) {
            return null;
        }

        $intervals = match (strlen($binary)) {
            4 => $this->ipv4,
            16 => $this->ipv6,
            default => null,
        };
        if ($intervals === null) {
            return null;
        }

        $low = 0;
        $high = count($intervals) - 1;
        while ($low <= $high) {
            $mid = intdiv($low + $high, 2);
            $interval = $intervals[$mid];
            if (strcmp($binary, $interval->startBinary) < 0) {
                $high = $mid - 1;

                continue;
            }
            if (strcmp($binary, $interval->endBinary) > 0) {
                $low = $mid + 1;

                continue;
            }

            return $interval;
        }

        return null;
    }

    /**
     * @param  list<mixed>  $rows
     * @return list<IpClassificationInterval>
     */
    private static function buildFamily(array $rows, int $byteLength, string $spaceStart, string $spaceEnd): array
    {
        Assert::notEmpty($rows, 'ip classification family must not be empty');

        $intervals = [];
        $expectedStart = self::toBinary($spaceStart, $byteLength);

        foreach ($rows as $index => $row) {
            Assert::isArray($row, "interval #{$index} must be an object");
            Assert::keyExists($row, 'start');
            Assert::keyExists($row, 'end');
            Assert::keyExists($row, 'name');
            Assert::keyExists($row, 'globally_reachable', "interval #{$index} must declare globally_reachable");
            Assert::string($row['start']);
            Assert::string($row['end']);
            Assert::stringNotEmpty($row['name']);
            Assert::boolean($row['globally_reachable'], "interval #{$index} globally_reachable must be boolean");

            $start = self::toBinary($row['start'], $byteLength);
            $end = self::toBinary($row['end'], $byteLength);

            if (strcmp($start, $end) > 0) {
                throw new RuntimeException("interval #{$index} is inverted: {$row['start']} > {$row['end']}");
            }
            if ($start !== $expectedStart) {
                // 隙間 (start > expected) も重複 (start < expected) もここで落ちる。
                throw new RuntimeException(
                    "interval #{$index} breaks the partition at {$row['start']} (expected the address right after the previous interval)"
                );
            }

            $denyReason = null;
            if ($row['globally_reachable'] === false) {
                Assert::keyExists($row, 'deny_reason', "interval #{$index} must declare deny_reason when not globally reachable");
                Assert::stringNotEmpty($row['deny_reason'], "interval #{$index} deny_reason must be a non-empty string");
                $denyReason = SsrfDenyReason::tryFrom($row['deny_reason']);
                if ($denyReason === null) {
                    throw new RuntimeException("interval #{$index} has an unknown deny_reason: {$row['deny_reason']}");
                }
            } elseif (($row['deny_reason'] ?? null) !== null) {
                throw new RuntimeException("interval #{$index} is globally reachable but declares a deny_reason");
            }

            $intervals[] = new IpClassificationInterval(
                startBinary: $start,
                endBinary: $end,
                name: $row['name'],
                globallyReachable: $row['globally_reachable'],
                denyReason: $denyReason,
            );

            $expectedStart = self::increment($end);
        }

        $lastEnd = $intervals[count($intervals) - 1]->endBinary;
        if ($lastEnd !== self::toBinary($spaceEnd, $byteLength)) {
            throw new RuntimeException("ip classification family does not cover the address space up to {$spaceEnd}");
        }

        return $intervals;
    }

    private static function toBinary(string $ip, int $byteLength): string
    {
        $binary = @inet_pton($ip);
        if ($binary === false || strlen($binary) !== $byteLength) {
            throw new RuntimeException("invalid address for a {$byteLength}-byte family: {$ip}");
        }

        return $binary;
    }

    /**
     * バイナリ表現の +1。空間の最上位を超えたときは「後続なし」を表す番兵を返す
     * （どの実アドレスとも一致しないので、余分な区間があれば partition 検査で落ちる）。
     */
    private static function increment(string $binary): string
    {
        for ($i = strlen($binary) - 1; $i >= 0; $i--) {
            $byte = ord($binary[$i]);
            if ($byte !== 0xFF) {
                $binary[$i] = chr($byte + 1);

                return $binary;
            }
            $binary[$i] = "\x00";
        }

        return str_repeat("\xFF", strlen($binary)).'overflow';
    }
}
