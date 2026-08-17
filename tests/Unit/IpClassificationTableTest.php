<?php

declare(strict_types=1);

use Kent013\SsrfPin\Enums\Reachability;
use Kent013\SsrfPin\Enums\SsrfDenyReason;
use Kent013\SsrfPin\Ip\IpClassificationTable;

/**
 * v0.4: 分類表が「アドレス空間の完全な分割」であることの pin。
 * 隙間・重複・globally_reachable 欠落のいずれか 1 つでも崩れたら失敗する。
 */
function classificationJson(array $overrides = []): string
{
    $base = [
        'registry_version' => '2025-10-09',
        'ipv4' => [
            ['start' => '0.0.0.0', 'end' => '255.255.255.255', 'name' => 'all', 'globally_reachable' => true, 'deny_reason' => null],
        ],
        'ipv6' => [
            ['start' => '::', 'end' => 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'name' => 'all', 'globally_reachable' => true, 'deny_reason' => null],
        ],
    ];

    return json_encode(array_replace($base, $overrides), JSON_THROW_ON_ERROR);
}

it('covers the whole IPv4 and IPv6 space with no gap and no overlap', function () {
    $table = IpClassificationTable::default();

    foreach ([
        ['intervals' => $table->ipv4Intervals(), 'first' => '0.0.0.0', 'last' => '255.255.255.255'],
        ['intervals' => $table->ipv6Intervals(), 'first' => '::', 'last' => 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'],
    ] as $family) {
        $intervals = $family['intervals'];
        expect($intervals)->not->toBeEmpty();
        expect($intervals[0]->startBinary)->toBe(inet_pton($family['first']));
        expect($intervals[count($intervals) - 1]->endBinary)->toBe(inet_pton($family['last']));

        // 隣接区間の間に穴も重なりも無い（end + 1 === 次の start）。
        for ($i = 1; $i < count($intervals); $i++) {
            $previousEnd = $intervals[$i - 1]->endBinary;
            $carry = 1;
            for ($b = strlen($previousEnd) - 1; $b >= 0 && $carry === 1; $b--) {
                $sum = ord($previousEnd[$b]) + $carry;
                $previousEnd[$b] = chr($sum & 0xFF);
                $carry = $sum > 0xFF ? 1 : 0;
            }
            expect($carry)->toBe(0, "interval #{$i} follows an interval that already reached the top of the space");
            expect($intervals[$i]->startBinary)->toBe($previousEnd, "interval #{$i} is not contiguous with its predecessor");
        }
    }
});

it('gives every interval a reachability verdict and a deny reason when not reachable', function () {
    $table = IpClassificationTable::default();

    foreach ([...$table->ipv4Intervals(), ...$table->ipv6Intervals()] as $interval) {
        if ($interval->globallyReachable) {
            expect($interval->reachability())->toBe(Reachability::PublicUnicast)
                ->and($interval->denyReason)->toBeNull();

            continue;
        }
        expect($interval->reachability())->toBe(Reachability::NotGloballyReachable)
            ->and($interval->denyReason)->toBeInstanceOf(SsrfDenyReason::class);
    }
});

it('pins the IANA registry version of the shipped table', function () {
    // 版が上がったときは、分類区間の見直しとセットで本テストを更新すること
    // （registry の更新は機械では検知できない = 四半期監査の対象）。
    expect(IpClassificationTable::default()->registryVersion())->toBe('2025-10-09');
});

it('rejects a table with a gap', function () {
    $json = classificationJson(['ipv4' => [
        ['start' => '0.0.0.0', 'end' => '9.255.255.255', 'name' => 'low', 'globally_reachable' => true, 'deny_reason' => null],
        ['start' => '11.0.0.0', 'end' => '255.255.255.255', 'name' => 'high', 'globally_reachable' => true, 'deny_reason' => null],
    ]]);

    expect(fn () => IpClassificationTable::fromJson($json))->toThrow(RuntimeException::class);
});

it('rejects a table with an overlap', function () {
    $json = classificationJson(['ipv4' => [
        ['start' => '0.0.0.0', 'end' => '10.255.255.255', 'name' => 'low', 'globally_reachable' => true, 'deny_reason' => null],
        ['start' => '10.0.0.0', 'end' => '255.255.255.255', 'name' => 'high', 'globally_reachable' => true, 'deny_reason' => null],
    ]]);

    expect(fn () => IpClassificationTable::fromJson($json))->toThrow(RuntimeException::class);
});

it('rejects a table that stops short of the top of the space', function () {
    $json = classificationJson(['ipv4' => [
        ['start' => '0.0.0.0', 'end' => '254.255.255.255', 'name' => 'most', 'globally_reachable' => true, 'deny_reason' => null],
    ]]);

    expect(fn () => IpClassificationTable::fromJson($json))->toThrow(RuntimeException::class);
});

it('rejects an interval without globally_reachable', function () {
    $json = classificationJson(['ipv4' => [
        ['start' => '0.0.0.0', 'end' => '255.255.255.255', 'name' => 'all', 'deny_reason' => null],
    ]]);

    expect(fn () => IpClassificationTable::fromJson($json))->toThrow(InvalidArgumentException::class);
});

it('rejects a non-reachable interval without a deny reason', function () {
    $json = classificationJson(['ipv4' => [
        ['start' => '0.0.0.0', 'end' => '255.255.255.255', 'name' => 'all', 'globally_reachable' => false, 'deny_reason' => null],
    ]]);

    expect(fn () => IpClassificationTable::fromJson($json))->toThrow(InvalidArgumentException::class);
});

it('rejects an unknown deny reason', function () {
    $json = classificationJson(['ipv4' => [
        ['start' => '0.0.0.0', 'end' => '255.255.255.255', 'name' => 'all', 'globally_reachable' => false, 'deny_reason' => 'no_such_reason'],
    ]]);

    expect(fn () => IpClassificationTable::fromJson($json))->toThrow(RuntimeException::class);
});

it('routes every interval endpoint through the binary search back to its own interval', function () {
    // 区間列の連続性だけでは、二分探索と端点の包含（両端を含む）が正しいことは言えない。
    // 全 50 区間の下端・上端を実際に検索し、同じ区間に戻ることと verdict / reason が
    // 表のとおりであることを 1 件ずつ確かめる。
    $table = IpClassificationTable::default();

    foreach ([...$table->ipv4Intervals(), ...$table->ipv6Intervals()] as $interval) {
        foreach ([$interval->startBinary, $interval->endBinary] as $binary) {
            $address = inet_ntop($binary);
            $found = $table->intervalFor((string) $address);

            expect($found)->not->toBeNull("no interval for {$address}");
            expect($found?->startBinary)->toBe($interval->startBinary, "wrong interval for {$address}");
            expect($found?->endBinary)->toBe($interval->endBinary, "wrong interval for {$address}");
            expect($found?->globallyReachable)->toBe($interval->globallyReachable, "wrong verdict for {$address}");
            expect($found?->denyReason)->toBe($interval->denyReason, "wrong deny reason for {$address}");
            expect($table->reachabilityOf($found))->toBe($interval->reachability(), "wrong reachability for {$address}");
        }
    }
});

it('treats an address outside every interval as Unclassified, not as allowed', function () {
    expect(IpClassificationTable::default()->reachabilityOf(null))->toBe(Reachability::Unclassified);
});

it('finds exactly one interval for canonical addresses and none for garbage', function () {
    $table = IpClassificationTable::default();

    expect($table->intervalFor('93.184.216.34')?->globallyReachable)->toBeTrue();
    expect($table->intervalFor('169.254.169.254')?->name)->toBe('link-local');
    expect($table->intervalFor('2606:2800:220:1:248:1893:25c8:1946')?->globallyReachable)->toBeTrue();
    expect($table->intervalFor('not-an-ip'))->toBeNull();
    expect($table->intervalFor('0xA9FEA9FE'))->toBeNull();
});
