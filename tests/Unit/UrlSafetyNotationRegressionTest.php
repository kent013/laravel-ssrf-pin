<?php

declare(strict_types=1);

use Kent013\SsrfPin\Enums\SsrfDenyReason;
use Kent013\SsrfPin\Ip\IpClassificationTable;
use Kent013\SsrfPin\Testing\FakeDnsResolver;
use Kent013\SsrfPin\UrlSafetyInspector;

/**
 * v0.4: 表記の揺れごとの回帰テスト（完了条件 3）と、完全区間分類への反転で
 * 新たに塞がった範囲の pin（0.2 の列挙型 deny では素通りしていた）。
 */
function notationInspector(): UrlSafetyInspector
{
    return new UrlSafetyInspector(new FakeDnsResolver);
}

it('denies the task metadata endpoints in every notation', function (string $url) {
    expect(notationInspector()->inspect($url)->allowed)->toBeFalse("expected deny for {$url}");
})->with([
    'imds v4' => 'http://169.254.169.254/latest/meta-data/',
    'ecs task role' => 'http://169.254.170.2/v2/credentials',
    'ipv4-mapped dotted' => 'http://[::ffff:169.254.169.254]/',
    'ipv4-mapped hex' => 'http://[::ffff:a9fe:a9fe]/',
    'hex literal' => 'http://0xA9FEA9FE/',
    'decimal literal' => 'http://2852039166/',
    'octal dotted' => 'http://0251.0376.0251.0376/',
    'ipv4-mapped loopback' => 'http://[::ffff:127.0.0.1]/',
]);

it('denies the ranges the enumerated 0.2 deny list let through', function (string $url, SsrfDenyReason $reason) {
    $decision = notationInspector()->inspect($url);

    expect($decision->allowed)->toBeFalse("expected deny for {$url}")
        ->and($decision->reason)->toBe($reason, "for {$url}");
})->with([
    'TEST-NET-1' => ['http://192.0.2.1/', SsrfDenyReason::NotGloballyReachable],
    'TEST-NET-2' => ['http://198.51.100.7/', SsrfDenyReason::NotGloballyReachable],
    'TEST-NET-3' => ['http://203.0.113.5/', SsrfDenyReason::NotGloballyReachable],
    '6to4 relay anycast' => ['http://192.88.99.1/', SsrfDenyReason::NotGloballyReachable],
    'IPv6 documentation' => ['http://[2001:db8::1]/', SsrfDenyReason::NotGloballyReachable],
    'IPv6 documentation 3fff' => ['http://[3fff::1]/', SsrfDenyReason::NotGloballyReachable],
    'IPv6 6to4' => ['http://[2002::1]/', SsrfDenyReason::NotGloballyReachable],
    'SRv6 SIDs' => ['http://[5f00::1]/', SsrfDenyReason::NotGloballyReachable],
]);

it('keeps the classic categories on the ranges 0.2 already denied', function (string $url, SsrfDenyReason $reason) {
    expect(notationInspector()->inspect($url)->reason)->toBe($reason, "for {$url}");
})->with([
    'this network' => ['http://0.0.0.0/', SsrfDenyReason::Reserved],
    'loopback' => ['http://127.0.0.1/', SsrfDenyReason::Loopback],
    'private 10/8' => ['http://10.0.0.1/', SsrfDenyReason::PrivateRange],
    'private 172.16/12' => ['http://172.16.0.0/', SsrfDenyReason::PrivateRange],
    'private 192.168/16' => ['http://192.168.1.1/', SsrfDenyReason::PrivateRange],
    'link local' => ['http://169.254.1.1/', SsrfDenyReason::LinkLocal],
    'multicast' => ['http://224.0.0.1/', SsrfDenyReason::Multicast],
    'reserved 240/4' => ['http://240.0.0.1/', SsrfDenyReason::Reserved],
    'limited broadcast' => ['http://255.255.255.255/', SsrfDenyReason::Reserved],
    'benchmarking' => ['http://198.18.0.1/', SsrfDenyReason::Reserved],
    'ietf protocol assignments' => ['http://192.0.0.1/', SsrfDenyReason::Reserved],
    'ipv6 unspecified' => ['http://[::]/', SsrfDenyReason::Reserved],
    'ipv6 loopback' => ['http://[::1]/', SsrfDenyReason::Loopback],
    'ipv6 ULA' => ['http://[fc00::1]/', SsrfDenyReason::PrivateRange],
    'ipv6 link local' => ['http://[fe80::1]/', SsrfDenyReason::LinkLocal],
    'ipv6 multicast' => ['http://[ff02::1]/', SsrfDenyReason::Multicast],
    'ipv6 NAT64' => ['http://[64:ff9b::1]/', SsrfDenyReason::Reserved],
    'ipv6 discard-only' => ['http://[100::1]/', SsrfDenyReason::Reserved],
    'ipv6 ietf protocol assignments' => ['http://[2001:1::1]/', SsrfDenyReason::Reserved],
    // 0.2 も拒否していた範囲（ECS のタスクメタデータ宛先を含む）。反転で緩まないことの pin。
    'CGNAT' => ['http://100.64.0.1/', SsrfDenyReason::PrivateRange],
    'ECS task role endpoint' => ['http://169.254.170.2/', SsrfDenyReason::LinkLocal],
    'ECS IPv6 task metadata' => ['http://[fd00:ec2::254]/', SsrfDenyReason::PrivateRange],
]);

it('allows addresses the table classifies as globally reachable', function (string $url) {
    expect(notationInspector()->inspect($url)->allowed)->toBeTrue("expected allow for {$url}");
})->with([
    'public v4' => 'http://93.184.216.34/',
    'public v6' => 'http://[2606:2800:220:1:248:1893:25c8:1946]/',
    'just above CGNAT' => 'http://100.128.0.0/',
    'just below 172.16/12' => 'http://172.15.255.255/',
    'just above 172.16/12' => 'http://172.32.0.0/',
    'just below TEST-NET-1' => 'http://192.0.1.255/',
    'just above TEST-NET-1' => 'http://192.0.3.0/',
    'just below TEST-NET-3' => 'http://203.0.112.255/',
    'just above TEST-NET-3' => 'http://203.0.114.0/',
    'just below 2001:db8::/32' => 'http://[2001:db7:ffff:ffff:ffff:ffff:ffff:ffff]/',
    'just above 2001:db8::/32' => 'http://[2001:db9::]/',
]);

it('denies a host whose DNS answer is not globally reachable even if some answers are public', function () {
    $inspector = new UrlSafetyInspector(new FakeDnsResolver(['mix.test' => ['93.184.216.34', '192.0.2.1']]));

    $decision = $inspector->inspect('http://mix.test/');

    expect($decision->allowed)->toBeFalse()
        ->and($decision->reason)->toBe(SsrfDenyReason::NotGloballyReachable);
});

it('exposes the classification registry version it judged with', function () {
    expect(notationInspector()->classificationRegistryVersion())
        ->toBe(IpClassificationTable::default()->registryVersion());
});

it('does not use string comparison anywhere on the IP judgement path', function () {
    // 完了条件 3: 判定は inet_pton のバイナリ比較のみ。IP の文字列を
    // 前方一致・部分一致で切り分ける実装が判定経路へ戻ってきたら落とす。
    $forbidden = ['str_starts_with', 'str_ends_with', 'strpos', 'stripos', 'substr_count'];

    $tableSource = file_get_contents(dirname(__DIR__, 2).'/src/Ip/IpClassificationTable.php');
    $intervalSource = file_get_contents(dirname(__DIR__, 2).'/src/Ip/IpClassificationInterval.php');
    foreach ($forbidden as $needle) {
        expect($tableSource)->not->toContain($needle.'(');
        expect($intervalSource)->not->toContain($needle.'(');
    }

    // classifyIp 本体（追加 deny CIDR の解釈を除く）にも文字列比較を置かない。
    $method = new ReflectionMethod(UrlSafetyInspector::class, 'classifyIp');
    $lines = file((string) $method->getFileName());
    $body = implode('', array_slice(
        (array) $lines,
        $method->getStartLine() - 1,
        $method->getEndLine() - $method->getStartLine() + 1,
    ));
    foreach ($forbidden as $needle) {
        expect($body)->not->toContain($needle.'(');
    }
    // 残る str_contains は追加 deny CIDR（アプリが渡す CIDR 文字列）の族判定だけで、
    // IP 側の文字列は切らない。
    expect(substr_count($body, 'str_contains('))->toBe(2);
    expect($body)->toContain('str_contains($cidr,');
});
