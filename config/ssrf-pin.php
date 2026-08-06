<?php

declare(strict_types=1);

return [
    // 許可するスキーム。
    'allowed_schemes' => ['http', 'https'],

    // 許可するポート。非標準ポート（内部サービス等）への到達を防ぐ。
    'allowed_ports' => [80, 443],

    // redirect 追従の最大 hop 数。
    'max_redirect_hops' => 5,

    // 応答 body の上限バイト数（既定 1 MiB）。超過は切り捨てず TransportError::BodyTooLarge で
    // 失敗させる。上限は curl の write callback 段階で効くので、巨大応答は読み切られない。
    'max_body_bytes' => 1_048_576,

    // アプリ拡張用の追加 deny CIDR（例: 自社内部レンジ）。
    'additional_deny_cidrs' => [],

    // true の場合、host が IP literal（例: http://93.184.216.34）の URL を一律拒否する。
    // 既定 false（public IP literal は許可）。raw-IP URL を嫌うアプリは true にする。
    'deny_ip_literals' => false,
];
