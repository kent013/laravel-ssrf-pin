<?php

declare(strict_types=1);

return [
    // 許可するスキーム。
    'allowed_schemes' => ['http', 'https'],

    // 許可するポート。非標準ポート（内部サービス等）への到達を防ぐ。
    'allowed_ports' => [80, 443],

    // redirect 追従の最大 hop 数。
    'max_redirect_hops' => 5,

    // アプリ拡張用の追加 deny CIDR（例: 自社内部レンジ）。
    'additional_deny_cidrs' => [],

    // true の場合、host が IP literal（例: http://93.184.216.34）の URL を一律拒否する。
    // 既定 false（public IP literal は許可）。raw-IP URL を嫌うアプリは true にする。
    'deny_ip_literals' => false,
];
