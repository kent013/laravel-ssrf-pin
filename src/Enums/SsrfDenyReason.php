<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Enums;

/**
 * 中立な SSRF deny 理由（セキュリティのドメインに閉じる）。
 *
 * アプリ固有の結果語彙（例: 到達性分類）はここに持ち込まない。各アプリが本 enum を
 * `match` で自プロダクトの reason へ写像する（密結合回避）。
 */
enum SsrfDenyReason: string
{
    case Loopback = 'loopback';
    case PrivateRange = 'private_range';
    case LinkLocal = 'link_local';
    case Multicast = 'multicast';
    case Reserved = 'reserved';
    /**
     * v0.4: 完全区間分類で「公開到達可能」と判定できなかった（= 既定拒否）。
     * 古典的な区分（loopback / private / link-local / multicast / reserved）に
     * 当てはまらない非到達区間と、分類表に当たらなかった表記がここに落ちる。
     */
    case NotGloballyReachable = 'not_globally_reachable';
    case DisallowedPort = 'disallowed_port';
    case CredentialInUrl = 'credential_in_url';
    case IpLiteralNotAllowed = 'ip_literal_not_allowed';
    case SchemeNotAllowed = 'scheme_not_allowed';
    case SchemeDowngrade = 'scheme_downgrade';
    case InvalidHost = 'invalid_host';
    case DnsResolutionFailed = 'dns_resolution_failed';
    case TooManyRedirects = 'too_many_redirects';
    case CurlHandlerUnavailable = 'curl_handler_unavailable';
}
