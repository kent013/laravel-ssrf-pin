<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Enums;

/**
 * pin 済み接続そのものは許可されたが、transport（curl）層で失敗した理由。
 * deny（SsrfDenyReason）とは区別する。
 */
enum TransportError: string
{
    case Timeout = 'timeout';
    case ConnectFailed = 'connect_failed';
    case TlsError = 'tls_error';
    case Unknown = 'unknown';
}
