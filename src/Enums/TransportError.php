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
    /** 応答 body が transport の上限バイト数を超えた（切り詰めずに失敗させる。v0.3 で追加）。 */
    case BodyTooLarge = 'body_too_large';
    case Unknown = 'unknown';
}
