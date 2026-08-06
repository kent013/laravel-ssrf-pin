<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Transport;

use Psr\Http\Message\StreamInterface;
use Webmozart\Assert\Assert;

/**
 * 書き込み総量に上限を課す PSR-7 stream decorator（応答 body の DoS 面を閉じる）。
 *
 * 使い方は Guzzle の `sink` オプション。Guzzle の curl handler は
 * `CURLOPT_WRITEFUNCTION` から `$sink->write($chunk)` を呼び、その戻り値を
 * そのまま libcurl へ返す。libcurl は **渡した長さと異なる戻り値を書き込みエラーと見なし
 * 転送をその場で中断する**（`CURLE_WRITE_ERROR`）。したがって上限判定は
 * 「全部読んでから strlen で測る」のではなく **chunk が届いた時点**で効き、
 * 上限超過の応答はネットワークから読み切られることも、メモリに載ることもない。
 *
 * 上限を跨いだ chunk は 1 バイトも書き込まない（切り詰めた body を握らせないため。
 * 呼び出し側は `hasExceededLimit()` を見て `TransportError::BodyTooLarge` を返す）。
 *
 * 注意: 内側 stream に届くのは curl が復号したあとのバイト列である（Guzzle 既定の
 * `decode_content` により gzip 等は透過的に展開される）。つまり上限は
 * **展開後**のバイト数に掛かるので、圧縮爆弾も同じ上限で止まる。
 */
final class ByteLimitedStream implements StreamInterface
{
    private int $written = 0;

    private bool $exceeded = false;

    /**
     * @param  StreamInterface  $stream  実バッファ（通常 `php://temp`）。
     * @param  int  $maxBytes  書き込みを許す総バイト数（0 以上）。
     */
    public function __construct(
        private readonly StreamInterface $stream,
        private readonly int $maxBytes,
    ) {
        Assert::greaterThanEq($maxBytes, 0);
    }

    /** 上限を超える書き込みが発生したか（= 転送を中断させたか）。 */
    public function hasExceededLimit(): bool
    {
        return $this->exceeded;
    }

    /** 実際にバッファへ書き込んだバイト数（常に `$maxBytes` 以下）。 */
    public function writtenBytes(): int
    {
        return $this->written;
    }

    /**
     * @param  string  $string
     */
    public function write($string): int
    {
        $length = strlen($string);
        if ($length === 0) {
            return 0;
        }

        if ($this->exceeded || $this->written + $length > $this->maxBytes) {
            // 短い戻り値（0）で libcurl に書き込みエラーを通知し、転送を中断させる。
            // 部分書き込みはしない（切り詰められた body を成功として扱わせない）。
            $this->exceeded = true;

            return 0;
        }

        $written = $this->stream->write($string);
        $this->written += $written;

        return $written;
    }

    public function __toString(): string
    {
        if ($this->stream->isSeekable()) {
            $this->stream->rewind();
        }

        return $this->stream->getContents();
    }

    public function close(): void
    {
        $this->stream->close();
    }

    public function detach()
    {
        return $this->stream->detach();
    }

    public function getSize(): ?int
    {
        return $this->stream->getSize();
    }

    public function tell(): int
    {
        return $this->stream->tell();
    }

    public function eof(): bool
    {
        return $this->stream->eof();
    }

    public function isSeekable(): bool
    {
        return $this->stream->isSeekable();
    }

    /**
     * @param  int  $offset
     * @param  int  $whence
     */
    public function seek($offset, $whence = SEEK_SET): void
    {
        $this->stream->seek($offset, $whence);
    }

    public function rewind(): void
    {
        $this->stream->rewind();
    }

    public function isWritable(): bool
    {
        return $this->stream->isWritable();
    }

    public function isReadable(): bool
    {
        return $this->stream->isReadable();
    }

    /**
     * @param  int  $length
     */
    public function read($length): string
    {
        return $this->stream->read($length);
    }

    public function getContents(): string
    {
        return $this->stream->getContents();
    }

    /**
     * @param  string|null  $key
     */
    public function getMetadata($key = null): mixed
    {
        return $this->stream->getMetadata($key);
    }
}
