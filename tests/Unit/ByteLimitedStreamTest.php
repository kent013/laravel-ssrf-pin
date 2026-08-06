<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Utils;
use Kent013\SsrfPin\Transport\ByteLimitedStream;

/**
 * 受入契約 2（応答 body の上限）の中核。
 *
 * 「読み切ってから測る」のでは防御にならないため、上限判定は **write（= curl の
 * CURLOPT_WRITEFUNCTION）段階**で効かなければならない。curl は write callback が
 * 渡されたバイト数と異なる値を返すと転送を即座に中断する（CURLE_WRITE_ERROR）。
 * ここではその「短い戻り値」と「バッファが上限を超えて育たないこと」を直接検証する。
 */
it('accepts writes up to the limit and buffers them verbatim', function () {
    $stream = new ByteLimitedStream(Utils::streamFor(''), 10);

    expect($stream->write('12345'))->toBe(5)
        ->and($stream->write('67890'))->toBe(5)
        ->and($stream->hasExceededLimit())->toBeFalse()
        ->and($stream->writtenBytes())->toBe(10)
        ->and((string) $stream)->toBe('1234567890');
});

it('aborts the transfer with a short write when a chunk crosses the limit', function () {
    $stream = new ByteLimitedStream(Utils::streamFor(''), 10);

    // 上限を跨ぐ chunk。curl は「渡した長さと違う値」を受け取って転送を中断する。
    $written = $stream->write('123456789012345');

    expect($written)->toBeLessThan(15)
        ->and($stream->hasExceededLimit())->toBeTrue()
        ->and($stream->writtenBytes())->toBeLessThanOrEqual(10);
});

it('never lets the buffer grow past the limit even under repeated writes', function () {
    $stream = new ByteLimitedStream(Utils::streamFor(''), 8);

    for ($i = 0; $i < 100; $i++) {
        $stream->write(str_repeat('x', 1024));
    }

    expect($stream->hasExceededLimit())->toBeTrue()
        ->and($stream->writtenBytes())->toBeLessThanOrEqual(8)
        ->and(strlen((string) $stream))->toBeLessThanOrEqual(8);
});

it('keeps rejecting once the limit has been exceeded', function () {
    $stream = new ByteLimitedStream(Utils::streamFor(''), 4);
    $stream->write('abcdef');

    expect($stream->write('g'))->toBe(0)
        ->and($stream->hasExceededLimit())->toBeTrue();
});

it('treats a zero-length write as a no-op success (curl may pass empty chunks)', function () {
    $stream = new ByteLimitedStream(Utils::streamFor(''), 4);

    expect($stream->write(''))->toBe(0)
        ->and($stream->hasExceededLimit())->toBeFalse();
});

it('delegates the remaining StreamInterface surface to the inner stream', function () {
    $stream = new ByteLimitedStream(Utils::streamFor(''), 16);
    $stream->write('hello');

    expect($stream->isSeekable())->toBeTrue()
        ->and($stream->isWritable())->toBeTrue()
        ->and($stream->isReadable())->toBeTrue()
        ->and($stream->getSize())->toBe(5)
        ->and($stream->tell())->toBe(5)
        ->and($stream->eof())->toBeFalse();

    $stream->rewind();
    expect($stream->read(5))->toBe('hello')
        ->and($stream->getMetadata('seekable'))->toBeTrue();

    $stream->seek(0);
    expect($stream->getContents())->toBe('hello')
        ->and($stream->detach())->not->toBeNull();
});
