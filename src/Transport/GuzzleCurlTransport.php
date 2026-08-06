<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Transport;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Handler\CurlHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Utils;
use Kent013\SsrfPin\Contracts\PinnedCurlTransportInterface;
use Kent013\SsrfPin\Dtos\CurlResolveEntry;
use Kent013\SsrfPin\Dtos\Deadline;
use Kent013\SsrfPin\Dtos\PinnedFailure;
use Kent013\SsrfPin\Dtos\PinnedRequest;
use Kent013\SsrfPin\Dtos\PinnedResponse;
use Kent013\SsrfPin\Enums\SsrfDenyReason;
use Kent013\SsrfPin\Enums\TransportError;
use Webmozart\Assert\Assert;

/**
 * libcurl の CURLOPT_RESOLVE で pin する唯一の本番 transport。
 *
 * fail-secure 方針:
 *  - ext-curl 不在、または複数アドレス CURLOPT_RESOLVE 非対応の libcurl では isAvailable()=false。
 *  - Guzzle Client は**内部で CurlHandler を明示構築**して使う（stream handler への fallback で
 *    pin が黙殺される穴を構造的に排除）。外部から任意 Client を注入させない。
 *  - 応答 body は `ByteLimitedStream` を sink にして読む。上限超過は**切り詰めずに**
 *    `TransportError::BodyTooLarge` で失敗させる（巨大応答によるメモリ枯渇を防ぐ）。
 */
final class GuzzleCurlTransport implements PinnedCurlTransportInterface
{
    /** 応答 body の既定上限（1 MiB）。discovery / JWKS / token 応答には十分で、DoS 面は閉じる。 */
    public const int DEFAULT_MAX_BODY_BYTES = 1_048_576;

    /** 複数アドレス CURLOPT_RESOLVE が安定的に使える最小 libcurl（7.21.3+ で RESOLVE 導入、余裕を見て 7.40）。 */
    private const int MIN_LIBCURL_VERSION = 0x072800; // 7.40.0

    private readonly Client $client;

    private readonly bool $available;

    /**
     * @param  int  $maxBodyBytes  応答 body の上限バイト数（0 以上）。超過は BodyTooLarge。
     */
    public function __construct(private readonly int $maxBodyBytes = self::DEFAULT_MAX_BODY_BYTES)
    {
        Assert::greaterThanEq($maxBodyBytes, 0);

        $this->available = $this->detectAvailability();
        $this->client = new Client([
            'handler' => HandlerStack::create(new CurlHandler),
            'http_errors' => false,
            'allow_redirects' => false,
        ]);
    }

    public function isAvailable(): bool
    {
        return $this->available;
    }

    public function send(PinnedRequest $request, CurlResolveEntry $entry, Deadline $deadline): PinnedResponse|PinnedFailure
    {
        if (! $this->available) {
            return new PinnedFailure(SsrfDenyReason::CurlHandlerUnavailable, $request->url, 0);
        }

        $remaining = $deadline->remainingSeconds();
        if ($remaining <= 0.0) {
            return new PinnedFailure(TransportError::Timeout, $request->url, 0);
        }

        // 応答 body は上限つき sink に受ける。上限超過は write 段階（curl の write callback）で
        // 検出され転送はその場で中断される（読み切ってから測るのでは防御にならない）。
        $sink = new ByteLimitedStream(Utils::streamFor(''), $this->maxBodyBytes);

        $options = [
            'headers' => $this->buildHeaders($request),
            'connect_timeout' => min($request->connectTimeout, $remaining),
            'timeout' => $remaining,
            'allow_redirects' => false,
            'sink' => $sink,
            'curl' => [CURLOPT_RESOLVE => [$entry->toCurlFormat()]],
        ];
        if ($request->body !== null) {
            $options['body'] = $request->body;
        }

        try {
            $response = $this->client->request($request->method, $request->url, $options);
        } catch (ConnectException $e) {
            if ($sink->hasExceededLimit()) {
                return new PinnedFailure(TransportError::BodyTooLarge, $request->url, 0);
            }

            return new PinnedFailure($this->classifyConnectError($e), $request->url, 0);
        } catch (GuzzleException) {
            // 上限超過による中断は curl の書き込みエラー（CURLE_WRITE_ERROR）として現れる。
            if ($sink->hasExceededLimit()) {
                return new PinnedFailure(TransportError::BodyTooLarge, $request->url, 0);
            }

            return new PinnedFailure(TransportError::Unknown, $request->url, 0);
        }

        // 中断が例外化しない実装差分に備えた保険（切り詰めた body は絶対に成功として返さない）。
        if ($sink->hasExceededLimit()) {
            return new PinnedFailure(TransportError::BodyTooLarge, $request->url, 0);
        }

        /** @var array<string, list<string>> $headers */
        $headers = $response->getHeaders();

        return new PinnedResponse($response->getStatusCode(), $headers, $request->url, [], (string) $sink);
    }

    /**
     * `contentType` を Content-Type ヘッダに反映する（明示指定は headers の同名エントリより優先）。
     *
     * @return array<string, string>
     */
    private function buildHeaders(PinnedRequest $request): array
    {
        if ($request->contentType === null) {
            return $request->headers;
        }

        $headers = [];
        foreach ($request->headers as $name => $value) {
            if (strcasecmp($name, 'Content-Type') === 0) {
                continue;
            }
            $headers[$name] = $value;
        }
        $headers['Content-Type'] = $request->contentType;

        return $headers;
    }

    private function classifyConnectError(ConnectException $e): TransportError
    {
        $message = strtolower($e->getMessage());
        if (str_contains($message, 'timed out') || str_contains($message, 'timeout')) {
            return TransportError::Timeout;
        }
        if (str_contains($message, 'ssl') || str_contains($message, 'certificate')) {
            return TransportError::TlsError;
        }

        return TransportError::ConnectFailed;
    }

    private function detectAvailability(): bool
    {
        if (! extension_loaded('curl') || ! defined('CURLOPT_RESOLVE')) {
            return false;
        }
        $info = curl_version();
        if (! is_array($info) || ! isset($info['version_number']) || ! is_int($info['version_number'])) {
            return false;
        }

        return $info['version_number'] >= self::MIN_LIBCURL_VERSION;
    }
}
