<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Transport;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Handler\CurlHandler;
use GuzzleHttp\HandlerStack;
use Kent013\SsrfPin\Contracts\PinnedCurlTransportInterface;
use Kent013\SsrfPin\Dtos\CurlResolveEntry;
use Kent013\SsrfPin\Dtos\Deadline;
use Kent013\SsrfPin\Dtos\PinnedFailure;
use Kent013\SsrfPin\Dtos\PinnedRequest;
use Kent013\SsrfPin\Dtos\PinnedResponse;
use Kent013\SsrfPin\Enums\SsrfDenyReason;
use Kent013\SsrfPin\Enums\TransportError;

/**
 * libcurl の CURLOPT_RESOLVE で pin する唯一の本番 transport。
 *
 * fail-secure 方針:
 *  - ext-curl 不在、または複数アドレス CURLOPT_RESOLVE 非対応の libcurl では isAvailable()=false。
 *  - Guzzle Client は**内部で CurlHandler を明示構築**して使う（stream handler への fallback で
 *    pin が黙殺される穴を構造的に排除）。外部から任意 Client を注入させない。
 */
final class GuzzleCurlTransport implements PinnedCurlTransportInterface
{
    /** 複数アドレス CURLOPT_RESOLVE が安定的に使える最小 libcurl（7.21.3+ で RESOLVE 導入、余裕を見て 7.40）。 */
    private const int MIN_LIBCURL_VERSION = 0x072800; // 7.40.0

    private readonly Client $client;

    private readonly bool $available;

    public function __construct()
    {
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

        try {
            $response = $this->client->request($request->method, $request->url, [
                'headers' => $request->headers,
                'connect_timeout' => min($request->connectTimeout, $remaining),
                'timeout' => $remaining,
                'allow_redirects' => false,
                'curl' => [CURLOPT_RESOLVE => [$entry->toCurlFormat()]],
            ]);
        } catch (ConnectException $e) {
            return new PinnedFailure($this->classifyConnectError($e), $request->url, 0);
        } catch (GuzzleException) {
            return new PinnedFailure(TransportError::Unknown, $request->url, 0);
        }

        /** @var array<string, list<string>> $headers */
        $headers = $response->getHeaders();

        return new PinnedResponse($response->getStatusCode(), $headers, $request->url, []);
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
