<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Dtos;

use Webmozart\Assert\Assert;

/**
 * `CURLOPT_RESOLVE` 用の `host:port:ip1,ip2,...` エントリ。
 *
 * transport の `send()` に必須引数として渡すことで、「検証済み IP に pin する」契約を
 * 型レベルで強制する（pin の迂回を構造的に不能化）。
 */
final readonly class CurlResolveEntry
{
    /** @param non-empty-list<string> $ips 検証済み IP 群 */
    public function __construct(
        public string $host,
        public int $port,
        public array $ips,
    ) {
        Assert::notEmpty($host);
    }

    /** libcurl の `CURLOPT_RESOLVE` 形式（`host:port:ip1,ip2`）。 */
    public function toCurlFormat(): string
    {
        return sprintf('%s:%d:%s', $this->host, $this->port, implode(',', $this->ips));
    }
}
