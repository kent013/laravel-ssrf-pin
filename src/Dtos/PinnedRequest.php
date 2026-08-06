<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Dtos;

/**
 * pin 済み fetch の入力。method 非依存（HEAD/GET/POST/任意）。
 *
 * v0.3: `$body` / `$contentType` を追加（既定値つきの末尾追加なので v0.2 の positional
 * 呼び出しはそのまま動く）。redirect 追従時は **2 hop 目以降に body を送らない**
 * （`PinnedHttpClient` が hop ごとに body を落とす。README「Redirects and bodies」）。
 */
final readonly class PinnedRequest
{
    /**
     * @param  array<string, string>  $headers
     * @param  string|null  $body  request body（例: `application/x-www-form-urlencoded` の POST）。GET/HEAD では null。
     * @param  string|null  $contentType  `$body` の Content-Type。指定時は `$headers` の同名エントリより優先される。
     */
    public function __construct(
        public string $method,
        public string $url,
        public array $headers = [],
        public float $connectTimeout = 2.0,
        public ?string $body = null,
        public ?string $contentType = null,
    ) {}

    /** URL だけ差し替えた複製（body/contentType は保持する）。 */
    public function withUrl(string $url): self
    {
        return new self($this->method, $url, $this->headers, $this->connectTimeout, $this->body, $this->contentType);
    }

    /**
     * URL を差し替え、body / contentType を落とした複製（redirect の 2 hop 目以降で使う）。
     * body を送らない以上 Content-Type / Content-Length ヘッダも意味を持たないので併せて取り除く。
     */
    public function withUrlWithoutBody(string $url): self
    {
        $headers = [];
        foreach ($this->headers as $name => $value) {
            if (strcasecmp($name, 'Content-Type') === 0 || strcasecmp($name, 'Content-Length') === 0) {
                continue;
            }
            $headers[$name] = $value;
        }

        return new self($this->method, $url, $headers, $this->connectTimeout);
    }
}
