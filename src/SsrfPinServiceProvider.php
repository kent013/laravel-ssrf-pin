<?php

declare(strict_types=1);

namespace Kent013\SsrfPin;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Kent013\SsrfPin\Contracts\DnsResolverInterface;
use Kent013\SsrfPin\Contracts\PinnedCurlTransportInterface;
use Kent013\SsrfPin\Dns\SystemDnsResolver;
use Kent013\SsrfPin\Transport\GuzzleCurlTransport;

final class SsrfPinServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/ssrf-pin.php', 'ssrf-pin');

        $this->app->bind(DnsResolverInterface::class, SystemDnsResolver::class);
        $this->app->bind(PinnedCurlTransportInterface::class, GuzzleCurlTransport::class);

        $this->app->singleton(UrlSafetyInspector::class, function (Application $app): UrlSafetyInspector {
            /** @var array{allowed_schemes?: list<string>, allowed_ports?: list<int>, additional_deny_cidrs?: list<string>} $config */
            $config = $app->make(ConfigRepository::class)->get('ssrf-pin', []);

            return new UrlSafetyInspector(
                $app->make(DnsResolverInterface::class),
                $config['allowed_schemes'] ?? ['http', 'https'],
                $config['allowed_ports'] ?? [80, 443],
                $config['additional_deny_cidrs'] ?? [],
            );
        });

        $this->app->singleton(PinnedHttpClient::class, function (Application $app): PinnedHttpClient {
            /** @var array{max_redirect_hops?: int} $config */
            $config = $app->make(ConfigRepository::class)->get('ssrf-pin', []);

            return new PinnedHttpClient(
                $app->make(UrlSafetyInspector::class),
                $app->make(PinnedCurlTransportInterface::class),
                $config['max_redirect_hops'] ?? 5,
            );
        });
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/ssrf-pin.php' => $this->app->configPath('ssrf-pin.php'),
            ], 'ssrf-pin-config');
        }
    }
}
