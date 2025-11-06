<?php

namespace r0073rr0r\WebAuthn\Tests;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Livewire\LivewireServiceProvider;
use Orchestra\Testbench\TestCase as BaseTestCase;
use r0073rr0r\WebAuthn\WebAuthnServiceProvider;

abstract class TestCase extends BaseTestCase
{
    use RefreshDatabase;

    protected function getPackageProviders($app)
    {
        return [
            LivewireServiceProvider::class,
            WebAuthnServiceProvider::class,
        ];
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/database/migrations');
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
    }

    protected function getEnvironmentSetUp($app): void
    {
        $paths = $app['config']->get('view.paths', []);
        array_unshift($paths, __DIR__.'/resources/views');
        $app['config']->set('view.paths', $paths);
    }
}


