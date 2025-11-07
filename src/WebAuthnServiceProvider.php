<?php

namespace r0073rr0r\WebAuthn;

use Illuminate\Support\ServiceProvider;
use Livewire\Livewire;
use r0073rr0r\WebAuthn\Livewire\WebAuthnLogin;
use r0073rr0r\WebAuthn\Livewire\WebAuthnRegister;

class WebAuthnServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/webauthn.php', 'webauthn');
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'webauthn');
        
        // Load translations - try lang/ first (Laravel 9+), fallback to resources/lang
        $langPath = is_dir(__DIR__.'/../lang') 
            ? __DIR__.'/../lang' 
            : __DIR__.'/../resources/lang';
        $this->loadTranslationsFrom($langPath, 'webauthn');

        Livewire::component('webauthn-register', WebAuthnRegister::class);
        Livewire::component('webauthn-login', WebAuthnLogin::class);

        // Use Laravel's langPath() method to get the correct path
        // In Laravel 9+ it returns lang/, in older versions it returns resources/lang
        $langPath = app()->langPath('vendor/webauthn');

        $this->publishes([
            __DIR__.'/../public' => public_path('vendor/webauthn'),
            __DIR__.'/../resources/views' => resource_path('views/vendor/webauthn'),
            __DIR__.'/../lang' => $langPath,
            __DIR__.'/../config/webauthn.php' => config_path('webauthn.php'),
            __DIR__.'/../database/migrations/' => database_path('migrations'),
        ], 'webauthn');
    }

    public function register(): void
    {

    }
}
