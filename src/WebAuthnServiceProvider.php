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
        $this->loadTranslationsFrom(__DIR__.'/../lang', 'webauthn');

        Livewire::component('webauthn-register', WebAuthnRegister::class);
        Livewire::component('webauthn-login', WebAuthnLogin::class);

        $langPath = function_exists('lang_path') ? lang_path('vendor/webauthn') : base_path('lang/vendor/webauthn');

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
