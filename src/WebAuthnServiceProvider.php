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
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'webauthn');
        $this->loadTranslationsFrom(__DIR__.'/../resources/lang', 'webauthn');

        Livewire::component('webauthn-register', WebAuthnRegister::class);
        Livewire::component('webauthn-login', WebAuthnLogin::class);

        $this->publishes([
            __DIR__.'/../public' => public_path('vendor/webauthn'),
            __DIR__.'/../resources/views' => resource_path('views/vendor/webauthn'),
            __DIR__.'/../resources/lang' => resource_path('lang/vendor/webauthn'),
            __DIR__.'/../database/migrations/' => database_path('migrations'),
        ], 'webauthn');
    }

    public function register(): void
    {
        //
    }
}
