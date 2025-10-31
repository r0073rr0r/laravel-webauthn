<?php

namespace r0073rr0r\WebAuthn;

use Illuminate\Support\ServiceProvider;
use Livewire\Livewire;

class WebAuthnServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        // Učitaj view-ove iz paketa
        $this->loadViewsFrom(__DIR__ . '/../resources/views', 'webauthn');

        // Registruj Livewire komponente
        Livewire::component('webauthn-register', \r0073rr0r\WebAuthn\Livewire\WebAuthnRegister::class);
        Livewire::component('webauthn-login', \r0073rr0r\WebAuthn\Livewire\WebAuthnLogin::class);

        // Objavi public fajlove (JS itd.)
        $this->publishes([
            __DIR__ . '/../public' => public_path('vendor/webauthn'),
        ], 'public');

        // Objavi view fajlove (ako korisnik želi da ih izmeni)
        $this->publishes([
            __DIR__ . '/../resources/views' => resource_path('views/vendor/webauthn'),
        ], 'views');
    }

    public function register(): void
    {
        //
    }
}
