# Laravel WebAuthn Livewire Components

[![Packagist Version](https://img.shields.io/packagist/v/r0073rr0r/laravel-webauthn)](https://packagist.org/packages/r0073rr0r/laravel-webauthn)
[![Total Downloads](https://img.shields.io/packagist/dt/r0073rr0r/laravel-webauthn)](https://packagist.org/packages/r0073rr0r/laravel-webauthn)
[![Monthly Downloads](https://img.shields.io/packagist/dm/r0073rr0r/laravel-webauthn)](https://packagist.org/packages/r0073rr0r/laravel-webauthn)
[![PHP Version](https://img.shields.io/packagist/php-v/r0073rr0r/laravel-webauthn)](https://packagist.org/packages/r0073rr0r/laravel-webauthn)
[![License](https://img.shields.io/packagist/l/r0073rr0r/laravel-webauthn)](https://packagist.org/packages/r0073rr0r/laravel-webauthn)
[![GitHub Stars](https://img.shields.io/github/stars/r0073rr0r/laravel-webauthn?style=social)](https://github.com/r0073rr0r/laravel-webauthn/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/r0073rr0r/laravel-webauthn)](https://github.com/r0073rr0r/laravel-webauthn/issues)
[![GitHub Forks](https://img.shields.io/github/forks/r0073rr0r/laravel-webauthn?style=social)](https://github.com/r0073rr0r/laravel-webauthn/network)

Laravel package with Livewire components for WebAuthn authentication (biometric authentication, USB security keys, passkeys).

## 📋 Requirements

- PHP 8.2+
- Laravel 12.x
- Livewire 3.x
- Jestream 5.x
- OpenSSL extension for PHP
- Composer packages:
    - spomky-labs/base64url ^2.0
    - spomky-labs/cbor-php ^3.1
    - web-auth/webauthn-framework ^5.2

## 📦 Installation

Install the package via Composer:

```bash
composer require r0073rr0r/laravel-webauthn
```

Publish views and config files:

```bash
php artisan vendor:publish --provider="r0073rr0r\WebAuthn\WebAuthnServiceProvider"
```

Publish all package resources (views, translations, and public assets) with a single command:
```bash
php artisan vendor:publish --tag=webauthn
```

Migrate database tables:

```bash
php artisan migrate
```

## ⚙️ Setup

After publishing the assets, include the WebAuthn JavaScript file in your layout (e.g., in `resources/views/layouts/app.blade.php` & `resources/views/layouts/guest.blade.php` or wherever you have your main layout):
```bladehtml
<script src="{{ asset('vendor/webauthn/webauthn/webauthn.js') }}"></script>
```

This script is required for the WebAuthn components to work properly.

## 🚀 Usage

### Registration (WebAuthnRegister)

Add the component to your Blade view (_I added it in `resources/views/profile/show.blade.php`_):
 ```bladehtml
 <livewire:web-authn-register />
 ```

This component allows users to register their WebAuthn device (fingerprint, Face ID, USB security key, etc.).

### Login (WebAuthnLogin)

Add the component to your Blade view (_I added it in `resources/views/auth/login.blade.php` after login form_):

 ```bladehtml
 <livewire:web-authn-login />
 ```

This component allows users to log in using their previously registered WebAuthn device.

## 🎨 Customization

You can customize the view files after publishing them:

- `resources/views/vendor/laravel-webauthn/livewire/web-authn-register.blade.php`
- `resources/views/vendor/laravel-webauthn/livewire/web-authn-login.blade.php`

## 🔒 Security

WebAuthn is a modern standard for secure passwordless authentication. This package uses browser native WebAuthn APIs for maximum security.

## 📝 License

MIT License

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.