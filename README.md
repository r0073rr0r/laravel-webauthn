# Laravel – Jetstream Livewire WebAuthn Components

[![Packagist Version](https://img.shields.io/packagist/v/r0073rr0r/laravel-webauthn)](https://packagist.org/packages/r0073rr0r/laravel-webauthn)
[![Total Downloads](https://img.shields.io/packagist/dt/r0073rr0r/laravel-webauthn)](https://packagist.org/packages/r0073rr0r/laravel-webauthn)
[![Monthly Downloads](https://img.shields.io/packagist/dm/r0073rr0r/laravel-webauthn)](https://packagist.org/packages/r0073rr0r/laravel-webauthn)
[![PHP Version](https://img.shields.io/packagist/php-v/r0073rr0r/laravel-webauthn)](https://packagist.org/packages/r0073rr0r/laravel-webauthn)
[![License](https://img.shields.io/packagist/l/r0073rr0r/laravel-webauthn)](https://packagist.org/packages/r0073rr0r/laravel-webauthn)
[![GitHub Stars](https://img.shields.io/github/stars/r0073rr0r/laravel-webauthn?style=social)](https://github.com/r0073rr0r/laravel-webauthn/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/r0073rr0r/laravel-webauthn)](https://github.com/r0073rr0r/laravel-webauthn/issues)
[![GitHub Forks](https://img.shields.io/github/forks/r0073rr0r/laravel-webauthn?style=social)](https://github.com/r0073rr0r/laravel-webauthn/network)
[![Tests](https://github.com/r0073rr0r/laravel-webauthn/actions/workflows/tests.yml/badge.svg)](https://github.com/r0073rr0r/laravel-webauthn/actions/workflows/tests.yml)
[![CodeQL](https://github.com/r0073rr0r/laravel-webauthn/workflows/CodeQL/badge.svg)](https://github.com/r0073rr0r/laravel-webauthn/actions/workflows/codeql.yml)
[![PHP Composer](https://github.com/r0073rr0r/laravel-webauthn/workflows/PHP%20Composer/badge.svg)](https://github.com/r0073rr0r/laravel-webauthn/actions/workflows/codeql.yml)

A **Laravel** package that integrates seamlessly with **Jetstream** and **Livewire** to provide **WebAuthn** authentication — including support for biometric login, USB security keys, and passkeys.

## 📑 Table of Contents

- [Requirements](#-requirements)
- [Installation](#-installation)
- [Setup](#️-setup)
- [Usage](#-usage)
  - [Registration (WebAuthnRegister)](#registration-webauthnregister)
  - [Login (WebAuthnLogin)](#login-webauthnlogin)
- [Customization](#-customization)
- [Security](#-security)
- [License](#-license)
- [Contributing](#-contributing)

## 📋 Requirements

- **PHP 8.2+**
- **Laravel 12.x**
- **Livewire 3.x**
- **Jestream 5.x**
- **OpenSSL** extension for PHP
- **_Composer packages_**:
    - **spomky-labs/base64url ^2.0**
    - **spomky-labs/cbor-php ^3.1**
    - **web-auth/webauthn-framework ^5.2**

## 📦 Installation

Install the package via Composer:

```bash
composer require r0073rr0r/laravel-webauthn
```
If you encounter dependency errors, run:
```bash
composer require r0073rr0r/laravel-webauthn -W 
```
> **Note:** The package [`spomky-labs/cbor-php`](https://github.com/Spomky-Labs/cbor-php) depends on [`brick/math`](https://github.com/brick/math) `^0.13`.

Publish views and config files:

```bash
php artisan vendor:publish --provider="r0073rr0r\WebAuthn\WebAuthnServiceProvider"
```

Publish all package resources (views, translations, and public assets) with a single command:
```bash
php artisan vendor:publish --tag=webauthn
```

This will also copy the translation files to your `lang/vendor/webauthn` directory, where you can customize them.

> **Troubleshooting:** If you see translation keys instead of translated text (e.g., `webauthn::webauthn.add_passkey`):
> 
> 1. **Clear all caches:**
>    ```bash
>    php artisan config:clear
>    php artisan cache:clear
>    php artisan view:clear
>    composer dump-autoload
>    ```


Migrate database tables:

```bash
php artisan migrate
```

> **Note:** The migration is safe to run even if the `webauthn_keys` table already exists. It will check if the table exists before creating it, and will add a unique constraint on `credentialId` if it doesn't already exist.

<a href="https://asciinema.org/a/Bn7vl6s5sqh3NfZk5nFI9iPBc?t=7" target="_blank">
  <img src="https://asciinema.org/a/Bn7vl6s5sqh3NfZk5nFI9iPBc.svg" alt="asciicast installation of package">
</a>

## ⚙️ Setup

After publishing the assets, include the WebAuthn JavaScript file in your layout (e.g., in `resources/views/layouts/app.blade.php` & `resources/views/layouts/guest.blade.php` or wherever you have your main layout):
```bladehtml
<script src="{{ asset('vendor/webauthn/webauthn/webauthn.js') }}"></script>
```

This script is required for the WebAuthn components to work properly.

## 🚀 Usage

### Registration (WebAuthnRegister)

Add the component to your Blade view (_I added it in `resources/views/profile/show.blade.php`_):

<a href="https://cloud.dbase.in.rs/s/sjq5JC735gcLxKE?dir=/&editing=false&openfile=true" target="_blank">
  <img src="https://cloud.dbase.in.rs/apps/files_sharing/publicpreview/sjq5JC735gcLxKE?file=/&fileId=996296&x=1920&y=1080&a=true&etag=3b5490f73173d4da7bb3cc915fc9ce6f" alt="Register">
</a>

```bladehtml
 <livewire:webauthn-register />
 ```

This component allows users to register their WebAuthn device (fingerprint, Face ID, USB security key, etc.).

### Login (WebAuthnLogin)

Add the component to your Blade view (_I added it in `resources/views/auth/login.blade.php` after login form_):

<a href="https://cloud.dbase.in.rs/s/TJEw7fZjbo2Ej6e?dir=/&editing=false&openfile=true" target="_blank">
<img src="https://cloud.dbase.in.rs/apps/files_sharing/publicpreview/TJEw7fZjbo2Ej6e?file=/&fileId=996289&x=1920&y=1080&a=true&etag=2d385d71d5ac4988489c39ad0e905089" alt="Login">
</a>

```bladehtml
 <livewire:webauthn-login />
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