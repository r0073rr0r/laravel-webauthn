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
- [Updating](#-updating)
- [Setup](#️-setup)
- [Usage](#-usage)
  - [Registration (WebAuthnRegister)](#registration-webauthnregister)
  - [Login (WebAuthnLogin)](#login-webauthnlogin)
- [Configuration](#-configuration)
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
> **Note:** `"web-auth/webauthn-framework": "^5.2"` requires [`brick/math`](https://github.com/brick/math) `^0.13`, while newer Jetstream requires `brick/math` `^0.14`. An update to version 5.3 is expected soon, which will resolve this issue, but the tag has not been created yet and the composer constraint cannot be changed.

Publish views and config files:

```bash
php artisan vendor:publish --provider="r0073rr0r\WebAuthn\WebAuthnServiceProvider"
```

Publish all package resources (views, translations, and public assets) with a single command:
```bash
php artisan vendor:publish --tag=webauthn
```

This will also copy the translation files to your `lang/vendor/webauthn` directory, where you can customize them.

Migrate database tables:

```bash
php artisan migrate
```

> **Note:** The migration is safe to run even if the `webauthn_keys` table already exists. It will check if the table exists before creating it, and will add a unique constraint on `credentialId` if it doesn't already exist.

<a href="https://asciinema.org/a/Bn7vl6s5sqh3NfZk5nFI9iPBc?t=7" target="_blank">
  <img src="https://asciinema.org/a/Bn7vl6s5sqh3NfZk5nFI9iPBc.svg" alt="asciicast installation of package">
</a>

## 🔄 Updating

When updating the package to a new version, you should republish the configuration and translation files to ensure you have the latest changes:

```bash
composer update r0073rr0r/laravel-webauthn
php artisan vendor:publish --provider="r0073rr0r\WebAuthn\WebAuthnServiceProvider" --tag=webauthn --force
```

The `--force` flag will overwrite existing files with the latest versions from the package, ensuring you have all new configuration options and translations.

> **Important:** After updating, review the `config/webauthn.php` file for any new configuration options that may have been added.

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

## ⚙️ Configuration

The package configuration file is located at `config/webauthn.php`. After publishing, you can customize the following options:

### Basic Configuration

```php
'rp_id' => env('WEBAUTHN_RP_ID', parse_url(config('app.url'), PHP_URL_HOST) ?: 'localhost'),

'allowed_origins' => [
    env('APP_URL'),
],

'require_user_verification' => env('WEBAUTHN_REQUIRE_UV', false),
```

### Supported Algorithms

You can configure which cryptographic algorithms are allowed:

```php
'allowed_algorithms' => [
    -7,   // ES256 (Elliptic Curve P-256) - Most common, used by Chrome passkeys and YubiKey
    -35,  // ES384 (Elliptic Curve P-384)
    -36,  // ES512 (Elliptic Curve P-521)
    -257, // RS256 (RSA) - Used by some older hardware security keys
],
```

### Rate Limiting

Protect against brute force attacks with configurable rate limiting:

```php
'rate_limit' => [
    'enabled' => env('WEBAUTHN_RATE_LIMIT_ENABLED', true),
    'max_attempts' => env('WEBAUTHN_RATE_LIMIT_ATTEMPTS', 5),
    'decay_minutes' => env('WEBAUTHN_RATE_LIMIT_DECAY', 1),
],
```

### Timeout Configuration

Configure the timeout for WebAuthn operations (in milliseconds):

```php
'timeout' => env('WEBAUTHN_TIMEOUT', 60000), // 60 seconds default
```

### Device Name Validation

Set minimum and maximum length for device names:

```php
'key_name' => [
    'min_length' => env('WEBAUTHN_KEY_NAME_MIN', 3),
    'max_length' => env('WEBAUTHN_KEY_NAME_MAX', 64),
],
```

### Audit Logging

Enable audit logging for security monitoring:

```php
'audit_log' => [
    'enabled' => env('WEBAUTHN_AUDIT_LOG_ENABLED', true),
    'channel' => env('WEBAUTHN_AUDIT_LOG_CHANNEL', 'daily'),
],
```

**Log Channel Options:**
- `'daily'` - Creates a new log file each day (e.g., `laravel-2025-01-07.log`) in `storage/logs/`
- `'single'` - Writes to a single log file (`laravel.log`)
- `'syslog'` - Writes to system log
- `'errorlog'` - Writes to PHP error log
- Custom channel - Use any channel defined in `config/logging.php`

> **Note:** The `'daily'` channel does NOT send emails. It only writes to log files. If you need email notifications, configure a custom log channel in `config/logging.php` that uses a mail driver.

#### Email Notifications for Audit Logs

If you want to receive email notifications for WebAuthn operations, you can configure a custom log channel with email support:

**Step 1:** Add a custom channel in `config/logging.php`:

```php
// config/logging.php
'channels' => [
    // ... existing channels ...
    
    'webauthn-email' => [
        'driver' => 'mail',
        'level' => 'info',
        'to' => env('WEBAUTHN_AUDIT_EMAIL', 'admin@example.com'),
        'subject' => 'WebAuthn Security Event',
    ],
],
```

**Step 2:** Configure the email channel in your `.env`:

```env
WEBAUTHN_AUDIT_LOG_CHANNEL=webauthn-email
WEBAUTHN_AUDIT_EMAIL=admin@example.com
```

**Step 3:** Make sure your Laravel mail configuration is set up correctly in `.env`:

```env
MAIL_MAILER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=your-username
MAIL_PASSWORD=your-password
MAIL_ENCRYPTION=tls
MAIL_FROM_ADDRESS=noreply@example.com
MAIL_FROM_NAME="${APP_NAME}"
```

**Alternative:** For more advanced email notifications (e.g., only on errors, formatted emails), you can create a custom channel with Slack, Discord, or other notification services:

```php
// config/logging.php
'webauthn-slack' => [
    'driver' => 'slack',
    'url' => env('WEBAUTHN_SLACK_WEBHOOK_URL'),
    'username' => 'WebAuthn Bot',
    'emoji' => ':warning:',
    'level' => 'info',
],
```

Audit logs include:
- Key registrations (with user ID, key name, credential ID, AAGUID)
- Login attempts (successful and failed)
- Key deletions
- Errors with full context (IP, user agent, timestamp)

**Example log entry:**
```json
{
  "message": "WebAuthn: login_success",
  "action": "login_success",
  "user_id": 123,
  "credential_id": "a1b2c3d4...",
  "success": true,
  "ip": "192.168.1.1",
  "user_agent": "Mozilla/5.0...",
  "timestamp": "2025-01-07T12:34:56+00:00"
}
```

### Environment Variables

You can configure all options via environment variables in your `.env` file:

```env
WEBAUTHN_RP_ID=your-domain.com
WEBAUTHN_REQUIRE_UV=false
WEBAUTHN_RATE_LIMIT_ENABLED=true
WEBAUTHN_RATE_LIMIT_ATTEMPTS=5
WEBAUTHN_RATE_LIMIT_DECAY=1
WEBAUTHN_TIMEOUT=60000
WEBAUTHN_KEY_NAME_MIN=3
WEBAUTHN_KEY_NAME_MAX=64
WEBAUTHN_AUDIT_LOG_ENABLED=true
WEBAUTHN_AUDIT_LOG_CHANNEL=daily
```

## 🎨 Customization

You can customize the view files after publishing them:

- `resources/views/vendor/laravel-webauthn/livewire/web-authn-register.blade.php`
- `resources/views/vendor/laravel-webauthn/livewire/web-authn-login.blade.php`

## 🔒 Security

WebAuthn is a modern standard for secure passwordless authentication. This package uses browser native WebAuthn APIs for maximum security.

### Security Features

- **Rate Limiting**: Protects against brute force attacks with configurable limits
- **Audit Logging**: Comprehensive logging of all WebAuthn operations for security monitoring
- **Replay Attack Protection**: Sign counter validation prevents replay attacks
- **Origin Validation**: Ensures requests come from allowed origins only
- **Challenge Validation**: One-time challenges prevent replay attacks
- **User Verification**: Optional user verification requirement for enhanced security

### Supported Authenticators

This package supports a wide range of WebAuthn authenticators:

- ✅ **Chrome/Edge passkeys** (biometric authentication) - EC2 P-256
- ✅ **YubiKey 5 series** (USB security keys) - EC2 P-256 or RSA
- ✅ **Apple Touch ID / Face ID** (via Safari) - EC2 P-256
- ✅ **Other hardware security keys** - Various algorithms (ES256, ES384, ES512, RS256)

## 📝 License

MIT License

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.