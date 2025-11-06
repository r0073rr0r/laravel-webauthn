<?php

namespace r0073rr0r\WebAuthn\Tests\Feature;

use Illuminate\Support\Facades\Auth;
use Livewire\Livewire;
use r0073rr0r\WebAuthn\Livewire\WebAuthnLogin;
use r0073rr0r\WebAuthn\Models\WebAuthnKey;
use r0073rr0r\WebAuthn\Tests\Support\OpenSslMock;

it('mounts and sets challenge when session is empty', function () {
    Livewire::test(WebAuthnLogin::class)
        ->assertSet('challenge', fn ($v) => is_string($v) && $v !== '')
        ->assertSet('keys', fn ($v) => $v instanceof \Illuminate\Database\Eloquent\Collection && $v->count() === 0);

    expect(session()->has('webauthn_login_challenge'))->toBeTrue();
});

it('does not authenticate when credential is not found', function () {
    // Not logged in initially
    expect(Auth::check())->toBeFalse();

    $cred = [
        'id' => rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '='),
        'type' => 'public-key',
        'response' => [
            'clientDataJSON' => rtrim(strtr(base64_encode('{}'), '+/', '-_'), '='),
            'authenticatorData' => rtrim(strtr(base64_encode('auth'), '+/', '-_'), '='),
            'signature' => rtrim(strtr(base64_encode('sig'), '+/', '-_'), '='),
        ],
    ];

    Livewire::test(WebAuthnLogin::class)
        ->call('loginWithPasskey', json_encode($cred));

    expect(Auth::check())->toBeFalse();
});

it('authenticates successfully on valid credential and signature', function () {
    config()->set('webauthn.allowed_origins', [config('app.url')]);
    $user = \App\Models\User::create(['name' => 'U', 'email' => 'ok@example.com']);

    // Existing key for user
    $rawId = random_bytes(16);
    $key = WebAuthnKey::create([
        'user_id' => $user->id,
        'name' => 'Key',
        'credentialId' => $rawId,
        'type' => 'public-key',
        'transports' => json_encode([]),
        'attestationType' => 'att',
        'trustPath' => 'trust',
        'aaguid' => null,
        'credentialPublicKey' => '-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----',
        'counter' => 0,
    ]);

    // Mount component to get expected challenge
    $component = Livewire::test(WebAuthnLogin::class);
    $challenge = $component->get('challenge');

    // Build clientDataJSON with the expected challenge
    $clientData = json_encode([
        'challenge' => $challenge,
        'type' => 'webauthn.get',
        'origin' => config('app.url'),
    ]);

    // Build authenticatorData with signCount at offset 33
    $prefix = str_repeat("\x00", 33);
    $signCount = 10;
    // Build rpIdHash = sha256(rp_id)
    $rpIdHash = hash('sha256', config('webauthn.rp_id'), true);
    // Flags: UP=1, UV=0x04 (we can include UV to test both later)
    $flags = chr(0x01 | 0x04);
    $authenticatorData = $rpIdHash . $flags . pack('N', $signCount) . str_repeat("\x00", 8);

    // Make signature "valid" via our override
    OpenSslMock::setReturn(1);

    $cred = [
        'id' => rtrim(strtr(base64_encode($rawId), '+/', '-_'), '='),
        'type' => 'public-key',
        'response' => [
            'clientDataJSON' => rtrim(strtr(base64_encode($clientData), '+/', '-_'), '='),
            'authenticatorData' => rtrim(strtr(base64_encode($authenticatorData), '+/', '-_'), '='),
            'signature' => rtrim(strtr(base64_encode('sig'), '+/', '-_'), '='),
        ],
    ];

    $component->call('loginWithPasskey', json_encode($cred));

    expect(Auth::check())->toBeTrue();
    expect(Auth::id())->toBe($user->id);
    expect($key->fresh()->counter)->toBe($signCount);

    // Reset mock
    OpenSslMock::setReturn(0);
});

it('invalidates challenge after attempt', function () {
    config()->set('webauthn.allowed_origins', [config('app.url')]);
    $user = \App\Models\User::create(['name' => 'U2', 'email' => 'ok2@example.com']);
    $rawId = random_bytes(16);
    WebAuthnKey::create([
        'user_id' => $user->id,
        'name' => 'Key',
        'credentialId' => $rawId,
        'type' => 'public-key',
        'transports' => json_encode([]),
        'attestationType' => 'att',
        'trustPath' => 'trust',
        'aaguid' => null,
        'credentialPublicKey' => '-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----',
        'counter' => 0,
    ]);

    $component = Livewire::test(WebAuthnLogin::class);
    $challenge = $component->get('challenge');

    $clientData = json_encode([
        'challenge' => $challenge,
        'type' => 'webauthn.get',
        'origin' => config('app.url'),
    ]);
    $rpIdHash = hash('sha256', config('webauthn.rp_id'), true);
    $flags = chr(0x01 | 0x04);
    $authenticatorData = $rpIdHash . $flags . pack('N', 1) . str_repeat("\x00", 8);

    OpenSslMock::setReturn(1);
    $cred = [
        'id' => rtrim(strtr(base64_encode($rawId), '+/', '-_'), '='),
        'type' => 'public-key',
        'response' => [
            'clientDataJSON' => rtrim(strtr(base64_encode($clientData), '+/', '-_'), '='),
            'authenticatorData' => rtrim(strtr(base64_encode($authenticatorData), '+/', '-_'), '='),
            'signature' => rtrim(strtr(base64_encode('sig'), '+/', '-_'), '='),
        ],
    ];

    $component->call('loginWithPasskey', json_encode($cred));

    expect(session()->has('webauthn_login_challenge'))->toBeFalse();
    OpenSslMock::setReturn(0);
});

it('fails when UV is required but not present', function () {
    config()->set('webauthn.allowed_origins', [config('app.url')]);
    config()->set('webauthn.require_user_verification', true);

    $user = \App\Models\User::create(['name' => 'U3', 'email' => 'uv@example.com']);
    $rawId = random_bytes(16);
    WebAuthnKey::create([
        'user_id' => $user->id,
        'name' => 'Key',
        'credentialId' => $rawId,
        'type' => 'public-key',
        'transports' => json_encode([]),
        'attestationType' => 'att',
        'trustPath' => 'trust',
        'aaguid' => null,
        'credentialPublicKey' => '-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----',
        'counter' => 0,
    ]);

    $component = Livewire::test(WebAuthnLogin::class);
    $challenge = $component->get('challenge');

    $clientData = json_encode([
        'challenge' => $challenge,
        'type' => 'webauthn.get',
        'origin' => config('app.url'),
    ]);
    $rpIdHash = hash('sha256', config('webauthn.rp_id'), true);
    // Flags: only UP, no UV
    $flags = chr(0x01);
    $authenticatorData = $rpIdHash . $flags . pack('N', 1) . str_repeat("\x00", 8);

    OpenSslMock::setReturn(1);
    $cred = [
        'id' => rtrim(strtr(base64_encode($rawId), '+/', '-_'), '='),
        'type' => 'public-key',
        'response' => [
            'clientDataJSON' => rtrim(strtr(base64_encode($clientData), '+/', '-_'), '='),
            'authenticatorData' => rtrim(strtr(base64_encode($authenticatorData), '+/', '-_'), '='),
            'signature' => rtrim(strtr(base64_encode('sig'), '+/', '-_'), '='),
        ],
    ];

    $component->call('loginWithPasskey', json_encode($cred));
    expect(\Illuminate\Support\Facades\Auth::check())->toBeFalse();
    OpenSslMock::setReturn(0);
});

it('does not authenticate on challenge mismatch', function () {
    $user = \App\Models\User::create(['name' => 'User', 'email' => 'user2@example.com']);

    $key = WebAuthnKey::create([
        'user_id' => $user->id,
        'name' => 'Key',
        'credentialId' => $rawId = random_bytes(16),
        'type' => 'public-key',
        'transports' => json_encode([]),
        'attestationType' => 'att',
        'trustPath' => 'trust',
        'aaguid' => null,
        'credentialPublicKey' => '-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----',
        'counter' => 0,
    ]);

    $badClientData = json_encode(['challenge' => 'different-challenge']);

    $cred = [
        'id' => rtrim(strtr(base64_encode($rawId), '+/', '-_'), '='),
        'type' => 'public-key',
        'response' => [
            'clientDataJSON' => rtrim(strtr(base64_encode($badClientData), '+/', '-_'), '='),
            'authenticatorData' => rtrim(strtr(base64_encode('authdata'), '+/', '-_'), '='),
            'signature' => rtrim(strtr(base64_encode('sig'), '+/', '-_'), '='),
        ],
    ];

    Livewire::test(WebAuthnLogin::class)
        ->call('loginWithPasskey', json_encode($cred));

    expect(Auth::check())->toBeFalse();
});

it('does not authenticate on invalid signature', function () {
    $user = \App\Models\User::create(['name' => 'User', 'email' => 'user3@example.com']);

    $rawId = random_bytes(16);
    WebAuthnKey::create([
        'user_id' => $user->id,
        'name' => 'Key',
        'credentialId' => $rawId,
        'type' => 'public-key',
        'transports' => json_encode([]),
        'attestationType' => 'att',
        'trustPath' => 'trust',
        'aaguid' => null,
        'credentialPublicKey' => '-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----',
        'counter' => 0,
    ]);

    // Prepare a matching challenge from mounted component
    $component = Livewire::test(WebAuthnLogin::class);
    $challenge = $component->get('challenge');

    $clientData = json_encode(['challenge' => $challenge]);

    $cred = [
        'id' => rtrim(strtr(base64_encode($rawId), '+/', '-_'), '='),
        'type' => 'public-key',
        'response' => [
            'clientDataJSON' => rtrim(strtr(base64_encode($clientData), '+/', '-_'), '='),
            'authenticatorData' => rtrim(strtr(base64_encode('authdata'), '+/', '-_'), '='),
            'signature' => rtrim(strtr(base64_encode('sig'), '+/', '-_'), '='),
        ],
    ];

    $component->call('loginWithPasskey', json_encode($cred));
    expect(Auth::check())->toBeFalse();
});


