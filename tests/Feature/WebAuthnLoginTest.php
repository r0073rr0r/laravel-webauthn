<?php

namespace r0073rr0r\WebAuthn\Tests\Feature;

use Illuminate\Support\Facades\Auth;
use Livewire\Livewire;
use r0073rr0r\WebAuthn\Helpers\CredentialParser;
use r0073rr0r\WebAuthn\Livewire\WebAuthnLogin;
use r0073rr0r\WebAuthn\Models\WebAuthnKey;
use r0073rr0r\WebAuthn\Tests\Support\OpenSslMock;

beforeEach(function () {
    // Disable rate limiting in tests
    config()->set('webauthn.rate_limit.enabled', false);
    // Disable audit logging in tests
    config()->set('webauthn.audit_log.enabled', false);
});

it('mounts and sets challenge when session is empty', function () {
    Livewire::test(WebAuthnLogin::class)
        ->assertSet('challenge', fn ($v) => is_string($v) && $v !== '');

    expect(session()->has('webauthn_login_challenge'))->toBeTrue();
});

it('does not expose any credential ids on the login page', function () {
    $user = \App\Models\User::create(['name' => 'U', 'email' => 'leak@example.com']);
    $rawId = random_bytes(16);
    webauthnLoginKey($user, $rawId);

    Livewire::test(WebAuthnLogin::class)
        ->assertDontSee(CredentialParser::base64url_encode($rawId), false);
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
    $authenticatorData = $rpIdHash.$flags.pack('N', $signCount).str_repeat("\x00", 8);

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

it('rotates the challenge after an attempt', function () {
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
    $authenticatorData = $rpIdHash.$flags.pack('N', 1).str_repeat("\x00", 8);

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

    $next = session('webauthn_login_challenge');
    expect($next)->toBeString()
        ->and(CredentialParser::base64url_encode($next))->not->toBe($challenge)
        ->and($component->get('challenge'))->toBe(CredentialParser::base64url_encode($next));
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
    $authenticatorData = $rpIdHash.$flags.pack('N', 1).str_repeat("\x00", 8);

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

function webauthnLoginKey($user, string $rawId, int $counter = 0): WebAuthnKey
{
    return WebAuthnKey::create([
        'user_id' => $user->id,
        'name' => 'Key',
        'credentialId' => $rawId,
        'type' => 'public-key',
        'transports' => json_encode([]),
        'attestationType' => 'att',
        'trustPath' => 'trust',
        'aaguid' => null,
        'credentialPublicKey' => '-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----',
        'counter' => $counter,
    ]);
}

function webauthnAssertion(string $rawId, string $challenge, int $signCount = 1, ?string $userHandle = null): string
{
    $clientData = json_encode([
        'challenge' => $challenge,
        'type' => 'webauthn.get',
        'origin' => config('app.url'),
    ]);
    $authenticatorData = hash('sha256', config('webauthn.rp_id'), true).chr(0x01 | 0x04).pack('N', $signCount);

    $response = [
        'clientDataJSON' => CredentialParser::base64url_encode($clientData),
        'authenticatorData' => CredentialParser::base64url_encode($authenticatorData),
        'signature' => CredentialParser::base64url_encode('sig'),
    ];
    if ($userHandle !== null) {
        $response['userHandle'] = CredentialParser::base64url_encode($userHandle);
    }

    return json_encode([
        'id' => CredentialParser::base64url_encode($rawId),
        'type' => 'public-key',
        'response' => $response,
    ]);
}

it('does not allow the challenge property to be tampered with', function () {
    Livewire::test(WebAuthnLogin::class)->set('challenge', 'attacker-chosen');
})->throws(\Livewire\Features\SupportLockedProperties\CannotUpdateLockedPropertyException::class);

it('rejects a replayed assertion even when it was valid the first time', function () {
    config()->set('webauthn.allowed_origins', [config('app.url')]);
    $user = \App\Models\User::create(['name' => 'R', 'email' => 'replay@example.com']);
    $rawId = random_bytes(16);
    webauthnLoginKey($user, $rawId);

    $component = Livewire::test(WebAuthnLogin::class);
    $assertion = webauthnAssertion($rawId, $component->get('challenge'), 5);

    OpenSslMock::setReturn(1);
    $component->call('loginWithPasskey', $assertion);
    expect(Auth::check())->toBeTrue();

    Auth::logout();
    $component->call('loginWithPasskey', $assertion);
    expect(Auth::check())->toBeFalse();
    OpenSslMock::setReturn(0);
});

it('rejects a signature counter that did not increase', function () {
    config()->set('webauthn.allowed_origins', [config('app.url')]);
    $user = \App\Models\User::create(['name' => 'C', 'email' => 'counter@example.com']);
    $rawId = random_bytes(16);
    webauthnLoginKey($user, $rawId, 7);

    $component = Livewire::test(WebAuthnLogin::class);

    OpenSslMock::setReturn(1);
    $component->call('loginWithPasskey', webauthnAssertion($rawId, $component->get('challenge'), 7));
    expect(Auth::check())->toBeFalse()
        ->and($component->get('error'))->not->toBe('');
    OpenSslMock::setReturn(0);
});

it('accepts authenticators that always report a zero counter', function () {
    config()->set('webauthn.allowed_origins', [config('app.url')]);
    $user = \App\Models\User::create(['name' => 'Z', 'email' => 'zero@example.com']);
    $rawId = random_bytes(16);
    webauthnLoginKey($user, $rawId, 0);

    $component = Livewire::test(WebAuthnLogin::class);

    OpenSslMock::setReturn(1);
    $component->call('loginWithPasskey', webauthnAssertion($rawId, $component->get('challenge'), 0));
    expect(Auth::id())->toBe($user->id);
    OpenSslMock::setReturn(0);
});

it('rejects a user handle that belongs to a different user', function () {
    config()->set('webauthn.allowed_origins', [config('app.url')]);
    $owner = \App\Models\User::create(['name' => 'O', 'email' => 'owner@example.com']);
    $other = \App\Models\User::create(['name' => 'X', 'email' => 'other@example.com']);
    $rawId = random_bytes(16);
    webauthnLoginKey($owner, $rawId);

    $component = Livewire::test(WebAuthnLogin::class);

    OpenSslMock::setReturn(1);
    $component->call('loginWithPasskey', webauthnAssertion($rawId, $component->get('challenge'), 1, (string) $other->id));
    expect(Auth::check())->toBeFalse();

    $component->call('loginWithPasskey', webauthnAssertion($rawId, $component->get('challenge'), 2, (string) $owner->id));
    expect(Auth::id())->toBe($owner->id);
    OpenSslMock::setReturn(0);
});
