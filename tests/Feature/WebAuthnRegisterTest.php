<?php

namespace r0073rr0r\WebAuthn\Tests\Feature;

use Illuminate\Support\Facades\Auth;
use Livewire\Livewire;
use r0073rr0r\WebAuthn\Livewire\WebAuthnRegister;
use r0073rr0r\WebAuthn\Models\WebAuthnKey;
use r0073rr0r\WebAuthn\Helpers\CredentialParser;

it('mounts and initializes creation options for the authenticated user', function () {
    $user = \App\Models\User::create([
        'name' => 'Test User',
        'email' => 'test@example.com',
        'password' => null,
    ]);

    Auth::login($user);

    Livewire::test(WebAuthnRegister::class)
        ->assertSet('userId', $user->id)
        ->assertSet('showModal', false)
        ->assertViewHas('creationOptions')
        ->assertSet('keys', fn ($v) => $v instanceof \Illuminate\Database\Eloquent\Collection && $v->count() === 0);

    expect(session()->has('webauthn_register_challenge'))->toBeTrue();
});

it('opens and closes the modal correctly', function () {
    $user = \App\Models\User::create([
        'name' => 'Test User',
        'email' => 'user2@example.com',
    ]);

    $this->actingAs($user);

    Livewire::test(WebAuthnRegister::class)
        ->call('openModal')
        ->assertSet('showModal', true)
        ->assertSet('keyName', '')
        ->call('closeModal')
        ->assertSet('showModal', false);
});

it('does not create a key when device name or credential missing', function () {
    $user = \App\Models\User::create([
        'name' => 'Test User',
        'email' => 'user3@example.com',
    ]);

    $this->actingAs($user);

    $component = Livewire::test(WebAuthnRegister::class)
        ->set('keyName', '')
        ->call('registerKey', null);

    expect(\r0073rr0r\WebAuthn\Models\WebAuthnKey::where('user_id', $user->id)->count())->toBe(0);
});

it('rejects registration when type is invalid', function () {
    config()->set('webauthn.allowed_origins', [config('app.url')]);
    $user = \App\Models\User::create([
        'name' => 'Test User',
        'email' => 'type@example.com',
    ]);

    $this->actingAs($user);

    $component = Livewire::test(WebAuthnRegister::class);

    $challenge = CredentialParser::base64url_encode(session('webauthn_register_challenge'));

    $clientData = [
        'type' => 'webauthn.get', // wrong type
        'origin' => config('app.url'),
        'challenge' => $challenge,
    ];

    $credential = [
        'type' => 'public-key',
        'response' => [
            'clientDataJSON' => rtrim(strtr(base64_encode(json_encode($clientData)), '+/', '-_'), '='),
        ],
    ];

    $component->set('keyName', 'Key')->call('registerKey', json_encode($credential));

    expect(WebAuthnKey::where('user_id', $user->id)->count())->toBe(0);
});

it('rejects registration when origin is not allowed', function () {
    config()->set('webauthn.allowed_origins', [config('app.url')]);
    $user = \App\Models\User::create([
        'name' => 'Test User',
        'email' => 'origin@example.com',
    ]);

    $this->actingAs($user);

    $component = Livewire::test(WebAuthnRegister::class);

    $challenge = CredentialParser::base64url_encode(session('webauthn_register_challenge'));

    $clientData = [
        'type' => 'webauthn.create',
        'origin' => 'https://malicious.example.com',
        'challenge' => $challenge,
    ];

    $credential = [
        'type' => 'public-key',
        'response' => [
            'clientDataJSON' => rtrim(strtr(base64_encode(json_encode($clientData)), '+/', '-_'), '='),
        ],
    ];

    $component->set('keyName', 'Key')->call('registerKey', json_encode($credential));

    expect(WebAuthnKey::where('user_id', $user->id)->count())->toBe(0);
});

it('rejects registration when challenge mismatches', function () {
    config()->set('webauthn.allowed_origins', [config('app.url')]);
    $user = \App\Models\User::create([
        'name' => 'Test User',
        'email' => 'chal@example.com',
    ]);

    $this->actingAs($user);

    $component = Livewire::test(WebAuthnRegister::class);

    $clientData = [
        'type' => 'webauthn.create',
        'origin' => config('app.url'),
        'challenge' => 'different-challenge',
    ];

    $credential = [
        'type' => 'public-key',
        'response' => [
            'clientDataJSON' => rtrim(strtr(base64_encode(json_encode($clientData)), '+/', '-_'), '='),
        ],
    ];

    $component->set('keyName', 'Key')->call('registerKey', json_encode($credential));

    expect(WebAuthnKey::where('user_id', $user->id)->count())->toBe(0);
});

it('deletes only own key and refreshes the list', function () {
    $owner = \App\Models\User::create(['name' => 'Owner', 'email' => 'owner@example.com']);
    $other = \App\Models\User::create(['name' => 'Other', 'email' => 'other@example.com']);

    $ownedKey = WebAuthnKey::create([
        'user_id' => $owner->id,
        'name' => 'MyKey',
        'credentialId' => random_bytes(16),
        'type' => 'public-key',
        'transports' => json_encode([]),
        'attestationType' => 'att',
        'trustPath' => 'trust',
        'aaguid' => null,
        'credentialPublicKey' => '-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----',
        'counter' => 0,
    ]);

    $otherKey = WebAuthnKey::create([
        'user_id' => $other->id,
        'name' => 'OtherKey',
        'credentialId' => random_bytes(16),
        'type' => 'public-key',
        'transports' => json_encode([]),
        'attestationType' => 'att',
        'trustPath' => 'trust',
        'aaguid' => null,
        'credentialPublicKey' => '-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----',
        'counter' => 0,
    ]);

    $this->actingAs($owner);

    Livewire::test(WebAuthnRegister::class)
        ->assertCount('keys', 1)
        ->call('deleteKey', $otherKey->id) // should be ignored (not owner)
        ->assertCount('keys', 1)
        ->call('deleteKey', $ownedKey->id)
        ->assertCount('keys', 0);

    expect(WebAuthnKey::find($ownedKey->id))->toBeNull();
    expect(WebAuthnKey::find($otherKey->id))->not()->toBeNull();
});


