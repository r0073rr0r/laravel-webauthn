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

it('converts EC2 P-256 COSE key to PEM format - Chrome passkey, YubiKey support', function () {
    // Test EC2 P-256 (ES256) - most common, used by Chrome passkey and YubiKey
    // This algorithm is supported by:
    // - Chrome/Edge passkeys (biometric authentication)
    // - YubiKey 5 series (USB security keys)
    // - Most modern hardware security keys
    
    $keyData = \r0073rr0r\WebAuthn\Tests\Support\CoseKeyGenerator::generateEc2P256Array();
    
    // Use reflection to test convertKeyDataToPem directly
    $reflection = new \ReflectionClass(CredentialParser::class);
    $method = $reflection->getMethod('convertKeyDataToPem');
    $method->setAccessible(true);
    
    $pem = $method->invokeArgs(null, [$keyData, $keyData]);
    
    // Verify PEM format is correct
    expect($pem)->toContain('BEGIN PUBLIC KEY');
    expect($pem)->toContain('END PUBLIC KEY');
    expect($pem)->toMatch('/^-----BEGIN PUBLIC KEY-----/');
    expect($pem)->toMatch('/-----END PUBLIC KEY-----\s*$/');
    
    // Verify structure - should have multiple lines
    $lines = array_filter(explode("\n", $pem), fn($line) => !empty(trim($line)));
    expect(count($lines))->toBeGreaterThan(2); // At least header, content, footer
});

it('converts RSA COSE key to PEM format - some hardware security keys', function () {
    // Test RSA (RS256) - used by some older hardware security keys
    // This algorithm is supported by:
    // - Some older YubiKey models
    // - Some enterprise security keys
    
    $keyData = \r0073rr0r\WebAuthn\Tests\Support\CoseKeyGenerator::generateRsaArray();
    
    $reflection = new \ReflectionClass(CredentialParser::class);
    $method = $reflection->getMethod('convertKeyDataToPem');
    $method->setAccessible(true);
    
    $pem = $method->invokeArgs(null, [$keyData, $keyData]);
    
    // Verify PEM format is correct
    expect($pem)->toContain('BEGIN PUBLIC KEY');
    expect($pem)->toContain('END PUBLIC KEY');
    expect($pem)->toMatch('/^-----BEGIN PUBLIC KEY-----/');
    expect($pem)->toMatch('/-----END PUBLIC KEY-----\s*$/');
    
    // Verify structure - should have multiple lines
    $lines = array_filter(explode("\n", $pem), fn($line) => !empty(trim($line)));
    expect(count($lines))->toBeGreaterThan(2); // At least header, content, footer
});

it('supports multiple key types for different authenticators', function () {
    // Test that the system can handle different key types
    // This ensures compatibility with:
    // - Chrome passkeys (EC2 P-256)
    // - YubiKey (EC2 P-256 or RSA)
    // - Other hardware security keys (various algorithms)
    
    // EC2 P-256 (most common)
    $ec2Key = \r0073rr0r\WebAuthn\Tests\Support\CoseKeyGenerator::generateEc2P256Array();
    expect($ec2Key[1])->toBe(2); // kty: EC2
    expect($ec2Key[3])->toBe(-7); // alg: ES256
    expect($ec2Key[-2])->toBe(1); // crv: P-256
    
    // RSA
    $rsaKey = \r0073rr0r\WebAuthn\Tests\Support\CoseKeyGenerator::generateRsaArray();
    expect($rsaKey[1])->toBe(3); // kty: RSA
    expect($rsaKey[3])->toBe(-257); // alg: RS256
    
    // Both should be convertible to PEM
    $reflection = new \ReflectionClass(CredentialParser::class);
    $method = $reflection->getMethod('convertKeyDataToPem');
    $method->setAccessible(true);
    
    $ec2Pem = $method->invokeArgs(null, [$ec2Key, $ec2Key]);
    $rsaPem = $method->invokeArgs(null, [$rsaKey, $rsaKey]);
    
    expect($ec2Pem)->toContain('BEGIN PUBLIC KEY');
    expect($rsaPem)->toContain('BEGIN PUBLIC KEY');
});


