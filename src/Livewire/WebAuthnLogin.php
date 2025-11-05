<?php

namespace r0073rr0r\WebAuthn\Livewire;

use Illuminate\Support\Facades\Auth;
use Livewire\Component;
use r0073rr0r\WebAuthn\Helpers\CredentialParser;
use r0073rr0r\WebAuthn\Models\WebAuthnKey;

class WebAuthnLogin extends Component
{
    public $keys;

    public $challenge;

    protected $listeners = ['loginWithPasskey'];

    public function mount(): void
    {
        $this->keys = WebAuthnKey::all();

        if (! session()->has('webauthn_login_challenge')) {
            session(['webauthn_login_challenge' => random_bytes(32)]);
        }

        $this->challenge = rtrim(strtr(base64_encode(session('webauthn_login_challenge')), '+/', '-_'), '=');
    }

    public function loginWithPasskey($credential)
    {
        $data = json_decode($credential, true);
        $credentialId = CredentialParser::base64url_decode($data['id'] ?? '');

        $key = WebAuthnKey::where('credentialId', $credentialId)->first();

        if (! $key) {
            session()->flash('status', 'Credential not found');
            \Log::error('WebAuthn login failed: credentialId not found', ['credentialId' => $data['id']]);
            return;
        }

        try {
            $clientDataJSON = CredentialParser::base64url_decode($data['response']['clientDataJSON'] ?? '');
            $authenticatorData = CredentialParser::base64url_decode($data['response']['authenticatorData'] ?? '');
            $signature = CredentialParser::base64url_decode($data['response']['signature'] ?? '');

            $clientData = json_decode($clientDataJSON, true);
            $expectedChallenge = $this->challenge;

            if (! isset($clientData['challenge']) || $clientData['challenge'] !== $expectedChallenge) {
                session()->flash('status', 'Challenge mismatch!');
                throw new \Exception('Challenge mismatch!');
            }

            $clientDataHash = hash('sha256', $clientDataJSON, true);
            $signedData = $authenticatorData.$clientDataHash;

            $ok = openssl_verify($signedData, $signature, $key->credentialPublicKey, OPENSSL_ALGO_SHA256);
            if ($ok !== 1) {
                session()->flash('status', 'Invalid signature!');
                throw new \Exception('Invalid signature!');
            }

            $signCount = unpack('N', substr($authenticatorData, 33, 4))[1];

            if ($signCount < $key->counter) {
                session()->flash('status', 'Sign counter decreased! Possible replay attack.');
                throw new \Exception('Sign counter decreased! Possible replay attack.');
            }

            $key->counter = $signCount;
            $key->save();

            Auth::login($key->user);

            return redirect()->intended('/');

        } catch (\Throwable $e) {
            session()->flash('status', 'Login failed: '.$e->getMessage());
            \Log::error('WebAuthn login failed: '.$e->getMessage());
            return;
        }
    }

    public function render()
    {
        return view('webauthn::livewire.web-authn-login');
    }
}
