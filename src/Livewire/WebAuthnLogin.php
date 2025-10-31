<?php

namespace r0073rr0r\WebAuthn\Livewire;

use Illuminate\Contracts\View\Factory;
use Illuminate\Contracts\View\View;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Livewire\Component;
use r0073rr0r\WebAuthn\Models\WebAuthnKey;
use Random\RandomException;

class WebAuthnLogin extends Component
{
    public $keys;

    public $challenge;

    protected $listeners = ['loginWithPasskey'];

    /**
     * @throws RandomException
     */
    public function mount(): void
    {
        $this->keys = WebAuthnKey::all();

        if (! session()->has('webauthn_login_challenge')) {
            session(['webauthn_login_challenge' => random_bytes(32)]);
        }

        $this->challenge = $this->base64url_encode(session('webauthn_login_challenge'));
    }

    public function loginWithPasskey($credential)
    {
        $data = json_decode($credential, true);
        $credentialId = base64_decode($data['id'] ?? '');

        $key = WebAuthnKey::where('credentialId', base64_encode($credentialId))->first();

        if (! $key) {
            \Log::error('WebAuthn login failed: credentialId not found', ['credentialId' => base64_encode($credentialId)]);
            throw new \Exception('WebAuthn login failed: credentialId not found!');
        }

        try {
            $clientDataJSON = $this->base64url_decode($data['response']['clientDataJSON'] ?? '');
            $authenticatorData = $this->base64url_decode($data['response']['authenticatorData'] ?? '');
            $signature = $this->base64url_decode($data['response']['signature'] ?? '');

            $clientData = json_decode($clientDataJSON, true);
            $expectedChallenge = $this->base64url_encode(session('webauthn_login_challenge'));

            \Log::info('Challenge', ['expected' => $expectedChallenge, 'received' => $clientData['challenge'] ?? null]);

            if (! isset($clientData['challenge']) || $clientData['challenge'] !== $expectedChallenge) {
                throw new \Exception('Challenge mismatch!');
            }

            $clientDataHash = hash('sha256', $clientDataJSON, true);
            $signedData = $authenticatorData.$clientDataHash;

            $ok = openssl_verify($signedData, $signature, $key->credentialPublicKey, OPENSSL_ALGO_SHA256);
            if ($ok !== 1) {
                throw new \Exception('Invalid signature!');
            }

            $signCount = unpack('N', substr($authenticatorData, 33, 4))[1];

            if ($signCount < $key->counter) {
                throw new \Exception('Sign counter decreased! Possible replay attack.');
            }

            $key->counter = $signCount;
            $key->save();

            Auth::login($key->user);

            return redirect()->intended('/accounts');

        } catch (\Throwable $e) {
            \Log::error('WebAuthn login failed: '.$e->getMessage());

            return;
        }
    }

    private function base64url_decode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($data, '-_', '+/'));
    }

    private function base64url_encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public function render(): Factory|View|Application|\Illuminate\View\View
    {
        return view('webauthn::livewire.web-authn-login');
    }
}
