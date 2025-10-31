<?php
namespace r0073rr0r\WebAuthn\Livewire;

use Livewire\Component;
use Illuminate\Support\Facades\Auth;
use r0073rr0r\WebAuthn\Models\WebAuthnKey;

class WebAuthnLogin extends Component
{
    public $keys;
    public $challenge;

    protected $listeners = ['loginWithPasskey'];

    public function mount(): void
    {
        $this->keys = WebAuthnKey::all();

        if (!session()->has('webauthn_login_challenge')) {
            session(['webauthn_login_challenge' => random_bytes(32)]);
        }

        $this->challenge = rtrim(strtr(base64_encode(session('webauthn_login_challenge')), '+/', '-_'), '=');
    }

    public function loginWithPasskey($credential)
    {
        $data = json_decode($credential, true);
        $credentialId = $this->base64url_decode($data['id'] ?? '');

        // ⚡ Direktno binarno poređenje (radi i za SQLite i MySQL)
        $key = WebAuthnKey::where('credentialId', $credentialId)->first();

        if (!$key) {
            \Log::error('WebAuthn login failed: credentialId not found', ['credentialId' => $data['id']]);
            return;
        }

        try {
            $clientDataJSON = $this->base64url_decode($data['response']['clientDataJSON'] ?? '');
            $authenticatorData = $this->base64url_decode($data['response']['authenticatorData'] ?? '');
            $signature = $this->base64url_decode($data['response']['signature'] ?? '');

            $clientData = json_decode($clientDataJSON, true);
            $expectedChallenge = $this->challenge;

            if (!isset($clientData['challenge']) || $clientData['challenge'] !== $expectedChallenge) {
                throw new \Exception('Challenge mismatch!');
            }

            $clientDataHash = hash('sha256', $clientDataJSON, true);
            $signedData = $authenticatorData . $clientDataHash;

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

    public function render()
    {
        return view('webauthn::livewire.web-authn-login');
    }
}
