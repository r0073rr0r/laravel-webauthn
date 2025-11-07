<?php

namespace r0073rr0r\WebAuthn\Livewire;

use CBOR\Decoder;
use CBOR\StringStream;
use Illuminate\Contracts\View\View;
use Illuminate\Foundation\Application;
use Livewire\Component;
use r0073rr0r\WebAuthn\Helpers\CredentialParser;
use r0073rr0r\WebAuthn\Models\WebAuthnKey;
use Random\RandomException;

class WebAuthnRegister extends Component
{
    public $creationOptions;

    public $keys;

    public $userId;

    public $keyName = '';

    public $showModal = false;

    protected $listeners = ['registerKey'];

    /**
     * @throws RandomException
     */
    public function mount(): void
    {
        $this->userId = auth()->id();
        $this->keys = WebAuthnKey::where('user_id', $this->userId)->get();

        $challenge = random_bytes(32);
        session(['webauthn_register_challenge' => $challenge]);

        $rp = [
            'name' => config('app.name'),
            'id' => request()->getHost(),
        ];

        $user = [
            'id' => $challengeUserId = random_bytes(32),
            'name' => auth()->user()->email,
            'displayName' => auth()->user()->name,
        ];

        $pubKeyCredParams = [
            ['type' => 'public-key', 'alg' => -7],   // ES256
            ['type' => 'public-key', 'alg' => -257], // RS256
        ];

        $this->creationOptions = [
            'challenge' => CredentialParser::base64url_encode($challenge),
            'rp' => $rp,
            'user' => [
                'id' => CredentialParser::base64url_encode((string) auth()->user()->id), // za Livewire
                'name' => $user['name'],
                'displayName' => $user['displayName'],
            ],
            'pubKeyCredParams' => $pubKeyCredParams,
            'authenticatorSelection' => [
                'userVerification' => 'preferred',
            ],
            'attestation' => 'none',
        ];
    }

    public function openModal(): void
    {
        $this->keyName = '';
        $this->showModal = true;
    }

    public function closeModal(): void
    {
        $this->showModal = false;
    }

    public function registerKey($credential): void
    {
        if (empty($this->keyName) || ! is_string($this->keyName) || mb_strlen($this->keyName) > 64) {
            session()->flash('status', 'Device name is required');
            return;
        }

        $data = json_decode($credential, true);

        // Validate presence of client data
        $clientDataJSON = CredentialParser::base64url_decode($data['response']['clientDataJSON'] ?? '');
        if ($clientDataJSON === '' || ! ($clientData = json_decode($clientDataJSON, true))) {
            session()->flash('status', 'Invalid client data');
            return;
        }

        // Validate expected type and origin
        if (($clientData['type'] ?? '') !== 'webauthn.create') {
            session()->flash('status', 'Invalid clientData type');
            return;
        }
        $origin = $clientData['origin'] ?? '';
        $allowedOrigins = array_filter((array) config('webauthn.allowed_origins', []));
        if (! in_array($origin, $allowedOrigins, true)) {
            session()->flash('status', 'Origin not allowed');
            return;
        }

        // Verify challenge (compare base64url-encoded session challenge)
        $expectedChallenge = session()->has('webauthn_register_challenge')
            ? CredentialParser::base64url_encode(session('webauthn_register_challenge'))
            : null;
        if (! $expectedChallenge || ($clientData['challenge'] ?? null) !== $expectedChallenge) {
            session()->flash('status', 'Challenge mismatch!');
            return;
        }

        // Now parse attestation
        $attestationObject = CredentialParser::base64url_decode($data['response']['attestationObject'] ?? '');

        $decoder = new Decoder;
        $streamAtt = new StringStream($attestationObject);
        $cborAtt = $decoder->decode($streamAtt);
        $normalized = $cborAtt->normalize();
        $authData = $normalized['authData'] ?? null;

        if (! $authData) {
            session()->flash('status', 'Invalid credential data');
            return;
        }

        // rpIdHash and flags
        $rpId = (string) config('webauthn.rp_id');
        if (! CredentialParser::rpIdHashMatches($authData, $rpId)) {
            session()->flash('status', 'RP ID hash mismatch');
            return;
        }
        if (! CredentialParser::isUserPresent($authData)) {
            session()->flash('status', 'User not present');
            return;
        }
        if (config('webauthn.require_user_verification') && ! CredentialParser::isUserVerified($authData)) {
            session()->flash('status', 'User not verified');
            return;
        }

        $credentialData = substr($authData, 37);
        $credIdLen = unpack('n', substr($credentialData, 16, 2))[1];
        $credentialId = substr($credentialData, 18, $credIdLen);
        $cosePublicKey = substr($credentialData, 18 + $credIdLen);

        // COSE -> PEM
        $publicKeyPem = CredentialParser::convertCoseToPem($cosePublicKey);

        // Enforce allowed algorithms
        $alg = CredentialParser::extractCoseAlgorithm($cosePublicKey);
        $allowedAlgs = (array) config('webauthn.allowed_algorithms', []);
        if ($alg !== null && ! in_array($alg, $allowedAlgs, true)) {
            session()->flash('status', 'Algorithm not allowed');
            return;
        }

        if (WebAuthnKey::where('credentialId', $credentialId)->exists()) {
            session()->flash('status', 'This key is already registered');
            return;
        }

        $counter = CredentialParser::extractCounter($authData);

        WebAuthnKey::create([
            'user_id' => $this->userId,
            'name' => $this->keyName,
            'credentialId' => $credentialId,
            'type' => $data['type'] ?? '',
            'transports' => json_encode($data['response']['transports'] ?? []),
            'attestationType' => base64_encode($attestationObject),
            'trustPath' => base64_encode(json_encode($data['response'] ?? [])),
            'aaguid' => CredentialParser::extractAAGUID($authData),
            'credentialPublicKey' => $publicKeyPem,
            'counter' => $counter,
        ]);

        $this->keys = WebAuthnKey::where('user_id', $this->userId)->get();
        // Invalidate registration challenge after successful registration
        session()->forget('webauthn_register_challenge');
        $this->closeModal();
    }

    public function deleteKey($id): void
    {
        $key = WebAuthnKey::find($id);
        if (! $key || $key->user_id !== $this->userId) {
            return;
        }
        $key->delete();
        $this->keys = WebAuthnKey::where('user_id', $this->userId)->get();
    }

    public function render(): View|Application
    {
        return view('webauthn::livewire.web-authn-register');
    }
}
