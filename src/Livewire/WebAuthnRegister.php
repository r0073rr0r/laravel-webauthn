<?php

namespace r0073rr0r\WebAuthn\Livewire;

use CBOR\Decoder;
use CBOR\StringStream;
use Illuminate\Contracts\View\View;
use Illuminate\Foundation\Application;
use Livewire\Component;
use r0073rr0r\WebAuthn\Exceptions\ChallengeMismatchException;
use r0073rr0r\WebAuthn\Exceptions\OriginNotAllowedException;
use r0073rr0r\WebAuthn\Exceptions\WebAuthnException;
use r0073rr0r\WebAuthn\Helpers\AuditLogger;
use r0073rr0r\WebAuthn\Helpers\CredentialParser;
use r0073rr0r\WebAuthn\Helpers\WebAuthnRateLimiter;
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

        // Get allowed algorithms from config (ES256, ES384, ES512, RS256)
        $allowedAlgs = config('webauthn.allowed_algorithms', [-7, -257]);
        $pubKeyCredParams = array_map(function ($alg) {
            return ['type' => 'public-key', 'alg' => $alg];
        }, $allowedAlgs);

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
            'timeout' => config('webauthn.timeout', 60000),
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
        // Rate limiting
        try {
            WebAuthnRateLimiter::check('register', $this->userId);
        } catch (WebAuthnException $e) {
            session()->flash('status', $e->getUserMessage());

            return;
        }

        // Validate key name
        $minLength = config('webauthn.key_name.min_length', 3);
        $maxLength = config('webauthn.key_name.max_length', 64);

        if (empty($this->keyName) || ! is_string($this->keyName)) {
            session()->flash('status', __('webauthn::webauthn.error_key_name_required'));

            return;
        }

        $nameLength = mb_strlen($this->keyName);
        if ($nameLength < $minLength) {
            session()->flash('status', __('webauthn::webauthn.error_key_name_too_short', ['min' => $minLength]));

            return;
        }

        if ($nameLength > $maxLength) {
            session()->flash('status', __('webauthn::webauthn.error_key_name_too_long', ['max' => $maxLength]));

            return;
        }

        $data = json_decode($credential, true);

        try {
            // Validate presence of client data
            $clientDataJSON = CredentialParser::base64url_decode($data['response']['clientDataJSON'] ?? '');
            if ($clientDataJSON === '' || ! ($clientData = json_decode($clientDataJSON, true))) {
                throw new WebAuthnException('Invalid client data', 'error_invalid_client_data');
            }

            // Validate expected type and origin
            if (($clientData['type'] ?? '') !== 'webauthn.create') {
                throw new WebAuthnException('Invalid clientData type', 'error_invalid_type');
            }

            $origin = $clientData['origin'] ?? '';
            $allowedOrigins = array_filter((array) config('webauthn.allowed_origins', []));
            if (! in_array($origin, $allowedOrigins, true)) {
                throw new OriginNotAllowedException;
            }

            // Verify challenge (compare base64url-encoded session challenge)
            $expectedChallenge = session()->has('webauthn_register_challenge')
                ? CredentialParser::base64url_encode(session('webauthn_register_challenge'))
                : null;
            if (! $expectedChallenge || ($clientData['challenge'] ?? null) !== $expectedChallenge) {
                throw new ChallengeMismatchException;
            }

            // Now parse attestation
            $attestationObject = CredentialParser::base64url_decode($data['response']['attestationObject'] ?? '');

            $decoder = new Decoder;
            $streamAtt = new StringStream($attestationObject);
            $cborAtt = $decoder->decode($streamAtt);
            $normalized = $cborAtt->normalize();
            $authData = $normalized['authData'] ?? null;

            if (! $authData) {
                throw new WebAuthnException('Invalid credential data', 'error_invalid_credential_data');
            }

            // rpIdHash and flags
            $rpId = (string) config('webauthn.rp_id');
            if (! CredentialParser::rpIdHashMatches($authData, $rpId)) {
                throw new WebAuthnException('RP ID hash mismatch', 'error_rp_id_mismatch');
            }
            if (! CredentialParser::isUserPresent($authData)) {
                throw new WebAuthnException('User not present', 'error_user_not_present');
            }
            if (config('webauthn.require_user_verification') && ! CredentialParser::isUserVerified($authData)) {
                throw new WebAuthnException('User not verified', 'error_user_not_verified');
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
                throw new WebAuthnException('Algorithm not allowed', 'error_algorithm_not_allowed');
            }

            if (WebAuthnKey::where('credentialId', $credentialId)->exists()) {
                throw new WebAuthnException('This key is already registered', 'error_key_already_registered');
            }

            $counter = CredentialParser::extractCounter($authData);
            $aaguid = CredentialParser::extractAAGUID($authData);

            $key = WebAuthnKey::create([
                'user_id' => $this->userId,
                'name' => $this->keyName,
                'credentialId' => $credentialId,
                'type' => $data['type'] ?? '',
                'transports' => json_encode($data['response']['transports'] ?? []),
                'attestationType' => base64_encode($attestationObject),
                'trustPath' => base64_encode(json_encode($data['response'] ?? [])),
                'aaguid' => $aaguid,
                'credentialPublicKey' => $publicKeyPem,
                'counter' => $counter,
            ]);

            // Clear rate limit on success
            WebAuthnRateLimiter::clear('register', $this->userId);

            // Audit log registration
            AuditLogger::logRegistration($this->userId, $this->keyName, $credentialId, $aaguid);

            $this->keys = WebAuthnKey::where('user_id', $this->userId)->get();
            // Invalidate registration challenge after successful registration
            session()->forget('webauthn_register_challenge');
            $this->closeModal();

            session()->flash('status', __('webauthn::webauthn.success_key_registered'));

        } catch (WebAuthnException $e) {
            AuditLogger::logError('registration', $e, [
                'user_id' => $this->userId,
                'key_name' => $this->keyName,
            ]);
            session()->flash('status', $e->getUserMessage());
        } catch (\Throwable $e) {
            AuditLogger::logError('registration', $e, [
                'user_id' => $this->userId,
                'key_name' => $this->keyName,
            ]);
            session()->flash('status', __('webauthn::webauthn.error_registration_failed'));
        }
    }

    public function deleteKey($id): void
    {
        $key = WebAuthnKey::find($id);
        if (! $key || $key->user_id !== $this->userId) {
            return;
        }

        $keyName = $key->name;
        $key->delete();

        // Audit log deletion
        AuditLogger::logKeyDeletion($this->userId, $id, $keyName);

        $this->keys = WebAuthnKey::where('user_id', $this->userId)->get();
        session()->flash('status', __('webauthn::webauthn.success_key_deleted'));
    }

    public function render(): View|Application
    {
        return view('webauthn::livewire.web-authn-register');
    }
}
