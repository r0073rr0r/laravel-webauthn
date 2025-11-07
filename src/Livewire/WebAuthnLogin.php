<?php

namespace r0073rr0r\WebAuthn\Livewire;

use Illuminate\Support\Facades\Auth;
use Livewire\Component;
use r0073rr0r\WebAuthn\Exceptions\ChallengeMismatchException;
use r0073rr0r\WebAuthn\Exceptions\InvalidCredentialException;
use r0073rr0r\WebAuthn\Exceptions\InvalidSignatureException;
use r0073rr0r\WebAuthn\Exceptions\OriginNotAllowedException;
use r0073rr0r\WebAuthn\Exceptions\ReplayAttackException;
use r0073rr0r\WebAuthn\Exceptions\WebAuthnException;
use r0073rr0r\WebAuthn\Helpers\AuditLogger;
use r0073rr0r\WebAuthn\Helpers\CredentialParser;
use r0073rr0r\WebAuthn\Helpers\WebAuthnRateLimiter;
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
            $exception = new InvalidCredentialException;
            AuditLogger::logLogin(0, $credentialId, false);
            session()->flash('status', $exception->getUserMessage());

            return;
        }

        try {
            // Rate limiting
            WebAuthnRateLimiter::check('login', $key->user_id);

            $clientDataJSON = CredentialParser::base64url_decode($data['response']['clientDataJSON'] ?? '');
            $authenticatorData = CredentialParser::base64url_decode($data['response']['authenticatorData'] ?? '');
            $signature = CredentialParser::base64url_decode($data['response']['signature'] ?? '');

            if (empty($clientDataJSON)) {
                throw new WebAuthnException('Invalid client data', 'error_invalid_client_data');
            }

            $clientData = json_decode($clientDataJSON, true);
            if (! $clientData) {
                throw new WebAuthnException('Invalid client data', 'error_invalid_client_data');
            }

            $expectedChallenge = $this->challenge;

            // One-time challenge: must match then invalidate
            if (! isset($clientData['challenge']) || $clientData['challenge'] !== $expectedChallenge) {
                throw new ChallengeMismatchException;
            }
            session()->forget('webauthn_login_challenge');

            // Verify type and origin
            if (($clientData['type'] ?? '') !== 'webauthn.get') {
                throw new WebAuthnException('Invalid clientData type', 'error_invalid_type');
            }

            $origin = $clientData['origin'] ?? '';
            $allowedOrigins = array_filter((array) config('webauthn.allowed_origins', []));
            if (! in_array($origin, $allowedOrigins, true)) {
                throw new OriginNotAllowedException;
            }

            // rpIdHash must match configured rp_id
            $rpId = (string) config('webauthn.rp_id');
            if (! CredentialParser::rpIdHashMatches($authenticatorData, $rpId)) {
                throw new WebAuthnException('RP ID hash mismatch', 'error_rp_id_mismatch');
            }

            // Flags: require user present; optionally require user verified
            if (! CredentialParser::isUserPresent($authenticatorData)) {
                throw new WebAuthnException('User not present', 'error_user_not_present');
            }
            if (config('webauthn.require_user_verification') && ! CredentialParser::isUserVerified($authenticatorData)) {
                throw new WebAuthnException('User not verified', 'error_user_not_verified');
            }

            $clientDataHash = hash('sha256', $clientDataJSON, true);
            $signedData = $authenticatorData.$clientDataHash;

            // Get public key resource from PEM
            $publicKeyResource = openssl_pkey_get_public($key->credentialPublicKey);
            if ($publicKeyResource === false) {
                $errors = [];
                while (($error = openssl_error_string()) !== false) {
                    $errors[] = $error;
                }
                throw new WebAuthnException('Invalid public key format: '.implode('; ', $errors), 'error_invalid_public_key');
            }

            $ok = openssl_verify($signedData, $signature, $publicKeyResource, OPENSSL_ALGO_SHA256);
            openssl_free_key($publicKeyResource);

            if ($ok !== 1) {
                throw new InvalidSignatureException;
            }

            $signCount = unpack('N', substr($authenticatorData, 33, 4))[1];
            if ($signCount < $key->counter) {
                throw new ReplayAttackException;
            }

            $key->counter = $signCount;
            $key->save();

            Auth::login($key->user);

            // Clear rate limit on success
            WebAuthnRateLimiter::clear('login', $key->user_id);

            // Audit log success
            AuditLogger::logLogin($key->user_id, $credentialId, true);

            session()->flash('status', __('webauthn::webauthn.success_login'));

            return redirect()->intended('/');

        } catch (WebAuthnException $e) {
            AuditLogger::logError('login', $e, [
                'user_id' => $key->user_id ?? null,
                'credential_id' => bin2hex($credentialId),
            ]);
            session()->flash('status', $e->getUserMessage());

            return;
        } catch (\Throwable $e) {
            AuditLogger::logError('login', $e, [
                'user_id' => $key->user_id ?? null,
                'credential_id' => bin2hex($credentialId),
            ]);
            session()->flash('status', __('webauthn::webauthn.error_login_failed'));

            return;
        }
    }

    public function render()
    {
        return view('webauthn::livewire.web-authn-login');
    }
}
