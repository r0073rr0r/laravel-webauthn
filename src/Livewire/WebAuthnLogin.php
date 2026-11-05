<?php

namespace r0073rr0r\WebAuthn\Livewire;

use Illuminate\Support\Facades\Auth;
use Livewire\Attributes\Locked;
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
    /**
     * Base64url challenge for the next sign-in attempt. Read by the browser only;
     * the server always verifies against the copy stored in the session.
     */
    #[Locked]
    public string $challenge = '';

    /**
     * Message of the last failed attempt, shown under the button.
     */
    #[Locked]
    public string $error = '';

    protected $listeners = ['loginWithPasskey'];

    public function mount(): void
    {
        $this->challenge = $this->issueChallenge();
    }

    public function loginWithPasskey($credential)
    {
        // The session challenge is single-use: take it out now and hand the browser a new one,
        // so a failed or replayed assertion can never be checked against the same challenge twice.
        $expectedChallenge = session()->pull('webauthn_login_challenge');
        $this->challenge = $this->issueChallenge();
        $this->error = '';

        $data = json_decode((string) $credential, true);
        $credentialId = CredentialParser::base64url_decode(is_array($data) ? (string) ($data['id'] ?? '') : '');

        try {
            // Per-IP limit before any lookup, so unknown credential IDs can't be probed endlessly
            WebAuthnRateLimiter::check('login');
        } catch (WebAuthnException $e) {
            $this->error = $e->getUserMessage();

            return;
        }

        $key = $credentialId === '' ? null : WebAuthnKey::where('credentialId', $credentialId)->first();

        if (! $key) {
            $exception = new InvalidCredentialException;
            AuditLogger::logLogin(0, $credentialId, false);
            $this->error = $exception->getUserMessage();

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

            // Challenge must match the one issued to this session
            if (! is_string($expectedChallenge) || $expectedChallenge === ''
                || ! is_string($clientData['challenge'] ?? null)
                || ! hash_equals(CredentialParser::base64url_encode($expectedChallenge), $clientData['challenge'])) {
                throw new ChallengeMismatchException;
            }

            // Verify type and origin
            if (($clientData['type'] ?? '') !== 'webauthn.get') {
                throw new WebAuthnException('Invalid clientData type', 'error_invalid_type');
            }

            $origin = $clientData['origin'] ?? '';
            $allowedOrigins = array_filter((array) config('webauthn.allowed_origins', []));
            if (! in_array($origin, $allowedOrigins, true)) {
                throw new OriginNotAllowedException;
            }

            // A discoverable credential reports the user handle set at registration; it must belong to the key owner
            $userHandle = CredentialParser::base64url_decode((string) ($data['response']['userHandle'] ?? ''));
            if ($userHandle !== '' && ! hash_equals((string) $key->user_id, $userHandle)) {
                throw new InvalidCredentialException;
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

            $ok = openssl_verify($signedData, $signature, $publicKeyResource, CredentialParser::signatureAlgorithm($publicKeyResource));
            openssl_free_key($publicKeyResource);

            if ($ok !== 1) {
                throw new InvalidSignatureException;
            }

            // Signature counter must grow, unless the authenticator doesn't keep one (both zero)
            $signCount = CredentialParser::extractCounter($authenticatorData);
            if (($signCount !== 0 || (int) $key->counter !== 0) && $signCount <= (int) $key->counter) {
                throw new ReplayAttackException;
            }

            $key->counter = $signCount;
            $key->save();

            Auth::login($key->user);
            session()->regenerate();

            // Clear rate limit on success
            WebAuthnRateLimiter::clear('login', $key->user_id);
            WebAuthnRateLimiter::clear('login');

            // Audit log success
            AuditLogger::logLogin($key->user_id, $credentialId, true);

            session()->flash('status', __('webauthn::webauthn.success_login'));

            return redirect()->intended('/');

        } catch (WebAuthnException $e) {
            AuditLogger::logError('login', $e, [
                'user_id' => $key->user_id ?? null,
                'credential_id' => bin2hex($credentialId),
            ]);
            $this->error = $e->getUserMessage();

            return;
        } catch (\Throwable $e) {
            AuditLogger::logError('login', $e, [
                'user_id' => $key->user_id ?? null,
                'credential_id' => bin2hex($credentialId),
            ]);
            $this->error = __('webauthn::webauthn.error_login_failed');

            return;
        }
    }

    public function render()
    {
        return view('webauthn::livewire.web-authn-login');
    }

    private function issueChallenge(): string
    {
        $challenge = random_bytes(32);
        session(['webauthn_login_challenge' => $challenge]);

        return CredentialParser::base64url_encode($challenge);
    }
}
