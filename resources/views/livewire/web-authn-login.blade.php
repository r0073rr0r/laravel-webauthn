<div>
    <script>
        window.webauthnLogin = (wire) => ({
            busy: false,
            error: '',
            supported: !!(window.PublicKeyCredential && navigator.credentials),

            toBuffer(value) {
                let base64 = value.replace(/-/g, '+').replace(/_/g, '/');
                while (base64.length % 4) { base64 += '='; }
                return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
            },

            toBase64url(buffer) {
                if (!buffer) { return ''; }
                const bytes = new Uint8Array(buffer);
                let binary = '';
                for (let i = 0; i < bytes.length; i++) { binary += String.fromCharCode(bytes[i]); }
                return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
            },

            async login() {
                this.error = '';
                this.busy = true;

                try {
                    // Empty allowCredentials: the browser offers the passkeys it holds for this site,
                    // so the page never has to reveal which credentials exist.
                    const credential = await navigator.credentials.get({
                        publicKey: {
                            challenge: this.toBuffer(wire.challenge),
                            allowCredentials: [],
                            timeout: @js((int) config('webauthn.timeout', 60000)),
                            userVerification: 'preferred',
                        },
                    });

                    await wire.loginWithPasskey(JSON.stringify({
                        id: credential.id,
                        rawId: this.toBase64url(credential.rawId),
                        type: credential.type,
                        response: {
                            clientDataJSON: this.toBase64url(credential.response.clientDataJSON),
                            authenticatorData: this.toBase64url(credential.response.authenticatorData),
                            signature: this.toBase64url(credential.response.signature),
                            userHandle: this.toBase64url(credential.response.userHandle),
                        },
                    }));
                } catch (e) {
                    this.error = @js(__('webauthn::webauthn.error_passkey_cancelled'));
                } finally {
                    this.busy = false;
                }
            },
        });
    </script>

    <div x-data="webauthnLogin($wire)" x-show="supported" x-cloak>
        <x-button type="button" class="mt-2" x-on:click="login()" x-bind:disabled="busy">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" aria-hidden="true" class="me-2 h-4 w-4">
                <path stroke-linecap="round" stroke-linejoin="round" d="M7.864 4.243A7.5 7.5 0 0 1 19.5 10.5c0 2.92-.556 5.709-1.568 8.268M5.742 6.364A7.465 7.465 0 0 0 4.5 10.5a7.464 7.464 0 0 1-1.15 3.993m1.989 3.559A11.209 11.209 0 0 0 8.25 10.5a3.75 3.75 0 1 1 7.5 0c0 .527-.021 1.049-.064 1.565M12 10.5a14.94 14.94 0 0 1-3.6 9.75m6.633-4.596a18.666 18.666 0 0 1-2.485 5.33" />
            </svg>
            <span x-show="!busy">{{ __('webauthn::webauthn.login_with_passkey') }}</span>
            <span x-show="busy">{{ __('webauthn::webauthn.passkey_signing_in') }}</span>
        </x-button>

        @if ($error)
            <p class="mt-2 text-sm text-red-600 dark:text-red-400">{{ $error }}</p>
        @endif
        <p x-show="error" x-text="error" class="mt-2 text-sm text-red-600 dark:text-red-400"></p>
    </div>
</div>
