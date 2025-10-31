<div>
    @if(count($keys) > 0)
        <x-button id="loginPasskey" class="mt-2">{{ __('webauthn.login_with_passkey') }}</x-button>
    @endif

    <script>
        function base64urlToBuffer(base64urlString) {
            let base64 = base64urlString.replace(/-/g, '+').replace(/_/g, '/');
            while (base64.length % 4) { base64 += '='; }
            const str = atob(base64);
            const buf = new Uint8Array(str.length);
            for (let i = 0; i < str.length; i++) { buf[i] = str.charCodeAt(i); }
            return buf;
        }

        document.getElementById('loginPasskey')?.addEventListener('click', async () => {
            const keys = @js(
                collect($keys)->map(fn($k) => [
                    'id' => rtrim(strtr(base64_encode($k->credentialId), '+/', '-_'), '='),
                    'type' => 'public-key',
                ])
            );

            const challengeBase64 = @js($challenge);

            if (!keys.length || !challengeBase64) return;

            try {
                const publicKey = {
                    challenge: base64urlToBuffer(challengeBase64),
                    allowCredentials: keys.map(k => ({
                        id: base64urlToBuffer(k.id),
                        type: k.type,
                    })),
                    timeout: 60000,
                    userVerification: 'preferred'
                };

                const credential = await navigator.credentials.get({ publicKey });
                @this.call('loginWithPasskey', JSON.stringify(credential));

            } catch (err) {
                console.error('Passkey login failed:', err);
            }
        });
    </script>
</div>
