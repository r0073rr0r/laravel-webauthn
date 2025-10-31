<div>
    @if(count($keys) > 0)
        <x-button id="loginPasskey" class="mt-2">{{__('default.login_with_passkey')}}</x-button>
    @endif

    <script>
        function base64urlToBuffer(base64urlString) {
            if (!base64urlString || typeof base64urlString !== 'string') {
                throw new Error('Invalid base64url input: ' + base64urlString);
            }

            let base64 = base64urlString.replace(/-/g, '+').replace(/_/g, '/');
            while (base64.length % 4) {
                base64 += '=';
            }

            const str = atob(base64);
            const buf = new Uint8Array(str.length);

            for (let i = 0; i < str.length; i++) {
                buf[i] = str.charCodeAt(i);
            }

            return buf;
        }

        document.getElementById('loginPasskey')?.addEventListener('click', async () => {
            const keys = @js(
    collect($keys)
        ->filter(fn($k) => $k->credentialId)
        ->map(fn($k) => [
            'type' => 'public-key',
            'id' => rtrim(strtr($k->credentialId, '+/', '-_'), '=')
        ])
);

            if (!keys.length) {
                Livewire.dispatch('notify', {
                    type: 'error',
                    message: 'No valid keys for login'
                });
                return;
            }

            const challengeBase64 = @js($challenge);
            if (!challengeBase64) {
                Livewire.dispatch('notify', {
                    type: 'error',
                    message: 'Authentication challenge not available. Please refresh the page.'
                });
                return;
            }

            try {
                const publicKey = {
                    challenge: base64urlToBuffer(challengeBase64),
                    allowCredentials: keys.map(k => ({
                        id: base64urlToBuffer(k.id),
                        type: k.type,
                    })),
                    timeout: 60000,
                    userVerification: 'preferred',
                };

                const credential = await navigator.credentials.get({publicKey});
                //@formatter:off
                @this.call('loginWithPasskey', JSON.stringify(credential));
            } catch (err) {
                console.error('Passkey login failed:', err);
            }
        });
    </script>
</div>
