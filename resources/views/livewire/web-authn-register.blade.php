<div>
    <x-webauthn::form-webauthn-section>
        <x-slot name="title">{{__('webauthn.registered_security_keys')}}</x-slot>
        <x-slot name="description">
            {{ __('webauthn.webauthn_add_passkey') }}
            {{ __('webauthn.webauthn_setup_passkey') }}
        </x-slot>

        <x-slot name="form">
            <table class="min-w-full divide-y divide-gray-200 border">
                <thead class="bg-gray-50">
                <tr>
                    <th class="px-6 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider text-center">
                        {{__('webauthn.Name')}}
                    </th>
                    <th class="px-6 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider text-center">
                        {{__('webauthn.Actions')}}
                    </th>
                </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">
                @forelse($keys as $key)
                    <tr>
                        <td class="px-6 py-4 whitespace-nowrap text-center">{{ $key->name }}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 text-center">
                            <x-danger-button wire:click="deleteKey({{ $key->id }})"
                                             wire:confirm="{{ __('webauthn.delete_key_confirm') }}"
                                             class="bg-red-500 hover:bg-red-600 text-white px-3 py-1 rounded">
                                {{__('webauthn.Delete')}}
                            </x-danger-button>
                        </td>
                    </tr>
                @empty
                    <tr>
                        <td colspan="3" class="px-6 py-4 text-center text-gray-500">
                            {{__('webauthn.no_keys_registered')}}
                        </td>
                    </tr>
                @endforelse
                </tbody>
            </table>
        </x-slot>

        <x-slot name="actions">
            <x-button wire:click="openModal">{{__('webauthn.webauthn_register_key')}}</x-button>
        </x-slot>
    </x-webauthn::form-webauthn-section>

    @if($showModal)
        <div class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50 flex items-center justify-center">
            <div class="relative p-5 border w-96 shadow-lg rounded-md bg-white">
                <h3 class="text-lg font-medium text-gray-900">{{__('webauthn.webauthn_name_your_key')}}</h3>
                <input type="text" wire:model="keyName"
                       placeholder="{{__('webauthn.webauthn_key_name_placeholder')}}"
                       class="mt-2 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50 px-3 py-2">
                <div class="mt-4 flex justify-end">
                    <x-secondary-button wire:click="closeModal" class="mr-2">{{__('webauthn.Cancel')}}</x-secondary-button>
                    <x-button onclick="startRegistration()" class="px-4 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600">
                        {{__('webauthn.Register')}}
                    </x-button>
                </div>
            </div>
        </div>
    @endif

    <script>
        function base64urlToBuffer(base64urlString) {
            let base64 = base64urlString.replace(/-/g, '+').replace(/_/g, '/');
            while (base64.length % 4) base64 += '=';
            const str = atob(base64);
            const buf = new Uint8Array(str.length);
            for (let i = 0; i < str.length; i++) buf[i] = str.charCodeAt(i);
            return buf;
        }

        async function startRegistration() {
            const publicKey = @js($creationOptions);
            publicKey.challenge = base64urlToBuffer(publicKey.challenge);
            publicKey.user.id = base64urlToBuffer(publicKey.user.id);

            try {
                const credential = await navigator.credentials.create({publicKey});
                const credentialData = {
                    id: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                    type: credential.type,
                    response: {
                        attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject))),
                        clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                        transports: credential.response.getTransports ? credential.response.getTransports() : []
                    }
                };
                @this.call('registerKey', JSON.stringify(credentialData));
            } catch (error) {
                console.error('Registration failed:', error);
                alert('Registration failed: ' + error.message);
                @this.call('closeModal');
            }
        }
    </script>
</div>
