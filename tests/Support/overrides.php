<?php

namespace r0073rr0r\WebAuthn\Livewire;

// Namespaced override to make openssl_verify controllable in tests.
if (!function_exists(__NAMESPACE__ . '\\openssl_verify')) {
    function openssl_verify($data, $signature, $key, $algo)
    {
        return \r0073rr0r\WebAuthn\Tests\Support\OpenSslMock::verify($data, $signature, $key, $algo);
    }
}


