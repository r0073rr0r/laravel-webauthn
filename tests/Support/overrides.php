<?php

namespace r0073rr0r\WebAuthn\Livewire;

// Namespaced override to make openssl_verify controllable in tests.
if (!function_exists(__NAMESPACE__ . '\\openssl_verify')) {
    function openssl_verify($data, $signature, $key, $algo)
    {
        return \r0073rr0r\WebAuthn\Tests\Support\OpenSslMock::verify($data, $signature, $key, $algo);
    }
}

// Override openssl_pkey_get_public for tests
if (!function_exists(__NAMESPACE__ . '\\openssl_pkey_get_public')) {
    function openssl_pkey_get_public($public_key)
    {
        return \r0073rr0r\WebAuthn\Tests\Support\OpenSslMock::getPublicKey($public_key);
    }
}

// Override openssl_free_key for tests
if (!function_exists(__NAMESPACE__ . '\\openssl_free_key')) {
    function openssl_free_key($key_identifier)
    {
        // No-op in tests
        return true;
    }
}


