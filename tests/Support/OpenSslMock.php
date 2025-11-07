<?php

namespace r0073rr0r\WebAuthn\Tests\Support;

class OpenSslMock
{
    public static int $returnCode = 0;

    // Mock resource identifier
    private static $mockResource = null;

    public static function setReturn(int $code): void
    {
        self::$returnCode = $code;
    }

    public static function verify($data, $signature, $key, $algo): int
    {
        return self::$returnCode;
    }

    public static function getPublicKey($public_key)
    {
        // Return a mock resource (just use a string identifier for testing)
        // In real OpenSSL, this would be a resource, but for tests we can use a simple identifier
        if (self::$mockResource === null) {
            self::$mockResource = 'mock_openssl_resource_'.uniqid();
        }

        return self::$mockResource;
    }
}
