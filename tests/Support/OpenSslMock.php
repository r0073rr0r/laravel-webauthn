<?php

namespace r0073rr0r\WebAuthn\Tests\Support;

class OpenSslMock
{
    public static int $returnCode = 0;

    public static function setReturn(int $code): void
    {
        self::$returnCode = $code;
    }

    public static function verify($data, $signature, $key, $algo): int
    {
        return self::$returnCode;
    }
}


