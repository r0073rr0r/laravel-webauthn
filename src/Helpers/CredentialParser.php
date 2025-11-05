<?php

namespace r0073rr0r\WebAuthn\Helpers;

use CBOR\Decoder;
use CBOR\StringStream;
use Cose\Key\Key;

class CredentialParser
{
    public static function extractCounter(string $authData): int
    {
        if (strlen($authData) < 37) return 0;
        $counterBytes = substr($authData, 33, 4);
        return strlen($counterBytes) === 4 ? unpack('N', $counterBytes)[1] : 0;
    }

    public static function extractAAGUID(string $authData): string
    {
        return bin2hex(substr($authData, 37, 16));
    }

    public static function base64url_decode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) $data .= str_repeat('=', 4 - $remainder);
        return base64_decode(strtr($data, '-_', '+/'));
    }

    public static function base64url_encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function convertCoseToPem(string $cosePublicKey): string
    {
        $stream = new StringStream($cosePublicKey);
        $decoderCose = new Decoder;
        $cborCose = $decoderCose->decode($stream);
        $coseKey = Key::createFromData($cborCose->normalize());
        return $coseKey->asPEM();
    }
}
