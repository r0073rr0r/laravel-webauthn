<?php

namespace r0073rr0r\WebAuthn\Helpers;

use CBOR\Decoder;
use CBOR\StringStream;
use Cose\Key\Key;

class CredentialParser
{
    public static function extractRpIdHash(string $authData): string
    {
        return substr($authData, 0, 32) ?: '';
    }

    public static function extractFlagsByte(string $authData): int
    {
        if (strlen($authData) < 33) return 0;
        return ord($authData[32]);
    }

    public static function isUserPresent(string $authData): bool
    {
        return (self::extractFlagsByte($authData) & 0x01) === 0x01;
    }

    public static function isUserVerified(string $authData): bool
    {
        return (self::extractFlagsByte($authData) & 0x04) === 0x04;
    }

    public static function rpIdHashMatches(string $authData, string $rpId): bool
    {
        $expected = hash('sha256', $rpId, true);
        return hash_equals(self::extractRpIdHash($authData), $expected);
    }
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
        
        // Check if asPEM() method exists (for compatibility with different versions)
        if (method_exists($coseKey, 'asPEM')) {
            return $coseKey->asPEM();
        }
        
        // Fallback: try toPEM() if asPEM() doesn't exist
        if (method_exists($coseKey, 'toPEM')) {
            return $coseKey->toPEM();
        }
        
        // If neither method exists, try to get PEM using get() method
        if (method_exists($coseKey, 'get')) {
            $data = $coseKey->get(-1); // -1 is the key type
            if (isset($data['pem'])) {
                return $data['pem'];
            }
        }
        
        throw new \RuntimeException('Unable to convert COSE key to PEM format. The Key object does not have asPEM(), toPEM(), or get() methods available.');
    }

    public static function extractCoseAlgorithm(string $cosePublicKey): ?int
    {
        $stream = new StringStream($cosePublicKey);
        $decoderCose = new Decoder;
        $cborCose = $decoderCose->decode($stream);
        $map = $cborCose->normalize();
        // Per COSE, key 3 => alg
        return isset($map[3]) ? (int) $map[3] : null;
    }
}
