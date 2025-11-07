<?php

namespace r0073rr0r\WebAuthn\Tests\Support;

use CBOR\Encoder;

/**
 * Helper class to generate test COSE key data for different key types
 */
class CoseKeyGenerator
{
    /**
     * Generate EC2 P-256 (ES256) COSE key as normalized array (for direct use in tests)
     * This returns the array format that convertCoseToPem expects after CBOR decoding
     */
    public static function generateEc2P256Array(): array
    {
        // EC2 P-256 key structure:
        // kty: 2 (EC2)
        // alg: -7 (ES256)
        // crv: 1 (P-256)
        // x: 32 bytes
        // y: 32 bytes

        $x = random_bytes(32);
        $y = random_bytes(32);

        return [
            1 => 2,      // kty: EC2
            3 => -7,     // alg: ES256
            -1 => 2,     // kty (alternative)
            -2 => 1,     // crv: P-256
            -3 => $x,    // x coordinate
            -4 => $y,    // y coordinate
        ];
    }

    /**
     * Generate EC2 P-256 (ES256) COSE key as CBOR binary string
     */
    public static function generateEc2P256(): string
    {
        $keyData = self::generateEc2P256Array();

        return self::encodeCoseKey($keyData);
    }

    /**
     * Generate EC2 P-384 (ES384) COSE key
     */
    public static function generateEc2P384(): string
    {
        $x = random_bytes(48);
        $y = random_bytes(48);

        $coseKey = [
            1 => 2,      // kty: EC2
            3 => -35,    // alg: ES384
            -1 => 2,     // kty (alternative)
            -2 => 2,     // crv: P-384
            -3 => $x,    // x coordinate
            -4 => $y,    // y coordinate
        ];

        return self::encodeCoseKey($coseKey);
    }

    /**
     * Generate EC2 P-521 (ES512) COSE key
     */
    public static function generateEc2P521(): string
    {
        $x = random_bytes(66);
        $y = random_bytes(66);

        $coseKey = [
            1 => 2,      // kty: EC2
            3 => -36,    // alg: ES512
            -1 => 2,     // kty (alternative)
            -2 => 3,     // crv: P-521
            -3 => $x,    // x coordinate
            -4 => $y,    // y coordinate
        ];

        return self::encodeCoseKey($coseKey);
    }

    /**
     * Generate RSA (RS256) COSE key as normalized array
     */
    public static function generateRsaArray(): array
    {
        // RSA key structure:
        // kty: 3 (RSA)
        // alg: -257 (RS256)
        // n: modulus (256 bytes for 2048-bit key)
        // e: exponent (usually 65537 = 0x010001)

        $n = random_bytes(256); // 2048-bit modulus
        $e = "\x01\x00\x01"; // 65537 in big-endian

        return [
            1 => 3,      // kty: RSA
            3 => -257,   // alg: RS256
            -1 => 3,     // kty (alternative)
            -2 => $n,    // n: modulus
            -3 => $e,    // e: exponent
        ];
    }

    /**
     * Generate RSA (RS256) COSE key as CBOR binary string
     */
    public static function generateRsa(): string
    {
        $keyData = self::generateRsaArray();

        return self::encodeCoseKey($keyData);
    }

    /**
     * Encode COSE key to CBOR binary format
     */
    private static function encodeCoseKey(array $keyData): string
    {
        // Use CBOR Encoder to encode the key data
        $encoder = new Encoder;
        $encoded = $encoder->encode($keyData);

        // The encoded value should be a CBOR object that can be converted to string
        if (method_exists($encoded, '__toString')) {
            return $encoded->__toString();
        }

        // Fallback: try to get binary representation
        if (method_exists($encoded, 'getValue')) {
            return $encoded->getValue();
        }

        // Last resort: serialize and encode
        return serialize($keyData);
    }

    /**
     * Generate authenticator data with COSE public key embedded
     */
    public static function generateAuthDataWithKey(string $cosePublicKey, int $counter = 0): string
    {
        // rpIdHash (32 bytes)
        $rpIdHash = hash('sha256', config('webauthn.rp_id'), true);

        // Flags: UP=1, UV=0x04
        $flags = chr(0x01 | 0x04);

        // Sign count (4 bytes)
        $signCount = pack('N', $counter);

        // AAGUID (16 bytes)
        $aaguid = random_bytes(16);

        // Credential ID length (2 bytes)
        $credentialId = random_bytes(16);
        $credIdLen = pack('n', strlen($credentialId));

        // Credential ID (16 bytes) + COSE public key
        $credentialData = $aaguid.$credIdLen.$credentialId.$cosePublicKey;

        // Authenticator data = rpIdHash + flags + signCount + credentialData
        return $rpIdHash.$flags.$signCount.$credentialData;
    }
}
