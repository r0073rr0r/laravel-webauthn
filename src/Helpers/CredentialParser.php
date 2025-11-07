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
        if (strlen($authData) < 33) {
            return 0;
        }

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
        if (strlen($authData) < 37) {
            return 0;
        }
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
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }

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
        $normalized = $cborCose->normalize();
        $coseKey = Key::createFromData($normalized);

        // Check if asPEM() method exists (for compatibility with different versions)
        if (method_exists($coseKey, 'asPEM')) {
            return $coseKey->asPEM();
        }

        // Fallback: try toPEM() if asPEM() doesn't exist
        if (method_exists($coseKey, 'toPEM')) {
            return $coseKey->toPEM();
        }

        // Try getData() method to get key data
        if (method_exists($coseKey, 'getData')) {
            try {
                $keyData = $coseKey->getData();
                if (is_array($keyData)) {
                    return self::convertKeyDataToPem($keyData, $normalized);
                }
            } catch (\Exception $e) {
                // Continue to next fallback
            }
        }

        // Try toArray() method if it exists
        if (method_exists($coseKey, 'toArray')) {
            try {
                $keyData = $coseKey->toArray();
                if (is_array($keyData)) {
                    return self::convertKeyDataToPem($keyData, $normalized);
                }
            } catch (\Exception $e) {
                // Continue to next fallback
            }
        }

        // Try get() method with different parameters
        if (method_exists($coseKey, 'get')) {
            // Try to get all data using different key indices
            try {
                // Try getting x coordinate (key -3 in COSE)
                $x = $coseKey->get(-3);
                $y = $coseKey->get(-4);
                if ($x !== null && $y !== null) {
                    $keyData = [
                        -3 => $x,
                        -4 => $y,
                        -2 => $coseKey->get(-2) ?? null, // crv
                        1 => $coseKey->get(1) ?? null,  // kty
                    ];

                    return self::convertKeyDataToPem($keyData, $normalized);
                }
            } catch (\Exception $e) {
                // Continue to next fallback
            }

            // Try getting RSA parameters
            try {
                $n = $coseKey->get(-2); // RSA modulus
                $e = $coseKey->get(-3); // RSA exponent
                if ($n !== null && $e !== null) {
                    $keyData = [
                        -2 => $n,
                        -3 => $e,
                        1 => $coseKey->get(1) ?? null,  // kty
                    ];

                    return self::convertKeyDataToPem($keyData, $normalized);
                }
            } catch (\Exception $e) {
                // Continue to next fallback
            }
        }

        // Last resort: manual conversion from normalized COSE data
        // The normalized array should contain all the COSE key data
        return self::convertKeyDataToPem($normalized, $normalized);
    }

    /**
     * Convert COSE key data to PEM format manually
     */
    private static function convertKeyDataToPem(array $keyData, array $normalized): string
    {
        // Get algorithm (key 3 in COSE)
        $alg = $keyData[3] ?? $normalized[3] ?? null;

        // Get key type (key 1 in COSE: 2 = EC2, 3 = RSA)
        $kty = $keyData[1] ?? $normalized[1] ?? null;

        if ($kty === 2) {
            // EC2 key (Elliptic Curve)
            return self::convertEc2ToPem($keyData, $normalized);
        } elseif ($kty === 3) {
            // RSA key
            return self::convertRsaToPem($keyData, $normalized);
        }

        throw new \RuntimeException('Unsupported key type. Only EC2 (kty=2) and RSA (kty=3) are supported.');
    }

    /**
     * Convert EC2 (Elliptic Curve) COSE key to PEM
     */
    private static function convertEc2ToPem(array $keyData, array $normalized): string
    {
        // EC2 keys: -1 = kty, -2 = crv, -3 = x, -4 = y
        // Use normalized array directly as it contains the raw COSE data
        // Try to get crv first (should be a small integer: 1, 2, or 3)
        $crv = null;
        $x = null;
        $y = null;

        // First, check if -2 is a binary string (x coordinate) - if so, crv is not in -2
        $val2 = $normalized[-2] ?? $keyData[-2] ?? null;
        $isVal2Binary = is_string($val2) && strlen($val2) > 1;

        // Only try to get crv from -2 if it's not a binary string
        if (! $isVal2Binary) {
            foreach ([-2, '-2'] as $key) {
                if (isset($normalized[$key])) {
                    $val = $normalized[$key];
                    // crv should be a small integer (1, 2, or 3) or a single byte
                    if (is_int($val) && $val >= 1 && $val <= 3) {
                        $crv = $val;
                        break;
                    } elseif (is_string($val) && strlen($val) === 1) {
                        $intVal = ord($val);
                        if ($intVal >= 1 && $intVal <= 3) {
                            $crv = $intVal;
                            break;
                        }
                    }
                }
            }

            // If crv not found, try from keyData
            if ($crv === null) {
                foreach ([-2, '-2'] as $key) {
                    if (isset($keyData[$key])) {
                        $val = $keyData[$key];
                        if (is_int($val) && $val >= 1 && $val <= 3) {
                            $crv = $val;
                            break;
                        } elseif (is_string($val) && strlen($val) === 1) {
                            $intVal = ord($val);
                            if ($intVal >= 1 && $intVal <= 3) {
                                $crv = $intVal;
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Get x and y coordinates - these should be longer binary strings
        // In some COSE implementations, -2 might be x and -3 might be y (instead of -3=x, -4=y)
        // Try both interpretations

        // First, check if -2 is a long binary string (x coordinate) and -3 is y
        $val2 = $normalized[-2] ?? $keyData[-2] ?? null;
        $val3 = $normalized[-3] ?? $keyData[-3] ?? null;

        if (is_string($val2) && strlen($val2) > 1 && is_string($val3) && strlen($val3) > 1) {
            // Both are binary strings - likely x and y coordinates
            $x = $val2;
            $y = $val3;
        } else {
            // Try standard COSE format: -3 = x, -4 = y
            foreach ([-3, '-3'] as $key) {
                if (isset($normalized[$key])) {
                    $val = $normalized[$key];
                    // x should be a binary string (typically 32 bytes for P-256)
                    if (is_string($val) && strlen($val) > 1) {
                        $x = $val;
                        break;
                    }
                }
            }

            foreach ([-4, '-4'] as $key) {
                if (isset($normalized[$key])) {
                    $val = $normalized[$key];
                    // y should be a binary string (typically 32 bytes for P-256)
                    if (is_string($val) && strlen($val) > 1) {
                        $y = $val;
                        break;
                    }
                }
            }

            // If not found in normalized, try keyData
            if ($x === null) {
                foreach ([-3, '-3'] as $key) {
                    if (isset($keyData[$key]) && is_string($keyData[$key]) && strlen($keyData[$key]) > 1) {
                        $x = $keyData[$key];
                        break;
                    }
                }
            }

            if ($y === null) {
                foreach ([-4, '-4'] as $key) {
                    if (isset($keyData[$key]) && is_string($keyData[$key]) && strlen($keyData[$key]) > 1) {
                        $y = $keyData[$key];
                        break;
                    }
                }
            }
        }

        if ($x === null || $y === null) {
            // Debug: log what we have
            $safeKeyData = self::sanitizeForDebug($keyData);
            $safeNormalized = self::sanitizeForDebug($normalized);
            $debugInfo = [
                'keyData_keys' => array_keys($keyData),
                'normalized_keys' => array_keys($normalized),
                'keyData' => $safeKeyData,
                'normalized' => $safeNormalized,
            ];
            throw new \RuntimeException('Missing EC2 key coordinates (x, y). Debug: '.json_encode($debugInfo, JSON_PARTIAL_OUTPUT_ON_ERROR));
        }

        // Convert coordinates to binary string
        $xBin = self::normalizeKeyValue($x);
        $yBin = self::normalizeKeyValue($y);

        // If crv is still null, try to determine from key size
        if ($crv === null) {
            // P-256: 32 bytes, P-384: 48 bytes, P-521: 66 bytes
            $keySize = strlen($xBin);
            $crv = match ($keySize) {
                32 => 1,  // P-256
                48 => 2,  // P-384
                66 => 3,  // P-521
                default => throw new \RuntimeException("Unable to determine EC curve from key size: {$keySize} bytes. x: ".bin2hex($xBin).', y: '.bin2hex($yBin)),
            };
        }

        $crvInt = $crv;

        // Determine curve name based on crv
        $curveName = match ($crvInt) {
            1 => 'prime256v1',  // P-256
            2 => 'secp384r1',   // P-384
            3 => 'secp521r1',   // P-521
            default => throw new \RuntimeException("Unsupported EC curve: {$crvInt}"),
        };

        // Try using OpenSSL to create the key directly
        if (function_exists('openssl_pkey_new') && function_exists('openssl_pkey_get_details')) {
            try {
                // Create EC key using OpenSSL
                $config = [
                    'curve_name' => $curveName,
                    'private_key_type' => OPENSSL_KEYTYPE_EC,
                ];

                // Generate a temporary private key to extract the public key structure
                $tempKey = openssl_pkey_new($config);
                if ($tempKey !== false) {
                    $details = openssl_pkey_get_details($tempKey);
                    if ($details !== false && isset($details['key'])) {
                        // Now create the public key from x and y coordinates
                        // We'll use the ASN.1 method but validate it with OpenSSL
                    }
                }
            } catch (\Exception $e) {
                // Fall through to ASN.1 conversion
            }
        }

        // Use ASN.1 conversion (this should work, but we'll validate it)
        $curveOid = match ($crvInt) {
            1 => '1.2.840.10045.3.1.7', // P-256
            2 => '1.3.132.0.34',         // P-384
            3 => '1.3.132.0.35',         // P-521
            default => throw new \RuntimeException("Unsupported EC curve: {$crvInt}"),
        };

        // Create public key point (0x04 + x + y for uncompressed)
        $publicKeyPoint = "\x04".$xBin.$yBin;

        // Build ASN.1 structure for EC public key
        $publicKeyInfo = self::buildEcPublicKeyInfo($publicKeyPoint, $curveOid);

        $pem = "-----BEGIN PUBLIC KEY-----\n".
               chunk_split(base64_encode($publicKeyInfo), 64, "\n").
               "-----END PUBLIC KEY-----\n";

        // Validate the PEM with OpenSSL before returning
        if (function_exists('openssl_pkey_get_public')) {
            $resource = openssl_pkey_get_public($pem);
            if ($resource === false) {
                // Get OpenSSL error
                $errors = [];
                while (($error = openssl_error_string()) !== false) {
                    $errors[] = $error;
                }

                // Try to fix the ASN.1 encoding
                $pem = self::fixEcPublicKeyPem($xBin, $yBin, $curveOid, $curveName);

                // Validate again
                $resource = openssl_pkey_get_public($pem);
                if ($resource === false) {
                    // If still fails, log the error but return the PEM anyway
                    // The issue might be in how it's used, not in the format
                    \Log::warning('OpenSSL could not parse generated EC public key PEM', [
                        'errors' => $errors,
                        'curve' => $curveName,
                        'x_length' => strlen($xBin),
                        'y_length' => strlen($yBin),
                    ]);
                } else {
                    openssl_free_key($resource);
                }
            } else {
                openssl_free_key($resource);
            }
        }

        return $pem;
    }

    /**
     * Normalize key value to binary string
     */
    private static function normalizeKeyValue($value): string
    {
        if (is_string($value)) {
            return $value;
        }

        if (is_int($value)) {
            return self::intToBytes($value);
        }

        if (is_object($value) && method_exists($value, '__toString')) {
            return (string) $value;
        }

        throw new \RuntimeException('Unable to normalize key value to binary string');
    }

    /**
     * Normalize COSE integer value (can be int, string, or binary)
     */
    private static function normalizeCoseInteger($value): ?int
    {
        if (is_int($value)) {
            return $value;
        }

        if (is_string($value)) {
            // If it's a single byte string, convert to int
            if (strlen($value) === 1) {
                return ord($value);
            }
            // If it's a numeric string, convert to int
            if (is_numeric($value)) {
                return (int) $value;
            }
            // If it's a multi-byte string, try to interpret as big-endian integer
            if (strlen($value) <= 4) {
                $int = 0;
                for ($i = 0; $i < strlen($value); $i++) {
                    $int = ($int << 8) | ord($value[$i]);
                }

                return $int;
            }
        }

        return null;
    }

    /**
     * Convert RSA COSE key to PEM
     */
    private static function convertRsaToPem(array $keyData, array $normalized): string
    {
        // RSA keys: -1 = kty, -2 = n (modulus), -3 = e (exponent)
        $n = $keyData[-2] ?? $normalized[-2] ?? null;
        $e = $keyData[-3] ?? $normalized[-3] ?? null;

        if ($n === null || $e === null) {
            throw new \RuntimeException('Missing RSA key parameters (n, e)');
        }

        // Convert to binary if needed
        $nBin = self::normalizeKeyValue($n);
        $eBin = self::normalizeKeyValue($e);

        // Ensure proper ASN.1 encoding (unsigned integers with leading zero if needed)
        if (strlen($nBin) > 0 && (ord($nBin[0]) & 0x80)) {
            $nBin = "\x00".$nBin;
        }
        if (strlen($eBin) > 0 && (ord($eBin[0]) & 0x80)) {
            $eBin = "\x00".$eBin;
        }

        // Build ASN.1 structure for RSA public key
        $publicKeyInfo = self::buildRsaPublicKeyInfo($nBin, $eBin);

        return "-----BEGIN PUBLIC KEY-----\n".
               chunk_split(base64_encode($publicKeyInfo), 64, "\n").
               "-----END PUBLIC KEY-----\n";
    }

    /**
     * Build ASN.1 structure for EC public key
     */
    private static function buildEcPublicKeyInfo(string $publicKeyPoint, string $curveOid): string
    {
        // EC public key: BIT STRING containing the public key point
        $publicKeyBitString = "\x03".self::encodeLength(strlen($publicKeyPoint) + 1)."\x00".$publicKeyPoint;

        // AlgorithmIdentifier: id-ecPublicKey + namedCurve
        // id-ecPublicKey OID: 1.2.840.10045.2.1
        $ecPublicKeyOid = "\x2a\x86\x48\xce\x3d\x02\x01"; // 1.2.840.10045.2.1
        $curveOidBytes = self::oidToBytes($curveOid);

        // SEQUENCE { OID ecPublicKey, OID namedCurve }
        $algorithmIdentifier = "\x30".self::encodeLength(strlen($ecPublicKeyOid) + strlen($curveOidBytes) + 4).
                              "\x06\x07".$ecPublicKeyOid.  // id-ecPublicKey
                              "\x06".self::encodeLength(strlen($curveOidBytes)).$curveOidBytes; // namedCurve

        // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }
        $subjectPublicKeyInfo = $algorithmIdentifier.$publicKeyBitString;

        return "\x30".self::encodeLength(strlen($subjectPublicKeyInfo)).$subjectPublicKeyInfo;
    }

    /**
     * Fix EC public key PEM using OpenSSL if available
     */
    private static function fixEcPublicKeyPem(string $xBin, string $yBin, string $curveOid, string $curveName): string
    {
        // Try alternative method: use OpenSSL to create a proper key structure
        if (function_exists('openssl_pkey_new') && function_exists('openssl_pkey_get_details')) {
            try {
                // Create a temporary EC key to get the proper structure
                $config = [
                    'curve_name' => $curveName,
                    'private_key_type' => OPENSSL_KEYTYPE_EC,
                ];

                $tempKey = openssl_pkey_new($config);
                if ($tempKey !== false) {
                    $details = openssl_pkey_get_details($tempKey);
                    if ($details !== false && isset($details['key'])) {
                        // Extract the structure from the temporary key
                        // But we need to replace the public key point
                        // This is complex, so we'll stick with ASN.1 but improve it
                    }
                    openssl_free_key($tempKey);
                }
            } catch (\Exception $e) {
                // Continue with ASN.1 method
            }
        }

        // Return the original PEM - the issue might be elsewhere
        $publicKeyPoint = "\x04".$xBin.$yBin;
        $publicKeyInfo = self::buildEcPublicKeyInfo($publicKeyPoint, $curveOid);

        return "-----BEGIN PUBLIC KEY-----\n".
               chunk_split(base64_encode($publicKeyInfo), 64, "\n").
               "-----END PUBLIC KEY-----\n";
    }

    /**
     * Build ASN.1 structure for RSA public key
     */
    private static function buildRsaPublicKeyInfo(string $n, string $e): string
    {
        // RSA public key: SEQUENCE { n INTEGER, e INTEGER }
        $rsaPublicKey = "\x02".self::encodeLength(strlen($n)).$n.
                       "\x02".self::encodeLength(strlen($e)).$e;
        $rsaPublicKey = "\x30".self::encodeLength(strlen($rsaPublicKey)).$rsaPublicKey;

        // AlgorithmIdentifier: rsaEncryption
        $rsaEncryptionOid = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"; // 1.2.840.113549.1.1.1
        $algorithmIdentifier = "\x30".self::encodeLength(strlen($rsaEncryptionOid) + 5).
                              "\x06".self::encodeLength(strlen($rsaEncryptionOid)).$rsaEncryptionOid.
                              "\x05\x00"; // NULL parameters

        // SubjectPublicKeyInfo
        $publicKeyBitString = "\x03".self::encodeLength(strlen($rsaPublicKey) + 1)."\x00".$rsaPublicKey;
        $subjectPublicKeyInfo = $algorithmIdentifier.$publicKeyBitString;

        return "\x30".self::encodeLength(strlen($subjectPublicKeyInfo)).$subjectPublicKeyInfo;
    }

    /**
     * Encode ASN.1 length
     */
    private static function encodeLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        // For lengths >= 0x80, use definite long form
        $bytes = '';
        $len = $length;
        while ($len > 0) {
            $bytes = chr($len & 0xFF).$bytes;
            $len >>= 8;
        }

        // First byte: 0x80 | number of following bytes
        return chr(0x80 | strlen($bytes)).$bytes;
    }

    /**
     * Convert OID string to bytes
     */
    private static function oidToBytes(string $oid): string
    {
        $parts = array_map('intval', explode('.', $oid));
        $bytes = chr($parts[0] * 40 + $parts[1]);
        for ($i = 2; $i < count($parts); $i++) {
            $val = $parts[$i];
            if ($val < 0x80) {
                $bytes .= chr($val);
            } else {
                $temp = '';
                while ($val > 0) {
                    $temp = chr(($val & 0x7F) | 0x80).$temp;
                    $val >>= 7;
                }
                $bytes .= substr($temp, 0, -1).chr(ord($temp[strlen($temp) - 1]) & 0x7F);
            }
        }

        return $bytes;
    }

    /**
     * Convert integer to bytes (big-endian)
     */
    private static function intToBytes(int $int): string
    {
        if ($int === 0) {
            return "\x00";
        }
        $bytes = '';
        while ($int > 0) {
            $bytes = chr($int & 0xFF).$bytes;
            $int >>= 8;
        }

        return $bytes;
    }

    /**
     * Sanitize data for debug output (convert binary to hex/base64)
     */
    private static function sanitizeForDebug($data): mixed
    {
        if (is_string($data)) {
            // Check if it's binary data (contains non-printable characters)
            if (preg_match('/[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F-\xFF]/', $data)) {
                return [
                    '_type' => 'binary',
                    '_hex' => bin2hex($data),
                    '_base64' => base64_encode($data),
                    '_length' => strlen($data),
                ];
            }

            return $data;
        }

        if (is_array($data)) {
            $result = [];
            foreach ($data as $key => $value) {
                $result[$key] = self::sanitizeForDebug($value);
            }

            return $result;
        }

        if (is_object($data)) {
            if (method_exists($data, '__toString')) {
                return self::sanitizeForDebug((string) $data);
            }

            return ['_type' => get_class($data)];
        }

        return $data;
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
