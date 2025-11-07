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
        // Try multiple ways to access the data
        $crv = $keyData[-2] ?? $normalized[-2] ?? $keyData['-2'] ?? $normalized['-2'] ?? null;
        $x = $keyData[-3] ?? $normalized[-3] ?? $keyData['-3'] ?? $normalized['-3'] ?? null;
        $y = $keyData[-4] ?? $normalized[-4] ?? $keyData['-4'] ?? $normalized['-4'] ?? null;
        
        // Also try with string keys (some implementations use string keys)
        if ($x === null || $y === null) {
            // Try accessing as string keys
            foreach (['-3', '-4', -3, -4] as $key) {
                if ($x === null && isset($keyData[$key])) {
                    $x = $keyData[$key];
                }
                if ($y === null && isset($normalized[$key])) {
                    $y = $normalized[$key];
                }
            }
        }
        
        if ($x === null || $y === null) {
            // Debug: log what we have (convert binary data to hex/base64 for safe JSON encoding)
            $safeKeyData = self::sanitizeForDebug($keyData);
            $safeNormalized = self::sanitizeForDebug($normalized);
            $debugInfo = [
                'keyData_keys' => array_keys($keyData),
                'normalized_keys' => array_keys($normalized),
                'keyData' => $safeKeyData,
                'normalized' => $safeNormalized,
            ];
            throw new \RuntimeException('Missing EC2 key coordinates (x, y). Debug: ' . json_encode($debugInfo, JSON_PARTIAL_OUTPUT_ON_ERROR));
        }
        
        // Convert coordinates to binary string
        $xBin = self::normalizeKeyValue($x);
        $yBin = self::normalizeKeyValue($y);
        
        // Normalize crv to integer (it might be a string or binary data)
        $crvInt = self::normalizeCoseInteger($crv);
        
        if ($crvInt === null) {
            throw new \RuntimeException('Missing or invalid EC curve (crv) parameter. Value: ' . (is_string($crv) ? bin2hex($crv) : var_export($crv, true)));
        }
        
        // Determine curve name based on crv
        $curveName = match ($crvInt) {
            1 => 'prime256v1',  // P-256
            2 => 'secp384r1',   // P-384
            3 => 'secp521r1',   // P-521
            default => throw new \RuntimeException("Unsupported EC curve: {$crvInt}"),
        };
        
        // Try using OpenSSL to create the key
        if (function_exists('openssl_pkey_get_public') && function_exists('openssl_pkey_get_details')) {
            try {
                // Create public key point (0x04 + x + y for uncompressed)
                $publicKeyPoint = "\x04" . $xBin . $yBin;
                
                // Determine curve OID based on crv
                $curveOid = match ($crvInt) {
                    1 => '1.2.840.10045.3.1.7', // P-256
                    2 => '1.3.132.0.34',         // P-384
                    3 => '1.3.132.0.35',         // P-521
                    default => throw new \RuntimeException("Unsupported EC curve: {$crvInt}"),
                };
                
                // Build ASN.1 structure for EC public key
                $publicKeyInfo = self::buildEcPublicKeyInfo($publicKeyPoint, $curveOid);
                
                // Try to load with OpenSSL to validate
                $resource = openssl_pkey_get_public("-----BEGIN PUBLIC KEY-----\n" . 
                    chunk_split(base64_encode($publicKeyInfo), 64, "\n") . 
                    "-----END PUBLIC KEY-----\n");
                
                if ($resource !== false) {
                    return "-----BEGIN PUBLIC KEY-----\n" .
                           chunk_split(base64_encode($publicKeyInfo), 64, "\n") .
                           "-----END PUBLIC KEY-----\n";
                }
            } catch (\Exception $e) {
                // Fall through to manual conversion
            }
        }
        
        // Manual conversion using ASN.1
        $curveOid = match ($crvInt) {
            1 => '1.2.840.10045.3.1.7', // P-256
            2 => '1.3.132.0.34',         // P-384
            3 => '1.3.132.0.35',         // P-521
            default => throw new \RuntimeException("Unsupported EC curve: {$crvInt}"),
        };
        
        // Create public key point (0x04 + x + y for uncompressed)
        $publicKeyPoint = "\x04" . $xBin . $yBin;
        
        // Build ASN.1 structure for EC public key
        $publicKeyInfo = self::buildEcPublicKeyInfo($publicKeyPoint, $curveOid);
        
        return "-----BEGIN PUBLIC KEY-----\n" .
               chunk_split(base64_encode($publicKeyInfo), 64, "\n") .
               "-----END PUBLIC KEY-----\n";
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
            $nBin = "\x00" . $nBin;
        }
        if (strlen($eBin) > 0 && (ord($eBin[0]) & 0x80)) {
            $eBin = "\x00" . $eBin;
        }
        
        // Build ASN.1 structure for RSA public key
        $publicKeyInfo = self::buildRsaPublicKeyInfo($nBin, $eBin);
        
        return "-----BEGIN PUBLIC KEY-----\n" .
               chunk_split(base64_encode($publicKeyInfo), 64, "\n") .
               "-----END PUBLIC KEY-----\n";
    }
    
    /**
     * Build ASN.1 structure for EC public key
     */
    private static function buildEcPublicKeyInfo(string $publicKeyPoint, string $curveOid): string
    {
        // EC public key: BIT STRING containing the public key point
        $publicKeyBitString = "\x03" . self::encodeLength(strlen($publicKeyPoint) + 1) . "\x00" . $publicKeyPoint;
        
        // AlgorithmIdentifier: id-ecPublicKey + namedCurve
        $curveOidBytes = self::oidToBytes($curveOid);
        $algorithmIdentifier = "\x30" . self::encodeLength(strlen($curveOidBytes) + 2) .
                              "\x06" . self::encodeLength(strlen($curveOidBytes)) . $curveOidBytes;
        
        // SubjectPublicKeyInfo
        $subjectPublicKeyInfo = $algorithmIdentifier . $publicKeyBitString;
        
        return "\x30" . self::encodeLength(strlen($subjectPublicKeyInfo)) . $subjectPublicKeyInfo;
    }
    
    /**
     * Build ASN.1 structure for RSA public key
     */
    private static function buildRsaPublicKeyInfo(string $n, string $e): string
    {
        // RSA public key: SEQUENCE { n INTEGER, e INTEGER }
        $rsaPublicKey = "\x02" . self::encodeLength(strlen($n)) . $n .
                       "\x02" . self::encodeLength(strlen($e)) . $e;
        $rsaPublicKey = "\x30" . self::encodeLength(strlen($rsaPublicKey)) . $rsaPublicKey;
        
        // AlgorithmIdentifier: rsaEncryption
        $rsaEncryptionOid = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"; // 1.2.840.113549.1.1.1
        $algorithmIdentifier = "\x30" . self::encodeLength(strlen($rsaEncryptionOid) + 5) .
                              "\x06" . self::encodeLength(strlen($rsaEncryptionOid)) . $rsaEncryptionOid .
                              "\x05\x00"; // NULL parameters
        
        // SubjectPublicKeyInfo
        $publicKeyBitString = "\x03" . self::encodeLength(strlen($rsaPublicKey) + 1) . "\x00" . $rsaPublicKey;
        $subjectPublicKeyInfo = $algorithmIdentifier . $publicKeyBitString;
        
        return "\x30" . self::encodeLength(strlen($subjectPublicKeyInfo)) . $subjectPublicKeyInfo;
    }
    
    /**
     * Encode ASN.1 length
     */
    private static function encodeLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        $bytes = '';
        $len = $length;
        while ($len > 0) {
            $bytes = chr($len & 0xff) . $bytes;
            $len >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
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
                    $temp = chr(($val & 0x7f) | 0x80) . $temp;
                    $val >>= 7;
                }
                $bytes .= substr($temp, 0, -1) . chr(ord($temp[strlen($temp) - 1]) & 0x7f);
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
            $bytes = chr($int & 0xff) . $bytes;
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
