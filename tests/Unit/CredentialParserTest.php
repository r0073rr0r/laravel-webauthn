<?php

namespace r0073rr0r\WebAuthn\Tests\Unit;

use r0073rr0r\WebAuthn\Helpers\CredentialParser;

it('encodes and decodes base64url correctly', function () {
    $raw = random_bytes(32);
    $encoded = CredentialParser::base64url_encode($raw);
    expect($encoded)->not->toContain('=');
    $decoded = CredentialParser::base64url_decode($encoded);
    expect($decoded)->toBe($raw);
});

it('extracts counter from authData safely', function () {
    // Build a fake authData with at least 37 bytes and a 4-byte counter at offset 33
    $prefix = str_repeat("\x00", 33);
    $counter = 12345;
    $counterBytes = pack('N', $counter);
    $rest = str_repeat("\x00", 8);
    $authData = $prefix.$counterBytes.$rest;

    expect(CredentialParser::extractCounter($authData))->toBe($counter);
});

it('picks the signature digest from the key curve', function () {
    $digest = fn (string $pem) => \r0073rr0r\WebAuthn\Helpers\CredentialParser::signatureAlgorithm(openssl_pkey_get_public($pem));

    $p256 = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEopCPwNZqTxcvBv/cyCSHxpEMs2ON\n4kIXmjx3yY1v8fOz6nh27MWTqiA0UfMfkKPabACBbGlxtIoEIGbHuH1TBw==\n-----END PUBLIC KEY-----\n";
    $p384 = "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEDb3LhCsxtqeqhQ/9K0XAdDxpCRj2A4To\nmdDP0dQApbGcR/+/0O1Mr1EjIEtlfiK+Jgwg45/kFkGbVM4UmcCSNU6jSjx65cfk\nfXrJjCFJ/Y/TLHbc9CLev6QadrcMF4MT\n-----END PUBLIC KEY-----\n";
    $p521 = "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBq6IzT63IMgBRWnZkjdh5DjxJKROv\nArts79xqcLA70cqdx58qoQdO6VvgWadPrtT9MGZbA+xEYXWoLnkQ7YhpORUBAdh4\nE/vGpUXHao84nEt6Y99OttOZ1u66i79G7r5oPy7Ma5Tb/2noeVZfsdTgShRZEEEA\nXH9CSAuJGitMXB9W6qM=\n-----END PUBLIC KEY-----\n";

    expect($digest($p256))->toBe(OPENSSL_ALGO_SHA256)
        ->and($digest($p384))->toBe(OPENSSL_ALGO_SHA384)
        ->and($digest($p521))->toBe(OPENSSL_ALGO_SHA512)
        ->and(\r0073rr0r\WebAuthn\Helpers\CredentialParser::signatureAlgorithm('not-a-key'))->toBe(OPENSSL_ALGO_SHA256);
});
