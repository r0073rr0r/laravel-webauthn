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
    $authData = $prefix . $counterBytes . $rest;

    expect(CredentialParser::extractCounter($authData))->toBe($counter);
});


