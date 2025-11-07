<?php

return [
    'rp_id' => env('WEBAUTHN_RP_ID', parse_url(config('app.url'), PHP_URL_HOST) ?: 'localhost'),

    'allowed_origins' => [
        env('APP_URL'),
    ],

    'allowed_algorithms' => [
        -7,   // ES256
        -35,  // ES384
        -36,  // ES512
        -257, // RS256
    ],

    'require_user_verification' => env('WEBAUTHN_REQUIRE_UV', false),

    'user' => \App\Models\User::class,

    // Rate limiting
    'rate_limit' => [
        'enabled' => env('WEBAUTHN_RATE_LIMIT_ENABLED', true),
        'max_attempts' => env('WEBAUTHN_RATE_LIMIT_ATTEMPTS', 5),
        'decay_minutes' => env('WEBAUTHN_RATE_LIMIT_DECAY', 1),
    ],

    // Timeout configuration (in milliseconds)
    'timeout' => env('WEBAUTHN_TIMEOUT', 60000),

    // Device name validation
    'key_name' => [
        'min_length' => env('WEBAUTHN_KEY_NAME_MIN', 3),
        'max_length' => env('WEBAUTHN_KEY_NAME_MAX', 64),
    ],

    // Audit logging
    'audit_log' => [
        'enabled' => env('WEBAUTHN_AUDIT_LOG_ENABLED', true),
        'channel' => env('WEBAUTHN_AUDIT_LOG_CHANNEL', 'daily'),
    ],
];
