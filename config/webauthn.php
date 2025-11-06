<?php

return [
    'rp_id' => env('WEBAUTHN_RP_ID', parse_url(config('app.url'), PHP_URL_HOST) ?: 'localhost'),

    'allowed_origins' => [
        env('APP_URL'),
    ],

    'allowed_algorithms' => [
        -7,   // ES256
        -257, // RS256
    ],

    'require_user_verification' => env('WEBAUTHN_REQUIRE_UV', false),

    'user' => \App\Models\User::class,
];
