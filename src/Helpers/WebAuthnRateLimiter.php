<?php

namespace r0073rr0r\WebAuthn\Helpers;

use Illuminate\Support\Facades\RateLimiter as RateLimiterFacade;
use r0073rr0r\WebAuthn\Exceptions\WebAuthnException;

class WebAuthnRateLimiter
{
    public static function check(string $key, ?int $userId = null): void
    {
        if (! config('webauthn.rate_limit.enabled', true)) {
            return;
        }

        $maxAttempts = config('webauthn.rate_limit.max_attempts', 5);
        $decayMinutes = config('webauthn.rate_limit.decay_minutes', 1);

        $rateLimitKey = $userId
            ? "webauthn:{$key}:user:{$userId}"
            : "webauthn:{$key}:ip:".request()->ip();

        if (RateLimiterFacade::tooManyAttempts($rateLimitKey, $maxAttempts)) {
            $seconds = RateLimiterFacade::availableIn($rateLimitKey);
            $message = __('webauthn::webauthn.error_rate_limit_exceeded', ['seconds' => $seconds]);
            throw new WebAuthnException(
                "Rate limit exceeded. Try again in {$seconds} seconds.",
                'error_rate_limit_exceeded',
                429
            );
        }

        RateLimiterFacade::hit($rateLimitKey, $decayMinutes * 60);
    }

    public static function clear(string $key, ?int $userId = null): void
    {
        $rateLimitKey = $userId
            ? "webauthn:{$key}:user:{$userId}"
            : "webauthn:{$key}:ip:".request()->ip();

        RateLimiterFacade::clear($rateLimitKey);
    }
}
