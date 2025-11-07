<?php

namespace r0073rr0r\WebAuthn\Exceptions;

class ChallengeMismatchException extends WebAuthnException
{
    public function __construct(string $message = 'Challenge mismatch', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, 'error_challenge_mismatch', $code, $previous);
    }
}
