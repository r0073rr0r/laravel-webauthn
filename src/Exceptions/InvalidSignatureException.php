<?php

namespace r0073rr0r\WebAuthn\Exceptions;

class InvalidSignatureException extends WebAuthnException
{
    public function __construct(string $message = 'Invalid signature', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, 'error_invalid_signature', $code, $previous);
    }
}
