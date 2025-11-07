<?php

namespace r0073rr0r\WebAuthn\Exceptions;

class InvalidCredentialException extends WebAuthnException
{
    public function __construct(string $message = 'Credential not found', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, 'error_credential_not_found', $code, $previous);
    }
}
