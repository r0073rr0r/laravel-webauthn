<?php

namespace r0073rr0r\WebAuthn\Exceptions;

class OriginNotAllowedException extends WebAuthnException
{
    public function __construct(string $message = 'Origin not allowed', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, 'error_origin_not_allowed', $code, $previous);
    }
}
