<?php

namespace r0073rr0r\WebAuthn\Exceptions;

class ReplayAttackException extends WebAuthnException
{
    public function __construct(string $message = 'Replay attack detected', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, 'error_replay_attack', $code, $previous);
    }
}
