<?php

namespace r0073rr0r\WebAuthn\Exceptions;

use Exception;

class WebAuthnException extends Exception
{
    protected string $translationKey;

    public function __construct(string $message = '', string $translationKey = 'error_login_failed', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->translationKey = $translationKey;
    }

    public function getTranslationKey(): string
    {
        return $this->translationKey;
    }

    public function getUserMessage(): string
    {
        return __('webauthn::webauthn.'.$this->translationKey);
    }
}
