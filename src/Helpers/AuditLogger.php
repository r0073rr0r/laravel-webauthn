<?php

namespace r0073rr0r\WebAuthn\Helpers;

use Illuminate\Support\Facades\Log;

class AuditLogger
{
    /**
     * Log WebAuthn action to the configured log channel
     * 
     * @param string $action Action name (e.g., 'key_registered', 'login_success')
     * @param array $context Additional context data
     * 
     * Note: 'daily' channel creates a new log file each day (e.g., laravel-2025-01-07.log)
     * Other Laravel channels: 'single', 'syslog', 'errorlog', or custom channels
     * This does NOT send emails - it only writes to log files in storage/logs/
     */
    public static function log(string $action, array $context = []): void
    {
        if (! config('webauthn.audit_log.enabled', true)) {
            return;
        }

        // 'daily' = Laravel log channel that rotates files daily (does NOT send emails)
        // Other options: 'single', 'syslog', 'errorlog', or custom channels from config/logging.php
        $channel = config('webauthn.audit_log.channel', 'daily');

        Log::channel($channel)->info("WebAuthn: {$action}", array_merge([
            'action' => $action,
            'ip' => request()->ip(),
            'user_agent' => request()->userAgent(),
            'timestamp' => now()->toIso8601String(),
        ], $context));
    }

    public static function logRegistration(int $userId, string $keyName, string $credentialId, ?string $aaguid = null): void
    {
        self::log('key_registered', [
            'user_id' => $userId,
            'key_name' => $keyName,
            'credential_id' => bin2hex($credentialId),
            'aaguid' => $aaguid,
        ]);
    }

    public static function logLogin(int $userId, string $credentialId, bool $success): void
    {
        self::log($success ? 'login_success' : 'login_failed', [
            'user_id' => $userId,
            'credential_id' => bin2hex($credentialId),
            'success' => $success,
        ]);
    }

    public static function logKeyDeletion(int $userId, int $keyId, string $keyName): void
    {
        self::log('key_deleted', [
            'user_id' => $userId,
            'key_id' => $keyId,
            'key_name' => $keyName,
        ]);
    }

    public static function logError(string $action, \Throwable $exception, array $context = []): void
    {
        self::log("error_{$action}", array_merge([
            'error' => $exception->getMessage(),
            'exception' => get_class($exception),
            'trace' => $exception->getTraceAsString(),
        ], $context));
    }
}
