# Security Policy for Laravel WebAuthn

## Supported Versions

We provide security updates for the following versions of **Laravel WebAuthn**:

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| 0.x     | :x:                |

> Only the latest stable version receives security updates. Upgrading to the latest version is recommended if you are using an unsupported version.

## Security Features

This package includes several built-in security features to protect against common attacks:

### Rate Limiting
- **Protection**: Prevents brute force attacks on login and registration
- **Configuration**: Configurable via `config/webauthn.php` or environment variables
- **Default**: 5 attempts per minute per user/IP
- **Recommendation**: Keep rate limiting enabled in production

### Audit Logging
- **Protection**: Comprehensive logging of all WebAuthn operations
- **Features**: Logs registrations, logins, deletions, and errors with full context
- **Configuration**: Configurable log channel via `WEBAUTHN_AUDIT_LOG_CHANNEL`
- **Recommendation**: Enable audit logging for security monitoring and compliance

### Replay Attack Protection
- **Protection**: Sign counter validation prevents replay attacks
- **Implementation**: Automatic counter validation on each authentication
- **Recommendation**: Always enabled, no configuration needed

### Origin Validation
- **Protection**: Ensures requests come from allowed origins only
- **Configuration**: Configure allowed origins in `config/webauthn.php`
- **Recommendation**: Only include trusted domains in `allowed_origins`

### Challenge Validation
- **Protection**: One-time challenges prevent replay attacks
- **Implementation**: Challenges are invalidated after use
- **Recommendation**: Always enabled, no configuration needed

### User Verification
- **Protection**: Optional user verification requirement
- **Configuration**: Enable via `WEBAUTHN_REQUIRE_UV=true`
- **Recommendation**: Enable for high-security applications

### Algorithm Validation
- **Protection**: Only allows configured cryptographic algorithms
- **Configuration**: Configure in `config/webauthn.php` → `allowed_algorithms`
- **Default**: ES256, ES384, ES512, RS256
- **Recommendation**: Only enable algorithms you need

## Reporting a Vulnerability

If you discover a security vulnerability in **Laravel WebAuthn**, please report it responsibly by following these guidelines:

1. **Do not open a public issue** for security bugs.
2. **Email the security team directly** at: `velimir@majstorov.rs`  
   Include:
   - A clear description of the vulnerability.
   - Steps to reproduce.
   - Affected version(s).
   - Any suggested fixes, if possible.

3. We will acknowledge receipt of your report within **48 hours**.
4. Security issues will be fixed in a **timely manner**, and a patched release will be made available.
5. If the report is accepted, you may be credited in the release notes (unless you request to remain anonymous).

## Supported Channels

- Email: `velimir@majstorov.rs`
- [GitHub Repository](https://github.com/r0073rr0r/laravel-webauthn)

## Response Timeline

- Acknowledgment of report: **within 48 hours**
- Security patch release: **as soon as possible** depending on severity
- Public disclosure: **after patch release**, unless agreed otherwise

## Security Best Practices

When using this package, we recommend:

1. **Enable Rate Limiting**: Keep rate limiting enabled to prevent brute force attacks
2. **Enable Audit Logging**: Monitor all WebAuthn operations for security analysis
3. **Configure Allowed Origins**: Only include trusted domains in `allowed_origins`
4. **Use HTTPS**: Always use HTTPS in production to protect WebAuthn communications
5. **Keep Updated**: Regularly update to the latest version for security patches
6. **Review Audit Logs**: Regularly review audit logs for suspicious activity
7. **User Verification**: Consider enabling user verification for high-security applications
8. **Algorithm Selection**: Only enable cryptographic algorithms you actually need

## Security Considerations

- **Private Keys**: Private keys never leave the authenticator device
- **Public Keys**: Public keys are stored in the database (PEM format)
- **Credentials**: Credential IDs are stored as binary data
- **Signatures**: All signatures are verified using OpenSSL
- **Challenges**: Challenges are cryptographically random and single-use
- **Counters**: Sign counters prevent replay attacks
