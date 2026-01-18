## Security Guide

This document describes how Polywatch protects user data and how to operate it safely in production.

## What We Store

Stored in SQLite:
- Encrypted user credentials (signer private key, funder address, API key/secret/passphrase)
- Per-user settings
- Trade history, audit logs, deposit signals

NOT stored:
- User passwords (used only to derive an encryption key)

## Encryption at Rest

- Credentials are encrypted with AES-256-GCM.
- A per-user salt is used for Argon2id key derivation.
- Additional Authenticated Data (AAD) binds ciphertext to `telegram:<id>`.
- Database file is created with restrictive permissions (0600) and directory 0700.

## In-Memory Handling

- Sensitive setup data is stored in secure buffers and cleared on completion or timeout.
- Session credentials auto-expire after a timeout.
- Unlock messages are deleted to reduce exposure in chat history.

## Logging Safety

- Secrets, signatures, and full request payloads are not logged.
- If you enable debug logging, ensure logs are stored securely and rotated.

## Operational Best Practices

1) Run with environment variables, not `.env`, in production.
2) Store secrets in a secrets manager (e.g., AWS Secrets Manager, Vault).
3) Use a dedicated wallet for trading (not a primary wallet).
4) Rotate API credentials on a regular schedule or after any suspected exposure.
5) Limit database access to the service account running the bot.

## Key Rotation

- Regenerate Polymarket API credentials in the Builder Dashboard.
- Update the stored encrypted credentials by re-running `/setup` or adding a secure rotation flow.
- Immediately invalidate old credentials in Polymarket.

## Backups

- Back up the SQLite database file with access controls (encrypted at rest).
- Store backups in a secure location with limited access.
- Do not store plaintext copies of credentials anywhere.

## Incident Response

If you suspect compromise:
1) Revoke API keys in Polymarket Builder Dashboard.
2) Rotate signer private key and funder address if needed.
3) Rotate encryption password for affected users (requires re-setup).
4) Review logs for suspicious activity and purge any sensitive debug logs.

## Secure Deployment Checklist

- [ ] Run as a non-root user
- [ ] Secrets in a manager (not in `.env`)
- [ ] Database file permissions: 0600
- [ ] Logs stored securely + rotated
- [ ] Rate limiting enabled (user + global)
- [ ] Monitoring and alerting on errors and latency

