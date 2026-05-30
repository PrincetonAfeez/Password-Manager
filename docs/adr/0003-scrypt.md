# ADR 0003: scrypt

Use scrypt for v1 because it is memory-hard and available through
`cryptography`. KDF parameters are stored in the plaintext header so old vaults
remain unlockable and future vaults can use stronger settings.
