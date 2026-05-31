# ADR 0006: Fail Closed

If header parsing, KDF validation, decryption, authentication, or schema
validation fails, refuse to use the vault contents.
