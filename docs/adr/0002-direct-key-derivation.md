# ADR 0002: Direct Key Derivation

The master password derives the vault encryption key directly. The vault is a
single small local file, so re-encrypting the body during password rotation is
acceptable and simpler than envelope encryption for v1.
