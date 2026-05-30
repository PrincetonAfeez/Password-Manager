# ADR 0004: Fernet

Use Fernet for authenticated encryption. Fernet handles IV generation,
authentication, and token formatting internally. It is AES-CBC plus HMAC-SHA256,
not an AEAD construction, and its token timestamp is visible metadata.
