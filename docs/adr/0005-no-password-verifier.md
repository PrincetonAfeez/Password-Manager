# ADR 0005: No Password Verifier

Do not store a password verifier. Successful authenticated decryption already
proves the derived key is correct. A separate verifier would add attack surface.
