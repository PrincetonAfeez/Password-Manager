# ADR 0001: Use cryptography

Use the `cryptography` package for all cryptographic operations. The project is
about safe assembly of vetted primitives, not inventing primitives. Only
`password_manager.crypto_engine` may import `cryptography`.
