# Password Manager Schema

This folder contains simple JSON Schema files for the `Password-Manager` vault format.

## Files

| File | Purpose |
| --- | --- |
| `vault-envelope.schema.json` | Validates the encrypted `.pwv` vault envelope stored on disk. |
| `vault-header.schema.json` | Validates the public vault header metadata. |
| `vault-body.schema.json` | Validates the decrypted plaintext body before encryption or after decryption. |
| `vault-entry.schema.json` | Validates one password entry inside the decrypted vault body. |
| `schema-manifest.json` | Describes the schema package and intended validation scope. |
| `examples/sample-vault-envelope.json` | Example encrypted vault envelope shape. |
| `examples/sample-vault-body.json` | Example decrypted body shape. |

## Validation scope

The on-disk vault file is an encrypted envelope:

```json
{
  "header": {},
  "body": "fernet-token-as-text"
}
```

The decrypted body has this shape:

```json
{
  "version": 1,
  "entries": []
}
```

These schemas intentionally separate the encrypted envelope from the decrypted body. A validator can check the outer vault file without knowing the master password, but `vault-body.schema.json` only applies after successful decryption.

## Application rules not fully expressible in JSON Schema

The Python application still owns several runtime checks:

- `updated_at` must be greater than or equal to `created_at`.
- Entry IDs must be unique across the full vault body.
- Encrypted body size must not exceed 50 MiB.
- Decrypted body size must not exceed 10 MiB.
- Fernet token authenticity and decryptability require the crypto layer.

## Usage

Copy the entire `Schema/` folder into the repository root when you are ready to add schema documentation to the project. This package was generated locally only and was not pushed to GitHub.
