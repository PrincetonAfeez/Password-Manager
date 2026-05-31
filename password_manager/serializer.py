"""Stable JSON serialization for vault headers and bodies."""

from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Any

from .errors import VaultFormatError
from .models import Entry, KDFParams, VaultBody, VaultHeader


class VaultSerializer:
    def dumps_header(self, header: VaultHeader) -> dict[str, Any]:
        return {
            "format": header.format,
            "version": header.version,
            "kdf": header.kdf,
            "kdf_params": {
                "length": header.kdf_params.length,
                "n": header.kdf_params.n,
                "r": header.kdf_params.r,
                "p": header.kdf_params.p,
            },
            "salt": base64.b64encode(header.salt).decode("ascii"),
            "cipher": header.cipher,
            "revision": header.revision,
            "created_at": header.created_at.isoformat(),
            "updated_at": header.updated_at.isoformat(),
        }

    def loads_header(self, data: dict[str, Any]) -> VaultHeader:
        try:
            params = data["kdf_params"]
            return VaultHeader(
                format=data["format"],
                version=data["version"],
                kdf=data["kdf"],
                kdf_params=KDFParams(
                    name=data["kdf"],
                    length=params["length"],
                    n=params["n"],
                    r=params["r"],
                    p=params["p"],
                ),
                salt=base64.b64decode(data["salt"], validate=True),
                cipher=data["cipher"],
                revision=int(data.get("revision", 0)),
                created_at=self._parse_datetime(data["created_at"]),
                updated_at=self._parse_datetime(data["updated_at"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise VaultFormatError("vault header is malformed") from exc

    def dumps_body(self, body: VaultBody) -> bytes:
        data = {
            "version": body.version,
            "entries": [self._entry_to_dict(entry) for entry in body.entries],
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def loads_body(self, data: bytes) -> VaultBody:
        try:
            raw = json.loads(data.decode("utf-8"))
            entries = [self._entry_from_dict(item) for item in raw["entries"]]
            return VaultBody(version=raw["version"], entries=entries)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise VaultFormatError("vault body is malformed") from exc

    def dumps_envelope(self, header: VaultHeader, encrypted_body: bytes) -> bytes:
        envelope = {
            "header": self.dumps_header(header),
            "body": encrypted_body.decode("ascii"),
        }
        text = json.dumps(envelope, sort_keys=True, indent=2)
        return (text + "\n").encode("utf-8")

    def loads_envelope(self, data: bytes) -> tuple[VaultHeader, bytes]:
        try:
            envelope = json.loads(data.decode("utf-8"))
            header = self.loads_header(envelope["header"])
            body = envelope["body"]
            if not isinstance(body, str):
                raise TypeError("body must be text")
            return header, body.encode("ascii")
        except VaultFormatError:
            raise
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise VaultFormatError("vault file is malformed") from exc

    def _entry_to_dict(self, entry: Entry) -> dict[str, Any]:
        return {
            "id": entry.id,
            "service": entry.service,
            "username": entry.username,
            "password": entry.password,
            "url": entry.url,
            "notes": entry.notes,
            "created_at": entry.created_at.isoformat(),
            "updated_at": entry.updated_at.isoformat(),
        }

    def _entry_from_dict(self, data: dict[str, Any]) -> Entry:
        return Entry(
            id=data["id"],
            service=data["service"],
            username=data["username"],
            password=data["password"],
            url=data.get("url", ""),
            notes=data.get("notes", ""),
            created_at=self._parse_datetime(data["created_at"]),
            updated_at=self._parse_datetime(data["updated_at"]),
        )

    def _parse_datetime(self, value: str) -> datetime:
        if not isinstance(value, str):
            raise ValueError("datetime must be text")
        return datetime.fromisoformat(value)
