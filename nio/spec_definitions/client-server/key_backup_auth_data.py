# generated by datamodel-codegen:
#   filename:  key_backup_auth_data.yaml
#   timestamp: 2024-06-01T22:41:30+00:00

from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class AuthData(BaseModel):
    public_key: str = Field(
        ...,
        description="The curve25519 public key used to encrypt the backups, encoded in unpadded base64.",
        examples=["abcdefg"],
    )
    signatures: Optional[Dict[str, Any]] = Field(
        None,
        description="Signatures of the `auth_data`, as Signed JSON",
        examples=[{"something": {"ed25519:something": "hijklmnop"}}],
    )
