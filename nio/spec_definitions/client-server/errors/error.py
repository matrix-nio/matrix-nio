# generated by datamodel-codegen:
#   filename:  error.yaml
#   timestamp: 2024-06-01T22:41:45+00:00

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class Error(BaseModel):
    errcode: str = Field(..., description="An error code.", examples=["M_UNKNOWN"])
    error: Optional[str] = Field(
        None,
        description="A human-readable error message.",
        examples=["An unknown error occurred"],
    )
