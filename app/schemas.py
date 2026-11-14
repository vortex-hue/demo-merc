from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Any, Literal


class OrgCreate(BaseModel):
    name: str
    contact_email: EmailStr

class OrgOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    contact_email: EmailStr
    public_key: str
    created_at: datetime

class CredentialCreate(BaseModel):
    organization_id: str
    recipient_email: EmailStr
    recipient_identifier: str | None = Field(default=None, description="Optional recipient identifier")
    metadata: dict[str, Any] = Field(default_factory=dict)
    expires_at: datetime

class CredentialOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    issuer_id: str
    recipient_email: EmailStr
    recipient_identifier: str | None = Field(default=None, description="Optional recipient identifier")
    metadata: dict[str, Any]
    issued_at: datetime
    expires_at: datetime
    signature: str
    revoked: bool

class PresentRequest(BaseModel):
    recipient_email: EmailStr
    verifier_identifier: str

class PresentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    credential_id: str
    recipient_email: EmailStr
    verifier_identifier: str
    presented_at: datetime

class VerifyRequest(BaseModel):
    verifier_identifier: str | None = None


class VerifyOut(BaseModel):
    credential_id: str
    status: Literal["valid", "invalid"]
    reason: str | None = None

class OrgCount(BaseModel):
    organization_id: str
    name: str | None
    credentials_issued: int

class StatsOut(BaseModel):
    total_credentials_issued: int
    total_verifications: int
    top_issuers: list[OrgCount]
    