import uuid
from datetime import datetime, timezone
from sqlachemy import Column, String, DateTime, ForeignKey, JSON, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base

def now():
    return datetime.now(timezone.utc)

def new_id():
    return str(uuid.uuid4())


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String, nullable=False)
    contact_email: Mapped[str] = mapped_column(String, nullable=False)
    public_key: Mapped[str] = mapped_column(String, nullable=False)
    private_key: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)

    users: Mapped[list["User"]] = relationship("User", back_populates="organization")


class Credentials(Base):
    __tablename__ = "credentials"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    issuer_id: Mapped[str] = mapped_column(String, ForeignKey("organizations.id"), nullable=False)
    recipient_email: Mapped[str] = mapped_column(String, nullable=False)
    recipient_identifier: Mapped[str] = mapped_column(String, nullable=False)
    claims: Mapped[dict] = mapped_column(JSON, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    
class Presentation(Base):
    __tablename__ = "presentations"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    credential_id: Mapped[str] = mapped_column(String, ForeignKey("credentials.id"), nullable=False)
    recipient_email: Mapped[str] = mapped_column(String, nullable=False)
    verifier_identifier: Mapped[str] = mapped_column(String, nullable=False)
    presented_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

    
class Event(base):
    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    type: Mapped[str] = mapped_column(String, nullable=False)
    organization_id: Mapped[str] = mapped_column(String, ForeignKey("organizations.id"), nullable=False)
    credential_id: Mapped[str] = mapped_column(String, ForeignKey("credentials.id"), nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


