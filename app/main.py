import asyncio, time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import crypto, events
from .db import Base, engine, get_db
from .metrics import REQUESTS, ERRORS, LATENCY
from .models import Organization, Credential, Presentation, Event, new_id
from .schemas import (OrgCreate, OrgOut, CredentialCreate, CredentialOut, PresentRequest,
                      PresentOut, VerifyRequest, VerifyOut, StatsOut, OrgCount)

def utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)

def ts(dt: datetime | None) -> str | None:
    return utc(dt).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None

def signed_payload(c: Credential) -> dict:
    # the exact fields covered by the signature; any change breaks verification
    return {"id": c.id, "issuer_id": c.issuer_id, "recipient_email": c.recipient_email,
            "recipient_identifier": c.recipient_identifier, "claims": c.claims,
            "issued_at": ts(c.issued_at), "expires_at": ts(c.expires_at)}

def to_out(c: Credential) -> CredentialOut:
    return CredentialOut(id=c.id, issuer_id=c.issuer_id, recipient_email=c.recipient_email,
                         recipient_identifier=c.recipient_identifier, metadata=c.claims,
                         issued_at=utc(c.issued_at), expires_at=utc(c.expires_at),
                         signature=c.signature, revoked=c.revoked)

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    task = asyncio.create_task(events.consumer())
    yield
    await events.queue.join()
    task.cancel()

app = FastAPI(title="Credential Verification API", version="1.0.0", lifespan=lifespan)

@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    route = request.scope.get("route")
    endpoint = route.path if route else "unmatched"
    labels = (request.method, endpoint, str(response.status_code))
    REQUESTS.labels(*labels).inc()
    if response.status_code >= 400:
        ERRORS.labels(*labels).inc()
    LATENCY.labels(request.method, endpoint).observe(time.perf_counter() - start)
    return response

def get_org(db: Session, org_id: str) -> Organization:
    org = db.get(Organization, org_id)
    if not org:
        raise HTTPException(404, f"organization {org_id} not found")
    return org

@app.post("/organizations", response_model=OrgOut, status_code=201)
def register_org(body: OrgCreate, db: Session = Depends(get_db)):
    priv, pub = crypto.generate_keypair()
    org = Organization(name=body.name, contact_email=body.contact_email,
                       public_key=pub, private_key=priv)
    db.add(org)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "organization name already registered")
    db.refresh(org)
    return org

@app.get("/organizations/{org_id}", response_model=OrgOut)
def read_org(org_id: str, db: Session = Depends(get_db)):
    return get_org(db, org_id)

@app.post("/credentials", response_model=CredentialOut, status_code=201)
async def issue_credential(body: CredentialCreate, db: Session = Depends(get_db)):
    org = get_org(db, body.organization_id)
    issued = datetime.now(timezone.utc).replace(microsecond=0)
    if body.expires_at and utc(body.expires_at) <= issued:
        raise HTTPException(422, "expires_at must be in the future")
    cred = Credential(id=new_id(), issuer_id=org.id, recipient_email=body.recipient_email,
                      recipient_identifier=body.recipient_identifier, claims=body.metadata,
                      issued_at=issued, expires_at=utc(body.expires_at), signature="")
    cred.signature = crypto.sign(org.private_key, signed_payload(cred))
    db.add(cred)
    db.commit()
    await events.publish({"type": "CREDENTIAL_ISSUED", "organization_id": org.id,
                          "credential_id": cred.id,
                          "payload": {"recipient_email": cred.recipient_email}})
    return to_out(cred)

@app.get("/credentials/{cred_id}", response_model=CredentialOut)
def read_credential(cred_id: str, db: Session = Depends(get_db)):
    cred = db.get(Credential, cred_id)
    if not cred:
        raise HTTPException(404, "credential not found")
    return to_out(cred)

@app.post("/credentials/{cred_id}/present", response_model=PresentOut, status_code=201)
async def present_credential(cred_id: str, body: PresentRequest, db: Session = Depends(get_db)):
    cred = db.get(Credential, cred_id)
    if not cred:
        raise HTTPException(404, "credential not found")
    if cred.recipient_email.lower() != body.recipient_email.lower():
        raise HTTPException(403, "presenter is not the credential recipient")
    get_org(db, body.verifier_id)
    p = Presentation(credential_id=cred.id, recipient_email=body.recipient_email,
                     verifier_id=body.verifier_id)
    db.add(p)
    db.commit()
    db.refresh(p)
    await events.publish({"type": "CREDENTIAL_PRESENTED", "organization_id": body.verifier_id,
                          "credential_id": cred.id, "payload": {"presentation_id": p.id}})
    return p

@app.post("/credentials/{cred_id}/verify", response_model=VerifyOut)
async def verify_credential(cred_id: str, body: VerifyRequest | None = None,
                            db: Session = Depends(get_db)):
    reason = None
    cred = db.get(Credential, cred_id)
    if not cred:
        reason = "credential not found"
    else:
        issuer = db.get(Organization, cred.issuer_id)
        if not issuer:
            reason = "issuer not found"
        elif not crypto.verify(issuer.public_key, signed_payload(cred), cred.signature):
            reason = "signature invalid: credential has been tampered with"
        elif cred.revoked:
            reason = "credential revoked"
        elif cred.expires_at and utc(cred.expires_at) <= datetime.now(timezone.utc):
            reason = "credential expired"
    status = "invalid" if reason else "valid"
    verifier = body.verifier_id if body and body.verifier_id else "anonymous"
    await events.publish({"type": "CREDENTIAL_VERIFIED", "organization_id": verifier,
                          "credential_id": cred_id,
                          "payload": {"status": status, "reason": reason}})
    return VerifyOut(credential_id=cred_id, status=status, reason=reason)

@app.post("/credentials/{cred_id}/revoke", response_model=CredentialOut)
def revoke_credential(cred_id: str, db: Session = Depends(get_db)):
    cred = db.get(Credential, cred_id)
    if not cred:
        raise HTTPException(404, "credential not found")
    cred.revoked = True
    db.commit()
    return to_out(cred)

@app.get("/analytics/stats", response_model=StatsOut)
def stats(db: Session = Depends(get_db)):
    issued = db.scalar(select(func.count()).where(Event.type == "CREDENTIAL_ISSUED")) or 0
    verified = db.scalar(select(func.count()).where(Event.type == "CREDENTIAL_VERIFIED")) or 0
    rows = db.execute(
        select(Event.organization_id, Organization.name, func.count().label("n"))
        .join(Organization, Organization.id == Event.organization_id, isouter=True)
        .where(Event.type == "CREDENTIAL_ISSUED")
        .group_by(Event.organization_id, Organization.name)
        .order_by(func.count().desc()).limit(3)
    ).all()
    return StatsOut(total_credentials_issued=issued, total_verifications=verified,
                    top_issuers=[OrgCount(organization_id=r[0], name=r[1],
                                          credentials_issued=r[2]) for r in rows])

@app.get("/metrics", include_in_schema=False)
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.get("/health")
def health():
    return {"status": "ok", "queue_depth": events.queue.qsize()}
