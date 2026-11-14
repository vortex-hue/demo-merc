import asyncio, logging
from .db import SessionLocal
from .models import Event
from .metrics import EVENTS_PROCESSED

log = logging.getLogger("events")
queue: asyncio.Queue[dict] = asyncio.Quece