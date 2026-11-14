import asyncio, logging
from .db import SessionLocal
from .models import Event
from .metrics import EVENTS_PROCESSED

log = logging.getLogger("events")
queue: asyncio.Queue[dict] = asyncio.Queue()

async def publish(event: dict) -> None:
    await queue.put(event)

async def consumer() -> None:
    while True:
        event = await queue.get()
        try:
            with SessionLocal() as db:
                db.add(Event(**event))
                db.commit()
            EVENTS_PROCESSED.labels(type=event["type"]).inc()
        except Exception:
            log.exception("Failed to process event: %s", event)
        finally:
            queue.task_done()