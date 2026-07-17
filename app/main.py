from contextlib import asynccontextmanager
import logging
import json
import time
from fastapi import FastAPI
from app.modules.core.geoip import load_geoip, close_geoip, get_geoip
from app.modules.analyze.controller import router as analyze_router
from app.modules.audit.controller import router as audit_router
from app.modules.blacklist.controller import router as blacklist_router
from app.modules.ids.controller import router as ids_router
from app.modules.ips.controller import router as ips_router

# ── JSON structured log formatter ────────────────────────────────────────────

class JsonFormatter(logging.Formatter):
    """Emits each log record as a single JSON line, including any extra= fields."""

    # Standard LogRecord attributes to exclude from the extra fields dump
    _SKIP = frozenset({
        "name", "msg", "args", "created", "filename", "funcName", "levelname",
        "levelno", "lineno", "message", "module", "msecs", "pathname",
        "process", "processName", "relativeCreated", "stack_info", "thread",
        "threadName", "exc_info", "exc_text", "taskName",
    })

    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Merge any extra= keyword arguments passed by the caller
        for key, value in record.__dict__.items():
            if key not in self._SKIP:
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def _configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    # Remove any handlers added before this runs (e.g. uvicorn's default)
    root.handlers.clear()
    root.addHandler(handler)


_configure_logging()

# ── App startup time (used for uptime) ───────────────────────────────────────
_started_at: float = time.monotonic()


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_geoip()
    yield
    close_geoip()


app = FastAPI(
    title="NexusPLM IDS",
    description="Real-time intrusion detection for NexusPLM (C# + React).",
    version="2.0.0",
    lifespan=lifespan,
)

app.include_router(analyze_router)
app.include_router(audit_router)
app.include_router(blacklist_router)
app.include_router(ids_router)
app.include_router(ips_router)


@app.get("/health", tags=["Health"])
async def health():
    from app.modules.core.redis import get_redis

    # Redis connectivity check
    redis_ok = False
    try:
        r = await get_redis()
        await r.ping()
        redis_ok = True
    except Exception:
        redis_ok = False

    uptime_seconds = int(time.monotonic() - _started_at)

    return {
        "status": "ok" if redis_ok else "degraded",
        "geoip": get_geoip() is not None,
        "redis": redis_ok,
        "uptime_seconds": uptime_seconds,
    }
