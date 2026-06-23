from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.modules.core.geoip import load_geoip, close_geoip
from app.modules.analyze.controller import router as analyze_router
from app.modules.audit.controller import router as audit_router
from app.modules.blacklist.controller import router as blacklist_router
from app.modules.ids.controller import router as ids_router


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


@app.get("/health", tags=["Health"])
async def health():
    from app.modules.core.geoip import get_geoip
    return {"status": "ok", "geoip": get_geoip() is not None}
