import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings
from .database import SessionLocal, init_db
from .external_ips import sync_due_external_ip_sources
from .failover import evaluate_failover_groups
from .health import mark_stale_agents, run_local_checks, run_target_pool_checks
from .routes import routers


async def scheduler_loop(stop_event: asyncio.Event) -> None:
    settings = get_settings()
    while not stop_event.is_set():
        try:
            with SessionLocal() as db:
                mark_stale_agents(db)
                check_cache = {}
                run_local_checks(db, check_cache=check_cache)
                run_target_pool_checks(db, check_cache=check_cache)
                sync_due_external_ip_sources(db)
                evaluate_failover_groups(db)
                db.commit()
        except Exception:
            # The next loop will retry; API event logging may not be available if DB init failed.
            pass
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=settings.check_interval_seconds)
        except asyncio.TimeoutError:
            continue


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    stop_event = asyncio.Event()
    task = asyncio.create_task(scheduler_loop(stop_event))
    try:
        yield
    finally:
        stop_event.set()
        await task


settings = get_settings()
app = FastAPI(title=settings.app_name, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


for router in routers:
    app.include_router(router, prefix="/api")
