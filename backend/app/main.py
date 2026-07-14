import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings
from .database import SessionLocal, init_db
from .external_ips import sync_due_external_ip_sources
from .failover import evaluate_failover_groups
from .integrations import auto_sync_synexvm_statuses, reconcile_pending_synexvm_changes
from .health import mark_stale_agents, run_local_checks
from .retention import prune_old_rows
from .runtime_settings import get_runtime_settings
from .routes import routers


logger = logging.getLogger(__name__)

_PRUNE_INTERVAL_SECONDS = 3600
_last_prune_at: datetime | None = None


def _run_scheduler_tick() -> int:
    """Run one blocking probe/evaluation tick. Returns the next interval in seconds.

    This does blocking TCP/DNS probes, so it must be called from a worker thread
    (via asyncio.to_thread) to avoid freezing the API event loop.
    """
    global _last_prune_at
    with SessionLocal() as db:
        runtime_settings = get_runtime_settings(db)
        mark_stale_agents(db)
        check_cache = {}
        run_local_checks(db, check_cache=check_cache)
        # 先把已下发但未确认的 SynexVM 换 IP 用 status 补上新 IP（并催外部来源重同步），
        # 再跑外部同步和故障切换评估，绑定的源站才能在本轮就跟上新 IP。
        reconcile_pending_synexvm_changes(db)
        # 兜底：按资源配置的间隔自动查 status，面板上 IP 变了（含手动换的）也能跟上
        auto_sync_synexvm_statuses(db)
        sync_due_external_ip_sources(db)
        # commit_per_group keeps external side effects (Cloudflare writes, azpanel
        # IP changes) recorded even if a later group fails mid-tick.
        evaluate_failover_groups(
            db,
            commit_per_group=True,
            consistency_check_interval_seconds=get_settings().dns_consistency_check_interval_seconds,
        )
        now = datetime.utcnow()
        if _last_prune_at is None or (now - _last_prune_at).total_seconds() >= _PRUNE_INTERVAL_SECONDS:
            _last_prune_at = now
            prune_old_rows(db)
        db.commit()
        return runtime_settings.check_interval_seconds


async def scheduler_loop(stop_event: asyncio.Event) -> None:
    timeout_seconds = get_settings().check_interval_seconds
    while not stop_event.is_set():
        try:
            timeout_seconds = await asyncio.to_thread(_run_scheduler_tick)
        except Exception:
            # The next loop will retry; keep the reason visible instead of failing silently.
            logger.exception("scheduler tick failed; retrying in %ss", timeout_seconds)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=timeout_seconds)
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
settings.check_production_secrets()
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
