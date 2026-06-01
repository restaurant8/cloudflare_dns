from . import agents, auth, credentials, events, external_ips, groups, overview, target_pool, telegram, webhooks, zones

routers = [
    auth.router,
    credentials.router,
    zones.router,
    groups.router,
    agents.router,
    target_pool.router,
    external_ips.router,
    telegram.router,
    webhooks.router,
    events.router,
    overview.router,
]
