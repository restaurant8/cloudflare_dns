from . import agents, auth, credentials, events, external_ips, groups, overview, settings, snippets, ssh, target_pool, telegram, webhooks, zones

routers = [
    auth.router,
    credentials.router,
    zones.router,
    groups.router,
    agents.router,
    target_pool.router,
    external_ips.router,
    snippets.router,
    ssh.router,
    settings.router,
    telegram.router,
    webhooks.router,
    events.router,
    overview.router,
]
