from . import agents, auth, credentials, events, groups, overview, telegram, webhooks, zones

routers = [
    auth.router,
    credentials.router,
    zones.router,
    groups.router,
    agents.router,
    telegram.router,
    webhooks.router,
    events.router,
    overview.router,
]
