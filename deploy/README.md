# Direct deployment with Nginx and Supervisor

This path fits servers that already have Nginx, MySQL, and Supervisor installed.

## Backend

```bash
cd /www/wwwroot/cloudflare_dns
python3 -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements.txt
```

Create `.env` in the project root:

```env
SECRET_KEY=replace-with-long-random-secret
APP_ENCRYPTION_KEY=replace-with-fernet-key
DATABASE_URL=mysql+pymysql://cloudflare_dns:password@127.0.0.1:3306/cloudflare_dns?charset=utf8mb4
CORS_ORIGINS=https://your-domain.example.com
CHECK_INTERVAL_SECONDS=30
CHECK_TIMEOUT_SECONDS=3
FAIL_THRESHOLD=3
RECOVERY_THRESHOLD=2
LOCAL_PROBE_MAX_WORKERS=16
```

Generate a Fernet key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Copy `deploy/supervisor-backend.ini` into your Supervisor config directory and update paths if needed.

## Frontend

```bash
cd /www/wwwroot/cloudflare_dns/frontend
npm install
npm run build
```

Copy `deploy/nginx-cloudflare-dns.conf` into your Nginx site config and update `server_name` and `root`.

## Agent

Create a probe in the dashboard. The UI will show a one-line installer command once. Copy that command to the China probe server and run it as root.

The generated command uses this shape:

```bash
curl -fsSL 'https://your-panel.example.com/api/agent/install.sh' -o /tmp/cloudflare-dns-agent-install.sh && CONTROL_URL='https://your-panel.example.com' AGENT_TOKEN='the-one-time-token' bash /tmp/cloudflare-dns-agent-install.sh
```

It installs the agent under `/opt/cloudflare-dns-agent`, writes `/etc/cloudflare-dns-agent.env`, creates the `cloudflare-dns-agent` systemd service, and starts it automatically.

The agent runs up to 16 TCP checks concurrently by default. Set `AGENT_MAX_WORKERS`
when running the installer if the probe server needs a smaller or larger limit
(the accepted range is 1–64).
Set `AGENT_LOG_ROUNDS=1` to emit one summary line per probe round. It defaults to
`0`, so routine failed targets do not generate a log line every interval.

The controller runs local TCP checks concurrently too, including expanded hostname
IP pools. `LOCAL_PROBE_MAX_WORKERS` controls that limit (default 16, maximum 64).

Health-check settings saved in the dashboard override `.env` and application
defaults. For an existing deployment, change these values in the dashboard rather
than expecting a new code default to replace rows already stored in `app_settings`.

Useful commands:

```bash
systemctl status cloudflare-dns-agent
journalctl -u cloudflare-dns-agent -f
systemctl restart cloudflare-dns-agent
```
