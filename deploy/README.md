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

Useful commands:

```bash
systemctl status cloudflare-dns-agent
journalctl -u cloudflare-dns-agent -f
systemctl restart cloudflare-dns-agent
```
