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

On the China probe server, copy the project or just the `agent` directory, install `agent/requirements.txt`, then run it with Supervisor using `deploy/supervisor-agent.ini`.

