# Cloudflare DNS Failover

A self-hosted Cloudflare DNS failover dashboard for DNS-only A, AAAA, and CNAME records.

## What it does

- Stores multiple Cloudflare API tokens with encryption.
- Syncs Cloudflare zones and DNS-only A/AAAA/CNAME records.
- Manages one logical hostname per failover group.
- Detects backup targets as IPv4, IPv6, or hostname in the same failover group.
- Publishes IPv4 targets as A, IPv6 targets as AAAA, and hostname targets as CNAME.
- Runs TCP health checks from the controller and optional China probe agents.
- Switches DNS by priority and weight, then fails back automatically when better targets recover.
- Sends webhook events for status changes and DNS switches.

## Quick start

1. Copy `.env.example` to `.env`.
2. Generate an encryption key:

   ```powershell
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

3. Set `SECRET_KEY` and `APP_ENCRYPTION_KEY` in `.env`.
4. Start the stack:

   ```powershell
   docker compose up --build
   ```

5. Open `http://localhost:8080`.

## Existing Nginx/MySQL/Supervisor servers

Use `deploy/README.md` for direct deployment. The backend supports SQLite by default and MySQL through a `mysql+pymysql://...` `DATABASE_URL`.

## Cloudflare token permissions

Create an API token with:

- `Zone Read`
- `DNS Read`
- `DNS Write`

Scope it to the zones you want this system to manage.

## China probe agent

Create an agent in the dashboard. The UI will show the token once. On the China server:

```powershell
docker run --restart unless-stopped `
  -e CONTROL_URL=https://your-controller.example.com `
  -e AGENT_TOKEN=the-one-time-token `
  cloudflare-dns-agent
```

The agent only makes outbound HTTPS requests to the controller.
