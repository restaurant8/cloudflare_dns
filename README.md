# Cloudflare DNS Failover

A self-hosted Cloudflare DNS failover dashboard for DNS-only A, AAAA, and CNAME records.

## What it does

- Stores multiple Cloudflare API tokens with encryption.
- Limits repeated login failures to reduce brute-force risk.
- Syncs Cloudflare zones and DNS-only A/AAAA/CNAME records.
- Manages one logical hostname per failover group.
- Detects backup targets as IPv4, IPv6, or hostname in the same failover group.
- Publishes IPv4 targets as A, IPv6 targets as AAAA, and hostname targets as CNAME.
- Runs TCP health checks from the controller and optional China probe agents.
- Switches DNS by health and priority, then fails back automatically when better targets recover.
- Supports a scheduled peak-hours entry while retaining health-based fallback to other origins.
- Sends Telegram and webhook events for status changes and DNS switches.
- Manages Alibaba Cloud Mobile HTTPDNS built-in authoritative records in a separate failover menu through the existing azpanel integration, including per-account proxy routing, health thresholds, cooldowns, drift repair, and A/AAAA/CNAME switching.

## Alibaba Cloud HTTPDNS failover

Configure and enable the existing **azpanel** integration under **Auto IP Change**, using the same internal token configured as `CLOUDFLARE_DNS_INTERNAL_TOKEN` on azpanel. Alibaba Cloud AccessKeys stay in azpanel; this application only stores the selected account/Zone/record IDs and calls azpanel's authenticated internal gateway. The proxy assigned to each Alibaba Cloud account in azpanel is therefore also used for zone reads and record updates.

The separate **Alibaba Cloud HTTPDNS** menu adopts an existing Mobile HTTPDNS built-in authoritative A, AAAA, or CNAME record as the primary origin. Add backup origins, set their probe port and priority, and optionally adjust the supported Alibaba TTL and recovery cooldown. The regular scheduler then applies the same global probe timeout and fail/recovery thresholds used by Cloudflare failover.

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

Create an agent in the dashboard. The UI will show a one-line installer command once. Copy that full command to the China server and run it as root. It installs the agent under `/opt/cloudflare-dns-agent`, creates the `cloudflare-dns-agent` systemd service, and starts reporting TCP probe results.

```bash
curl -fsSL 'https://your-controller.example.com/api/agent/install.sh' -o /tmp/cloudflare-dns-agent-install.sh && CONTROL_URL='https://your-controller.example.com' AGENT_TOKEN='the-one-time-token' bash /tmp/cloudflare-dns-agent-install.sh
```

The agent only makes outbound HTTPS requests to the controller.
View logs with `journalctl -u cloudflare-dns-agent -f`.

## Security notes

- Cloudflare API tokens are encrypted with `APP_ENCRYPTION_KEY`.
- Telegram Bot tokens are encrypted with `APP_ENCRYPTION_KEY`.
- Agent registration tokens are stored as hashes; the raw token is only shown once.
- Webhook secrets are encrypted for new and updated webhooks. Legacy plaintext secrets still work and are encrypted the next time you edit them.
- Login attempts are rate limited by IP and username. Defaults: 5 failures within 15 minutes locks login for 15 minutes. Override with `LOGIN_MAX_FAILURES`, `LOGIN_FAILURE_WINDOW_SECONDS`, and `LOGIN_LOCKOUT_SECONDS`.
