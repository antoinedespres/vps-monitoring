# VPS Monitoring

Discord bot that watches a VPS for brute-force activity — SSH login attempts (via `fail2ban`) and HTTP request rate on a public subdomain (via Caddy's access log) — and posts color-coded alert embeds (🟢 recovered / 🟠 warning / 🔴 critical) to a Discord channel.

## How it works

- **SSH bans**: tails `fail2ban.log`. Every `Ban` on the `sshd` jail fires a 🔴 critical alert; every `Unban` that clears the last banned IP fires a 🟢 recovered alert. Detection itself is delegated to `fail2ban` — this bot only reports its bans/unbans.
- **HTTP request rate**: tails Caddy's JSON access log, counts requests per source IP within a sliding time window for a given host. Crossing `HTTP_WARN_THRESHOLD` fires 🟠, crossing `HTTP_CRIT_THRESHOLD` fires 🔴, dropping back below fires 🟢. The alert includes the IP's most-requested paths, so you can see what was actually targeted.
- **Did the brute-force succeed?** — the piece `fail2ban`/rate-limiting alone can't answer, since a fast or lucky attacker can log in before triggering a ban:
  - **SSH**: tails `/var/log/auth.log` for `Failed password` / `Invalid user` lines, keeping a per-IP failure count in a sliding window. If an `Accepted` login then comes from an IP that had `SSH_BRUTEFORCE_SUCCESS_THRESHOLD`+ recent failures, fires a 🔴 "SSH brute-force SUCCEEDED" alert.
  - **HTTP (Home Assistant)**: tails Caddy's log for the login flow. `POST /auth/login_flow/...` requests are counted per IP; a subsequent successful `POST /auth/token` from that IP is reported — 🔴 "brute-force SUCCEEDED" if it followed `HTTP_BRUTEFORCE_SUCCESS_THRESHOLD`+ attempts, otherwise a low-key 🔵 informational "new login" note (useful as a general audit trail even when nothing's wrong).
- Alerts only fire on **state transitions** for the ban/rate monitors — no spam. The success-detection alerts are one-off audit events by nature (each login is a discrete occurrence), so they fire every time, but only for genuinely new events (never repeated for the same login).

## Setup

1. Create a Discord Application + Bot at [discord.com/developers/applications](https://discord.com/developers/applications), copy its token, and invite it to your server with the `Send Messages` + `Embed Links` permissions (OAuth2 → URL Generator → scope `bot`).
2. On the VPS: `mkdir -p ~/apps/vps-monitoring`, copy `docker-compose.yml` there, then `cp .env.example .env` (fill in `DISCORD_BOT_TOKEN`) in that same directory.
3. Log the VPS into ghcr.io once, with a PAT that has `read:packages` (create at [github.com/settings/tokens](https://github.com/settings/tokens)):
   ```
   echo <token> | docker login ghcr.io -u <github-username> --password-stdin
   ```
4. `docker compose pull && docker compose up -d`.

From then on, deploys happen automatically via CI (see below) — there's no manual redeploy step for day-to-day changes.

## CI/CD

[`.github/workflows/release-and-deploy.yml`](.github/workflows/release-and-deploy.yml) runs on every push to `main`:

1. **Version + tag**: bumps the patch version in [`VERSION`](VERSION), commits it (`[skip ci]`, so it doesn't re-trigger itself), and pushes a matching `vX.Y.Z` git tag.
2. **Build + push**: builds the Docker image and pushes `ghcr.io/<owner>/<repo>:<version>` and `:latest`.
3. **Deploy**: SSHes into the VPS and runs `docker compose pull && docker compose up -d` in `~/apps/vps-monitoring`.

Workflow: branch → PR → merge to `main` → the above runs automatically. Required repo secrets (`Settings → Secrets and variables → Actions`): `VPS_HOST`, `VPS_SSH_PORT`, `VPS_SSH_USER`, `VPS_SSH_KEY` (a dedicated deploy keypair — not your personal key — with its public half in the VPS's `~/.ssh/authorized_keys`). The repo's default `GITHUB_TOKEN` needs "Read and write permissions" under `Settings → Actions → General → Workflow permissions` for the version-bump commit/tag push and the `ghcr.io` push to work.

## Configuration

All thresholds and paths are in `.env` (see `.env.example`): fail2ban log/jail, SSH port (for alert context only), Caddy log path, monitored host, warn/critical request-rate thresholds, and the brute-force-success correlation window/thresholds.

`TRUSTED_IPS` (comma-separated) downgrades a "brute-force SUCCEEDED" alert to a low-key 🔵 info note for known IPs (e.g. your own), instead of 🔴 critical — useful for typo'd passwords/usernames from your own machine, or repeated testing.

Note: the container needs to read `fail2ban.log`, `auth.log` (both `root:adm`) and Caddy's access log (`caddy:caddy`). `docker-compose.yml` bind-mounts them read-only and joins the container to the host's `adm`/`caddy` groups via `group_add` (GIDs from `getent group adm caddy` on the VPS — update them there if they ever differ). If Caddy's log file mode isn't `640`, adjust its `Caddyfile` `log` block to set `mode 640` (see the `home-automation` repo's `docs/remote-access.md` for the full Caddy config).

## Related VPS hardening done alongside this bot

- `PasswordAuthentication no` in `/etc/ssh/sshd_config.d/00-password-auth.conf` (named `00-` so it's read *before* `50-cloud-init.conf`, which sets it back to `yes` — sshd_config keeps the *first* value seen for a given directive, so a later/higher-numbered file does **not** win). Key-only SSH access makes SSH brute-force structurally impossible, not just detected.
- `fail2ban`'s `[DEFAULT] ignoreip` (in `/etc/fail2ban/jail.local`) should include your own IP(s) and the Tailscale CGNAT range (`100.64.0.0/10`), so testing or a few real typos from a trusted source never actually bans you.

## Logs

```
docker compose -f ~/apps/vps-monitoring/docker-compose.yml logs -f
```
