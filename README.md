# VPS Monitoring

Discord bot for a VPS, doing two jobs:

- **Alerting** — watches for brute-force activity, SSH login attempts (via `fail2ban`) and HTTP request rate on a public subdomain (via Caddy's access log), and posts color-coded alert embeds (🟢 recovered / 🟠 warning / 🔴 critical) to a Discord channel.
- **Slash commands** — answers `/status`, `/cpu`, `/mem`, `/disk`, `/docker`, `/updates` and `/uptime` on demand with the host's current health. Same command set, and the same embed shape, as the sibling `pi-monitoring` bot, so both hosts answer the same questions the same way.

## How it works

- **SSH bans**: tails `fail2ban.log`. Every `Ban` on the `sshd` jail fires a 🔴 critical alert; every `Unban` that clears the last banned IP fires a 🟢 recovered alert. Detection itself is delegated to `fail2ban` — this bot only reports its bans/unbans.
- **HTTP request rate**: tails Caddy's JSON access log, counts requests per source IP within a sliding time window for a given host. Crossing `HTTP_WARN_THRESHOLD` fires 🟠, crossing `HTTP_CRIT_THRESHOLD` fires 🔴, dropping back below fires 🟢. The alert includes the IP's most-requested paths, so you can see what was actually targeted.
- **Did the brute-force succeed?** — the piece `fail2ban`/rate-limiting alone can't answer, since a fast or lucky attacker can log in before triggering a ban:
  - **SSH**: tails `/var/log/auth.log` for `Failed password` / `Invalid user` lines, keeping a per-IP failure count in a sliding window. If an `Accepted` login then comes from an IP that had `SSH_BRUTEFORCE_SUCCESS_THRESHOLD`+ recent failures, fires a 🔴 "SSH brute-force SUCCEEDED" alert.
  - **HTTP (Home Assistant)**: tails Caddy's log for the login flow. `POST /auth/login_flow/...` requests are counted per IP; a subsequent successful `POST /auth/token` from that IP is reported — 🔴 "brute-force SUCCEEDED" if it followed `HTTP_BRUTEFORCE_SUCCESS_THRESHOLD`+ attempts, otherwise a low-key 🔵 informational "new login" note (useful as a general audit trail even when nothing's wrong).
- Alerts only fire on **state transitions** for the ban/rate monitors — no spam. The success-detection alerts are one-off audit events by nature (each login is a discrete occurrence), so they fire every time, but only for genuinely new events (never repeated for the same login).

### Slash commands

| Command | Shows |
|---------|-------|
| `/status` | One-screen overview: CPU, RAM, disk `/`, containers, pending updates, uptime |
| `/cpu` | Utilisation across all cores, load averages, top 6 processes by CPU |
| `/mem` | RAM + swap usage, top 6 processes by resident memory |
| `/disk` | Usage bar per mounted host filesystem |
| `/docker` | Every container with state/health |
| `/updates` | Pending apt packages, which are security, and reboot-required status |
| `/uptime` | Uptime, boot time, load averages |

Commands are registered **guild-scoped** to `DISCORD_GUILD_ID`, so they appear instantly rather than after Discord's up-to-an-hour global propagation. Leave `DISCORD_GUILD_ID` empty to run the bot alerts-only with no commands.

Note that `pi-monitoring` registers the *same* command names. Discord scopes commands per application, so both work — the picker labels each with its bot — but expect two `/status` entries if both bots are in the same server.

### Seeing the host from inside the container

The bot reports on the host, but runs in a container, so it has to be shown the host explicitly. `docker-compose.yml` does this with two mounts and no extra capabilities:

| Source | Needs | Without it |
|--------|-------|------------|
| CPU, RAM, load, uptime | nothing — `/proc`'s aggregate files are host-wide already | — |
| Top processes, disk, apt/dpkg state, `/run/reboot-required` | `/:/host:ro` (read-only) | `/cpu`, `/mem`, `/disk` and `/updates` say so instead of reporting container figures |
| Container list (`/docker`) | `/var/run/docker.sock` | `/docker` reports the socket is unmounted |

The host bind is recursive, so it carries the host's procfs at `/host/proc` — that is where the process lists come from. The obvious alternative, `pid: host`, is deliberately **not** used: it works for processes but makes apt skip Ubuntu's phased updates (it compares PID 1's root with its own, decides it is in a chroot, and stops deferring), so `/updates` would report upgrades the host is actually holding back — on this VPS, 32 instead of the true 25. Reading `/host/proc` gets both right and grants less.

The Docker socket is the one mount worth knowing about: `:ro` makes only the socket *file* read-only — the Engine API behind it stays fully writable, so anything that compromises this container compromises the host. That is the price of `/docker`; drop the line from `docker-compose.yml` and the other six commands carry on unaffected. Each source degrades to a clear message when its mount is missing, rather than silently reporting the container's own numbers.

`/updates` reads the host's real apt state by pointing the container's `apt-get -s dist-upgrade` at the host tree (`-o Dir=/host`), which reports package-for-package identically to running it on the host. If that ever fails it falls back to the counts in Ubuntu's daily `update-notifier` motd summary — no package names, and up to a day stale, flagged as such.

## Setup

1. Create a Discord Application + Bot at [discord.com/developers/applications](https://discord.com/developers/applications), copy its token, and invite it to your server with the `Send Messages` + `Embed Links` permissions and the scopes `bot` **and** `applications.commands` (OAuth2 → URL Generator). The second scope is what allows slash commands; if the bot was invited before they existed, re-invite it with that scope added.
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

All thresholds and paths are in `.env` (see `.env.example`, which is a template — the real `.env` is git-ignored and lives on the VPS): fail2ban log/jail, SSH port (for alert context only), Caddy log path, monitored host, warn/critical request-rate thresholds, and the brute-force-success correlation window/thresholds. `DISCORD_GUILD_ID` enables slash commands, `HOST_LABEL` names the VPS in their embeds, and `HOST_ROOT` says where the host root is bind-mounted (set it to `/` if you ever run the bot outside a container).

`TRUSTED_IPS` (comma-separated) downgrades a "brute-force SUCCEEDED" alert to a low-key 🔵 info note for known IPs (e.g. your own), instead of 🔴 critical — useful for typo'd passwords/usernames from your own machine, or repeated testing.

Note: the container needs to read `fail2ban.log`, `auth.log` (both `root:adm`) and Caddy's access log (`caddy:caddy`). `docker-compose.yml` bind-mounts them read-only and joins the container to the host's `adm`/`caddy` groups via `group_add` (GIDs from `getent group adm caddy` on the VPS — update them there if they ever differ). If Caddy's log file mode isn't `640`, adjust its `Caddyfile` `log` block to set `mode 640` (see the `home-automation` repo's `docs/remote-access.md` for the full Caddy config).

## Related VPS hardening done alongside this bot

- `PasswordAuthentication no` in `/etc/ssh/sshd_config.d/00-password-auth.conf` (named `00-` so it's read *before* `50-cloud-init.conf`, which sets it back to `yes` — sshd_config keeps the *first* value seen for a given directive, so a later/higher-numbered file does **not** win). Key-only SSH access makes SSH brute-force structurally impossible, not just detected.
- `fail2ban`'s `[DEFAULT] ignoreip` (in `/etc/fail2ban/jail.local`) should include your own IP(s) and the Tailscale CGNAT range (`100.64.0.0/10`), so testing or a few real typos from a trusted source never actually bans you.

## Logs

```
docker compose -f ~/apps/vps-monitoring/docker-compose.yml logs -f
```
