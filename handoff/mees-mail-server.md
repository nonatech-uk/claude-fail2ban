# claude-fail2ban — handoff for mees-mail-server (mailcow host)

> Place this file at `~stu/code/claude-fail2ban-handoff.md` on mees-mail-server, owned `stu:stu`. It briefs the next Claude Code session on what's done, what's next, and where the gotchas are. Once the host is fully deployed and Phase 4 closed out, archive or delete it.

## TL;DR

You are picking up a multi-host security analyser project in the middle of Phase 4 (mailcow deployment). On `mees-app-server` (the sister host) we shipped Phase 1/1.5/2 — a packaged version of an existing Caddy-log analyser, with a pluggable architecture, structured journald JSON, shadow-mode quality validation, and a GitHub repo. **Your job here is Phase 4: extend the package with mailcow-specific sources + ban backend, deploy on this host, validate end-to-end.**

The full plan is at `~stu/code/claude-fail2ban-plan.md` (you'll need to copy that across too) or via the original session: `/root/.claude/plans/there-is-a-claude-shimmering-aurora.md` on mees-app-server.

## What exists in the repo

`git@github.com:nonatech-uk/claude-fail2ban.git`, branch `main`. Stu is a member of `nonatech-uk` so `git clone` should just work as `stu` once the host has GitHub auth.

```
claude_fail2ban/           # the Python package
  cli.py                   # argparse + run loop
  analyzer.py              # provider chain + shadow comparison
  config.py                # TOML loader → builds source/action/provider instances
  patterns.py              # shared BAD_PATH_PATTERNS / SUSPICIOUS_STATUSES / SUSPICIOUS_METHODS
  prompts.py               # SYSTEM_PROMPT
  log.py                   # JSON-line stdout logger (use log.emit("EVENT", **fields))
  state.py geoip.py whitelist.py health.py email_alert.py digest.py
  sources/
    base.py caddy_json.py
    _docker_logs.py        # shared `docker logs --since` reader with cursor mgmt
    mailcow_docker.py      # postfix / dovecot / rspamd flavours
    mailcow_nginx.py       # combined-log-format access log parser
  actions/
    base.py fail2ban_client.py
    mailcow_api.py         # POST /api/v1/edit/fail2ban via X-API-Key
  providers/
    base.py anthropic_provider.py ollama_openai.py ollama_native.py
systemd/                   # service + timer units
examples/
  config.caddy.toml        # template for caddy hosts
  config.mailcow.toml      # template for THIS host — uses mailcow_docker source type
  whitelist.txt            # placeholder, deliver real one separately
install.sh                 # idempotent installer (copies package → /opt/claude-fail2ban)
README.md                  # operator-facing docs
CLAUDE.md                  # repo-level briefing for Claude (read it!)
```

> Note: the original handoff named the source `mailcow_journald.py` on the
> assumption mailcow's docker-compose stack would ship to journald. On
> mees-mail-server the docker daemon uses the default `json-file` log
> driver, so the source is named `mailcow_docker.py` and reads via
> `docker logs --since`. If a host changes the docker daemon log driver,
> a sibling `mailcow_journald.py` can be added.

## Phase 0 checks BEFORE writing code

Verify on this host:

1. **Mailcow container names.** docker-compose names are
   `mailcowdockerized-{postfix,dovecot,nginx}-mailcow-1` on stock installs
   (note the trailing `-1` and that mailcow uses `json-file` logging, not
   journald). Confirm:
   ```sh
   docker ps --format '{{.Names}}' | grep mailcowdockerized
   ```
   If they differ, update `container = "..."` in
   `examples/config.mailcow.toml`.

2. **Mailcow nginx log format.** Look at recent lines:
   ```sh
   docker logs --tail=5 mailcowdockerized-nginx-mailcow-1
   ```
   On mees-mail-server the format is **combined log format**, parsed by
   the regex in `claude_fail2ban/sources/mailcow_nginx.py`. Path
   suspicion shares `BAD_PATH_PATTERNS` from `claude_fail2ban/patterns.py`.

3. **Alloy presence.** This host should be shipping journald to Loki at `http://10.8.0.1:3100`:
   ```sh
   systemctl is-active alloy
   ls /etc/alloy/
   ```
   If absent, Phase 6 (central reporter) won't see this host's events. Flag to the user.

4. **Mailcow REST API access.** Confirm a working API key and endpoint:
   ```sh
   curl -H "X-API-Key: $MAILCOW_API_KEY" \
        "$MAILCOW_API_URL/api/v1/get/fail2ban" | jq '.active_bans | length'
   ```
   You'll need read+write scope on `/api/v1/edit/fail2ban`. The user creates these in the mailcow admin UI under Configuration → API.

5. **Mailcow's built-in fail2ban must KEEP RUNNING.** It handles threshold-based bans (5 SOGo failed logins, etc.). Don't try to replace it. claude-fail2ban runs *additionally* and catches slow / distributed / multi-vector cases that the built-in regex misses. Your `currently_banned()` reads mailcow's banlist via the API so you don't redundantly re-ban what mailcow already caught.

## What to build

### 1. `claude_fail2ban/sources/mailcow_journald.py`

Reads via `journalctl --since=<state_ts> --output=json _SYSTEMD_UNIT=<unit>`. State stores last-seen `__REALTIME_TIMESTAMP` per source. Pre-filter regexes per flavour:

- **postfix**: `SASL LOGIN authentication failed`, `postscreen` DNSBL hits, `NOQUEUE: reject`. IP from `[ip]:port` brackets.
- **dovecot**: `auth failed`, `disconnected (auth failed`. IP from `rip=`.
- (Optional) **rspamd**: `reject` actions.

Subclass `Source` (see `sources/base.py`). Constructor takes `unit: str` and `flavour: str` ("postfix"|"dovecot"|"rspamd") to pick the right regex set.

### 2. `claude_fail2ban/sources/mailcow_nginx.py`

Same shape; reads from the nginx unit. Pre-filter for:

- POST `/SOGo/so/<user>` or `/SOGo/connect` non-2xx → SOGo login attempts
- GET/POST `/admin/`, `/admin/dist/`, `/admin/index.php` non-2xx → admin UI brute force
- `/api/v1/` 401/403 → API auth failures
- `/Microsoft-Server-ActiveSync` 401 → ActiveSync brute force
- 404 storms from one IP → recon scanning
- Suspicious paths mailcow doesn't serve: `/wp-login.php`, `/phpmyadmin/`, `/.env`, `/.git/` — reuse `BAD_PATH_PATTERNS` (extract to `claude_fail2ban/patterns.py` first if you want to share with `caddy_json.py`).

### 3. `claude_fail2ban/actions/mailcow_api.py`

```python
def currently_banned(self) -> set[str]:
    r = requests.get(f"{url}/api/v1/get/fail2ban",
                     headers={"X-API-Key": key}, timeout=10)
    return {b["network"] for b in r.json().get("active_bans", [])}

def ban(self, ip, reason) -> bool:
    r = requests.post(f"{url}/api/v1/edit/fail2ban",
                      headers={"X-API-Key": key},
                      json={"items": ["banlist_add"],
                            "attr": {"network": ip}}, timeout=10)
    return r.ok
```

On 401 emit `event="MAILCOW_AUTH_ERROR"` (using `log.error(...)`) and fail healthcheck. Add a startup check: `GET /api/v1/get/status/version` → emit `MAILCOW_AUTH_OK`/`MAILCOW_AUTH_FAIL` so a stale key surfaces in Loki without anyone logging in.

### 4. Optional: escalation tracking

Mailcow REST exposes a single `BAN_TIME`; no native increment. If you want repeat-offender tracking, add `/var/lib/claude-fail2ban/offenders.db` (sqlite, columns: `ip TEXT PRIMARY KEY, ban_count INTEGER, first_seen TEXT, last_action TEXT`). Second offence within 30d → emit `event="REPEAT_OFFENDER"`. (Mailcow expires bans on its own schedule; don't fight it.)

### 5. Wire it through `config.py`

Add to `_build_source()`:
```python
if typ == "mailcow_journald":
    return MailcowJournaldSource(unit=spec["unit"], flavour=spec["flavour"])
if typ == "mailcow_nginx":
    return MailcowNginxSource(unit=spec["unit"])
```

And to `_build_action()`:
```python
if typ == "mailcow_api":
    return MailcowApiAction(url_env=spec["url_env"], key_env=spec["key_env"])
```

## Deploy steps on this host

```sh
# Clone (as stu)
mkdir -p ~/code && cd ~/code
git clone git@github.com:nonatech-uk/claude-fail2ban.git
cd claude-fail2ban

# Build + install (as root)
sudo ./install.sh

# Stage config — start from template, customise unit names
sudo cp examples/config.mailcow.toml /etc/claude-fail2ban/config.toml
sudo $EDITOR /etc/claude-fail2ban/config.toml
# - Set `mode = "warn"` for the first 24h
# - Confirm the three [[sources]] unit= strings
# - Confirm `[digest].sender` hostname

# Stage secrets — get keys from the user out-of-band.
# QWEN_URL goes via mees-app-server (10.128.0.2:8442) — that host has a
# DNAT/MASQUERADE rule forwarding to nas (10.8.0.1:8442) over WireGuard.
# Mail hosts on the Hetzner private network can't reach 10.8.0.1 directly.
sudo install -m 0700 -d /etc/claude-fail2ban
sudo tee /etc/claude-fail2ban/.env >/dev/null <<'EOF'
ANTHROPIC_API_KEY=sk-ant-host-specific-key
HEALTHCHECK_URL=https://hc-ping.com/<uuid>
QWEN_URL=https://10.128.0.2:8442
QWEN_TOKEN=<bearer-from-user>
MAILCOW_API_URL=https://mail.mees.st        # confirm exact URL with the user
MAILCOW_API_KEY=<read-write-mailcow-api-key>
EOF
sudo chmod 600 /etc/claude-fail2ban/.env

# Note on the QWEN forwarder: traffic from this host arrives at nas as if
# it came from mees-app-server's WireGuard IP (10.8.0.22) thanks to the
# MASQUERADE. Caddy's source-IP allowlist on nas needs to accept 10.8.0.22
# for any token presented through the forwarder — i.e. the source-IP gate
# becomes effectively shared between mees-app-server and any host using
# this forwarder. The bearer token is the authoritative auth.

# Stage GeoIP DB (one-time, copy from mees-app-server)
# scp mees-app-server:/var/lib/claude-fail2ban/GeoLite2-Country.mmdb /tmp/
sudo install -m 0644 /tmp/GeoLite2-Country.mmdb /var/lib/claude-fail2ban/

# Stage whitelist (per-host, NOT committed to repo)
sudo $EDITOR /etc/claude-fail2ban/whitelist.txt
# Include: 127.0.0.0/8, container nets, your trusted personal IP(s),
#         this host's public IP

# Smoke test in dry-run
cd /opt/claude-fail2ban
sudo bash -c 'set -a; . /etc/claude-fail2ban/.env; set +a; \
  /opt/claude-fail2ban/.venv/bin/python -m claude_fail2ban \
    --config /etc/claude-fail2ban/config.toml --dry-run' 2>&1 | jq .

# Run once via systemd (still warn mode)
sudo systemctl start claude-fail2ban.service
sudo journalctl -u claude-fail2ban --since="2min ago" -o cat | jq .

# When happy, enable
sudo systemctl enable --now claude-fail2ban.timer claude-fail2ban-digest.timer
```

## Validation

End-to-end check after deployment:

1. `sudo systemctl list-timers 'claude-fail2ban*'` — both timers should be active.
2. After 15 min, `journalctl -u claude-fail2ban --since="20min ago"` should show `RUN_END` events with `host_role: "mailcow"`.
3. **Manual ban test** when ready to flip to `mode = "enforce"`:
   - Pick an obvious offender from `journalctl -u <nginx-unit> --grep '/admin/' | head -20` or the mailcow logs MCP.
   - Force a `--enforce` run.
   - Verify the ban landed: `curl -H "X-API-Key: $K" "$URL/api/v1/get/fail2ban" | jq '.active_bans'`
   - Loki should show a matching `event="BANNED"` line.
4. Compare Anthropic vs Qwen verdicts via `LLM_SHADOW_COMPARE` events for ~24h before deciding to swap order.

## Things that bit us already

- **Reasoning model trap.** `qwen3.6:35b-a3b` on Ollama's `/v1/chat/completions` (OpenAI-compat) generates extensive `reasoning` tokens silently — caused 240s+ timeouts. Solution baked into the repo: use the `ollama_native` provider (`/api/chat` with `think: false`). Empirically ~10× faster on this model. The mailcow config template already uses it.
- **fleet-sync clobbers file modes.** Once you add this host to the fleet-sync manifest, prepend `chmod 0644` to the `reload:` line. See memory `feedback_fleet_sync_perms` on mees-app-server for context.
- **State offsets must be non-negative.** `caddy_json.py` clamps; do the same in your new sources (especially `mailcow_journald.py` where state stores a timestamp — guard against state corruption with sane defaults).
- **Edit tool changes file modes.** After editing any file under `/etc/claude-fail2ban/`, double-check perms — `.env` must stay `0600` and root-owned.
- **Old behaviour preserved on mees-app-server**: `/opt/caddy-claude-analysis/` is the legacy deployment. Don't touch it; the new code at `/opt/claude-fail2ban/` runs the timer.

## Useful Loki queries while validating

```logql
# All runs from this host today
{host="mees-mail-server", syslog_identifier="claude-fail2ban"} |= "RUN_END"

# Per-source filter rates (where is the noise?)
sum by (host_role) (
  count_over_time({syslog_identifier="claude-fail2ban"}
                  | json | event="FILTERED" [1h])
)

# Mailcow API auth health
{syslog_identifier="claude-fail2ban"}
  | json | event=~"MAILCOW_AUTH_OK|MAILCOW_AUTH_FAIL"
```

## Phase 5 / Phase 6 (later, not your immediate work)

- **Phase 5**: repeat all of this for `albury-mail-server`. Same config template, different secrets, possibly different mailcow unit names if versions differ.
- **Phase 6**: central daily reporter. Recommendation in the plan is a scheduled remote agent that queries Loki and sends one cross-host email digest, replacing per-host emails.

Good luck.
