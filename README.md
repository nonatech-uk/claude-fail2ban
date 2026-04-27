# claude-fail2ban

Per-host log analyser that pre-filters suspicious entries, asks an LLM to classify per-IP behaviour, and bans confirmed threats. Designed to run on multiple hosts with structured logs aggregated through journald → Loki.

## Hosts

| Role | Hosts | Source | Ban backend |
|---|---|---|---|
| `caddy` | mees-app-server, albury-app-server | Caddy JSON access logs | `fail2ban-client set <jail> banip` |
| `mailcow` | mees-mail-server, albury-mail-server | journald units (postfix, dovecot, nginx) | mailcow REST API |

## Provider chain

Ordered list, first parseable result wins. Failures emit `LLM_FALLBACK` and continue.

1. **Anthropic Haiku** (`claude-haiku-4-5-20251001`) — primary at cutover, no behavioural change vs. the old single-provider script.
2. **Local Qwen** via Ollama (`qwen3.6:35b-a3b`, `think=false`) — once shadow-validated, swap order so Qwen drives bans and Anthropic only fires on Qwen failures.

Phase 1.5 shadow mode (`[shadow]` block in config) calls a second provider in parallel after the primary returns. Comparison is logged via `LLM_SHADOW_COMPARE` / `LLM_SHADOW_SUMMARY` events; bans are *only* driven by the primary chain.

## Layout on each host

| Path | Owner | Contents |
|---|---|---|
| `/opt/claude-fail2ban/` | root | Code + venv, target of `install.sh` |
| `/etc/claude-fail2ban/config.toml` | root | Per-host config (delivered via fleet-sync) |
| `/etc/claude-fail2ban/.env` | root, `0600` | API keys, healthcheck URL — staged out-of-band |
| `/etc/claude-fail2ban/whitelist.txt` | root | IP/CIDR whitelist |
| `/var/lib/claude-fail2ban/state.json` | root | File offsets / journald cursors |
| `/var/lib/claude-fail2ban/daily-digest.json` | root | Accumulated ban-recommended items |
| `/var/lib/claude-fail2ban/GeoLite2-Country.mmdb` | root | GeoIP DB (manual download) |
| `/etc/systemd/system/claude-fail2ban.{service,timer}` | root | 15-min analyser |
| `/etc/systemd/system/claude-fail2ban-digest.{service,timer}` | root | Daily 06:00 digest email |

The repo source-of-truth lives in stu's home (`~stu/code/claude-fail2ban` on the dev host). It is not deployed to `/opt/` directly — `install.sh` copies the package tree.

## Initial deploy on a new host

```sh
# 1. Clone + install
git clone git@github.com:nonatech-uk/claude-fail2ban.git /tmp/claude-fail2ban
sudo /tmp/claude-fail2ban/install.sh

# 2. Stage config (use fleet-sync long-term; manual is fine bootstrap)
sudo cp /tmp/claude-fail2ban/examples/config.caddy.toml /etc/claude-fail2ban/config.toml
sudo cp /tmp/claude-fail2ban/examples/whitelist.txt /etc/claude-fail2ban/whitelist.txt

# 3. Stage secrets per host (NEVER commit these)
sudo install -m 0700 -d /etc/claude-fail2ban
sudo tee /etc/claude-fail2ban/.env >/dev/null <<'EOF'
ANTHROPIC_API_KEY=sk-ant-host-specific-key
HEALTHCHECK_URL=https://hc-ping.com/<uuid>
QWEN_URL=https://10.8.0.1:8442
QWEN_TOKEN=<host-specific-bearer>
# mailcow hosts only:
MAILCOW_API_URL=https://mail.example.com
MAILCOW_API_KEY=<mailcow-rw-key>
EOF
sudo chmod 600 /etc/claude-fail2ban/.env

# 4. Stage GeoIP DB (one-time)
sudo cp GeoLite2-Country.mmdb /var/lib/claude-fail2ban/

# 5. Smoke test
sudo systemctl start claude-fail2ban.service
sudo journalctl -u claude-fail2ban -n 50 -o cat | jq .

# 6. Enable when happy
sudo systemctl enable --now claude-fail2ban.timer claude-fail2ban-digest.timer
```

## Updating an existing host

```sh
cd ~/code/claude-fail2ban && git pull
sudo ./install.sh
```

`install.sh` is idempotent. Timers do not need restarting unless unit files changed; if they did, `daemon-reload` runs automatically and the next timer fire picks up the new code.

## Schema

Every line in the journal is a single JSON object. Stable fields:

| Field | Always | Notes |
|---|---|---|
| `ts` | yes | UTC ISO8601 |
| `event` | yes | `RUN_START`, `LOGS_READ`, `FILTERED`, `BATCH_CAPPED`, `LLM_CALL`, `LLM_FALLBACK`, `LLM_SHADOW_CALL`, `LLM_SHADOW_COMPARE`, `LLM_SHADOW_SUMMARY`, `LLM_SHADOW_FAILED`, `LLM_NO_PROVIDERS`, `LLM_ALL_FAILED`, `ANALYSIS`, `BANNED`, `BAN_BLOCKED`, `BAN_LIMIT`, `BAN_FAILED`, `DIGEST_APPEND`, `DIGEST_SEND`, `EMAIL_SENT`, `EMAIL_FAILED`, `RUN_END`, `CLAUDE_CALL` (legacy alias of `LLM_CALL`) |
| `host_role` | most | `caddy` \| `mailcow` |
| `level` | warn/err only | `warn` \| `error` |
| `ip`, `country`, `threat_level`, `classification`, `ban_recommended`, `reason`, `action` | per-IP events | |
| `provider`, `model`, `tokens_in`, `tokens_out`, `cache_read`, `cache_create`, `latency_ms`, `fallback_reason` | LLM events | |
| `version` | `RUN_START` | git short rev when the install was a `git clone` |

`host_role`, `event`, etc. live in the JSON body — *not* promoted to Loki labels (would explode stream cardinality).

## Useful queries

```logql
# All runs from a given host today
{host="mees-app-server", syslog_identifier="claude-fail2ban"} |= "RUN_END"

# Token spend per provider over 24h
sum by (provider) (
  rate({syslog_identifier="claude-fail2ban"} | json | event="LLM_CALL"
       | unwrap tokens_in [24h])
)

# Shadow agreement rate
sum by (verdict) (
  count_over_time({syslog_identifier="claude-fail2ban"}
                  | json | event="LLM_SHADOW_COMPARE" [24h])
)

# Recent bans across the fleet
{syslog_identifier="claude-fail2ban"} | json | event="BANNED"
```
