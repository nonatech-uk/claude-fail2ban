# CLAUDE.md

Notes for Claude Code working in this repo.

## What this is

A multi-host log analyser. Each host runs `python -m claude_fail2ban` every 15 min via a systemd timer. The package has pluggable **sources** (where logs come from), **actions** (how to ban), and **providers** (which LLM to ask). Per-host `config.toml` selects which of each to use.

## Where things live

- `claude_fail2ban/` — the importable package
  - `cli.py` — argparse + orchestration loop
  - `analyzer.py` — provider chain walker + shadow-mode comparison
  - `config.py` — TOML loader, builds source/action/provider instances
  - `prompts.py` — single shared `SYSTEM_PROMPT`
  - `log.py` — JSON-line stdout logger (NOT Python `logging`); always write events with `log.emit("EVENT_NAME", **fields)`
  - `state.py`, `geoip.py`, `whitelist.py`, `health.py`, `email_alert.py`, `digest.py` — leaf utilities
  - `sources/` — `Source` ABC + `caddy_json.py`. Add `mailcow_journald.py`, `mailcow_nginx.py` for Phase 4.
  - `actions/` — `Action` ABC + `fail2ban_client.py`. Add `mailcow_api.py` for Phase 4.
  - `providers/` — `LLMProvider` ABC + `anthropic_provider.py`, `ollama_openai.py`, `ollama_native.py`.
- `systemd/` — units copied to `/etc/systemd/system/` by `install.sh`
- `examples/` — per-role `config.*.toml` templates
- `install.sh` — idempotent installer; safe to re-run

Do **not** look in `/opt/claude-fail2ban/` for the source — that path is the deployment target. Edit here, push, then `./install.sh` on the host.

## Running

Local sanity check (with venv):

```sh
cd /opt/claude-fail2ban && set -a && . /etc/claude-fail2ban/.env && set +a \
  && /opt/claude-fail2ban/.venv/bin/python -m claude_fail2ban \
       --config /etc/claude-fail2ban/config.toml --dry-run
```

Through systemd:

```sh
sudo systemctl start claude-fail2ban.service
journalctl -u claude-fail2ban --since="2min ago" -o cat | jq .
```

## Conventions

- **Every log line is JSON.** New events should use the existing schema fields where they exist (`ip`, `host_role`, `event`, `provider`, `model`, `tokens_in`, etc.). Don't promote new high-cardinality fields to Loki labels — keep them in the JSON body.
- **No file logging.** Stdout only. systemd captures it with `SyslogIdentifier=claude-fail2ban`.
- **Failures should never crash a run.** Provider errors raise `ProviderError(reason)` with one of the documented reasons; the orchestrator catches and falls through. Action errors return `False`. Source errors should log `*_PARSE_ERROR` and skip the entry.
- **Provider order = priority order.** First parseable result wins. Shadow runs *after* the winning primary call.
- **Existing event names are stable.** `RUN_START`, `LOGS_READ`, `FILTERED`, `ANALYSIS`, `BANNED`, `RUN_END` etc. — historical Loki queries depend on these. New events are fine; renaming old ones isn't.

## Testing changes

There's no formal test suite yet. Validation flow:

1. Edit code in `~stu/code/claude-fail2ban/`.
2. Either commit + push and `./install.sh` on the host, or rsync directly to `/opt/claude-fail2ban/` for fast iteration.
3. `sudo systemctl start claude-fail2ban.service` (in `enforce`, `warn`, or `--dry-run`).
4. Check `journalctl -u claude-fail2ban --since="2min ago" -o cat | jq .` — every line must parse as JSON, every run must end with `RUN_END`.

## Phases

| Phase | What | Where it stands |
|---|---|---|
| 1 | Refactor existing analyser into the package above; switch logging to journald JSON | Done on mees-app-server |
| 1.5 | Shadow-mode validation: run Qwen alongside Anthropic for ~3 days, compare verdicts | Done on mees-app-server, baking |
| 2 | GitHub repo + per-host config via fleet-sync | In progress (this repo) |
| 3 | Roll out to albury-app-server | Pending |
| 4 | Mailcow source (`mailcow_journald.py`, `mailcow_nginx.py`) + ban backend (`mailcow_api.py`); roll out to mees-mail-server | Pending |
| 5 | Roll out to albury-mail-server | Pending |
| 6 | Central reporter — daily Loki-driven cross-host digest | Pending |

## Things that bit me last time

- **Negative state offsets** crash `f.seek()`. `caddy_json.py` clamps; do the same in any new source.
- **Reasoning models eat tokens silently.** Qwen3 family generates a `reasoning` field on Ollama's OpenAI-compat endpoint that doesn't count as `completion_tokens` but blocks for 30+ seconds. Use the native `/api/chat` endpoint with `think: false` (`ollama_native.py`).
- **fleet-sync clobbers file modes.** Any per-host config delivered via fleet-sync needs `chmod 0644` in the manifest's `reload:` line. See `feedback_fleet_sync_perms` in memory.
- **`/opt/caddy-claude-analysis/` is the OLD deployment.** Read it for reference if you need to compare behaviour, but don't edit it. Once Phase 1.5 is signed off, archive it.
