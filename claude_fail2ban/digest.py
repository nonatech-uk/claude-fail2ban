"""Per-host daily digest: accumulates ban-recommended items, sends summary email."""

from __future__ import annotations

import datetime
import json
from pathlib import Path

from . import email_alert, geoip, log

DEFAULT_DIGEST_FILE = Path("/var/lib/claude-fail2ban/daily-digest.json")

THREAT_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "none": "#6b7280",
}
_THREAT_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


def append(
    analysis: list[dict],
    mode: str,
    ip_targets: dict[str, list[str]],
    *,
    path: Path = DEFAULT_DIGEST_FILE,
) -> None:
    ban_items = [a for a in analysis if a.get("ban_recommended")]
    if not ban_items:
        return

    existing: list[dict] = []
    if path.exists():
        try:
            existing = json.loads(path.read_text())
        except (json.JSONDecodeError, ValueError):
            existing = []

    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for item in ban_items:
        ip = item.get("ip", "?")
        item["_digest_ts"] = timestamp
        item["_mode"] = mode
        item["_targets"] = ip_targets.get(ip, [])
        item["_country"] = geoip.lookup_country(ip)

    existing.extend(ban_items)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(existing, indent=2))
    log.emit("DIGEST_APPEND", added=len(ban_items), total=len(existing))


def send(
    *,
    to: str,
    sender: str,
    path: Path = DEFAULT_DIGEST_FILE,
    host_role: str = "caddy",
) -> None:
    if not path.exists():
        log.emit("DIGEST_SEND", status="no_file")
        return

    try:
        items = json.loads(path.read_text())
    except (json.JSONDecodeError, ValueError):
        items = []

    if not items:
        log.emit("DIGEST_SEND", status="empty")
        path.unlink(missing_ok=True)
        return

    subject, body = _build(items, host_role=host_role)
    if subject:
        email_alert.send(subject, body, to=to, sender=sender)
        log.emit("DIGEST_SEND", events=len(items), status="sent")
    path.unlink(missing_ok=True)


def _build(items: list[dict], *, host_role: str) -> tuple[str, str]:
    if not items:
        return "", ""

    by_ip: dict[str, dict] = {}
    for item in items:
        ip = item.get("ip", "?")
        cur = by_ip.get(ip)
        if cur is None or _THREAT_ORDER.get(item.get("threat_level", "none"), 0) > \
                _THREAT_ORDER.get(cur.get("threat_level", "none"), 0):
            by_ip[ip] = item
        targets = by_ip[ip].setdefault("_targets", [])
        for t in item.get("_targets", []):
            if t not in targets:
                targets.append(t)

    sorted_ips = sorted(
        by_ip.values(),
        key=lambda x: _THREAT_ORDER.get(x.get("threat_level", "none"), 0),
        reverse=True,
    )
    date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    subject = (
        f"[DAILY] {host_role.title()} threat summary: "
        f"{len(sorted_ips)} IPs flagged — {date_str}"
    )

    rows = ""
    for item in sorted_ips:
        ip = item.get("ip", "?")
        country = item.get("_country") or geoip.lookup_country(ip)
        threat = item.get("threat_level", "?")
        color = THREAT_COLORS.get(threat, "#6b7280")
        mode = item.get("_mode", "?")
        action = "banned" if mode == "enforce" else "warned"
        targets = item.get("_targets", [])
        targets_html = "<br>".join(
            f'<span style="font-family:monospace;font-size:12px">{t}</span>'
            for t in targets[:5]
        )
        if len(targets) > 5:
            targets_html += f'<br><span style="color:#94a3b8;font-size:12px">+{len(targets)-5} more</span>'
        rows += f"""<tr>
  <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace">{ip}</td>
  <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">{country}</td>
  <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">
    <span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{threat}</span>
  </td>
  <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">{item.get('classification', '?').replace('_', ' ')}</td>
  <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">{targets_html}</td>
  <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:13px;color:#374151">{item.get('reason', '')}</td>
  <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">
    <span style="font-size:12px;color:#64748b">{action}</span>
  </td>
</tr>"""

    counts: dict[str, int] = {}
    for item in sorted_ips:
        counts[item.get("threat_level", "unknown")] = counts.get(item.get("threat_level", "unknown"), 0) + 1
    summary = ", ".join(f"{counts[l]} {l}" for l in ("critical", "high", "medium", "low") if counts.get(l, 0)) or "no threats"

    html = f"""\
<html>
<body style="margin:0;padding:20px;background:#f9fafb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">
<div style="max-width:900px;margin:0 auto;background:#fff;border-radius:8px;border:1px solid #e5e7eb;overflow:hidden">
  <div style="background:#1e293b;padding:16px 24px">
    <h2 style="margin:0;color:#fff;font-size:18px">Daily {host_role.title()} Threat Summary</h2>
    <p style="margin:4px 0 0;color:#94a3b8;font-size:13px">{date_str} &middot; {len(sorted_ips)} unique IPs &middot; {len(items)} total events &middot; {summary}</p>
  </div>
  <div style="padding:16px 24px">
    <table style="width:100%;border-collapse:collapse;font-size:14px">
      <thead>
        <tr style="background:#f8fafc;text-align:left">
          <th style="padding:10px 12px;border-bottom:2px solid #e5e7eb;color:#64748b;font-weight:600">IP</th>
          <th style="padding:10px 12px;border-bottom:2px solid #e5e7eb;color:#64748b;font-weight:600">Country</th>
          <th style="padding:10px 12px;border-bottom:2px solid #e5e7eb;color:#64748b;font-weight:600">Threat</th>
          <th style="padding:10px 12px;border-bottom:2px solid #e5e7eb;color:#64748b;font-weight:600">Classification</th>
          <th style="padding:10px 12px;border-bottom:2px solid #e5e7eb;color:#64748b;font-weight:600">Targets</th>
          <th style="padding:10px 12px;border-bottom:2px solid #e5e7eb;color:#64748b;font-weight:600">Reason</th>
          <th style="padding:10px 12px;border-bottom:2px solid #e5e7eb;color:#64748b;font-weight:600">Action</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
  </div>
  <div style="padding:12px 24px;background:#f8fafc;border-top:1px solid #e5e7eb;font-size:12px;color:#94a3b8">
    Daily digest from claude-fail2ban &middot; Logs: journalctl -u claude-fail2ban
  </div>
</div>
</body>
</html>"""
    return subject, html
