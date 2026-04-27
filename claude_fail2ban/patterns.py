"""Shared suspicion patterns used across sources."""

from __future__ import annotations

import re

BAD_PATH_PATTERNS = re.compile(
    r"(?i)"
    r"(\.env|\.git|\.aws|\.ssh|\.docker|\.kube"
    r"|wp-login\.php|xmlrpc\.php|wp-admin"
    r"|phpMyAdmin|phpmyadmin|pma|adminer"
    r"|/actuator|/solr|/jenkins|/manager"
    r"|/shell|/cmd|/eval|/exec"
    r"|/etc/passwd|/proc/self"
    r"|\.\./"
    r"|<script|SELECT\s|UNION\s|OR\s1=1"
    r"|/vendor/phpunit|/cgi-bin|/debug|/console"
    r"|/config\.php|/info\.php|/test\.php"
    r"|/backup|\.sql|\.bak|\.old|\.orig"
    r"|/api/v1/pods|/\.well-known/security)"
)

SUSPICIOUS_STATUSES = {400, 401, 403, 405, 406, 408, 411, 413, 414, 429, 444, 500, 502, 503}
SUSPICIOUS_METHODS = {"CONNECT", "TRACE", "DEBUG", "PROPFIND", "PATCH", "DELETE", "PUT", "TRACK"}
