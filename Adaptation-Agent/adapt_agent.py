#!/usr/bin/env python3
# adapt_agent.py — v3.7
# ============================================================
# COWRIE ADAPTIVE PERSONA AGENT
#
# CHANGES FROM v3.6 → v3.7:
#   [D-1] sdn_init_session() added — inserts a per-attacker default-
#         deny rule that blocks ALL TCP from that IP except the
#         honeypot SSH port.  Called automatically on the first
#         action from any new IP so no manual trigger is needed.
#         This is the foundation for expose/hide to actually work.
#   [D-2] sdn_expose_port() uses -I (insert at top) so the ACCEPT
#         rule lands BEFORE the default-deny DROP.  iptables walks
#         rules top-to-bottom and stops at the first match, so
#         ACCEPT at position 1 wins over the DROP further down.
#   [D-3] sdn_hide_port() rewritten — instead of inserting yet
#         another DROP (which was redundant once default-deny was
#         in place and confused the rule list), it now finds and
#         removes the ACCEPT rule for that port.  The default-deny
#         DROP already handles blocking; removing ACCEPT is enough.
#   [D-4] _track_session() calls sdn_init_session() on first entry
#         for a new IP.  Subsequent actions from the same IP do NOT
#         re-initialise (idempotent guard via 'not in sessions').
#   [D-5] sdn_init_session() tagged with the attacker's comment so
#         sdn_reset() picks it up automatically on session end —
#         no extra cleanup step needed.
#
# CHANGES FROM v3.5 → v3.6 (retained):
#   [C-1..C-6] Username-aware token paths
#
# CHANGES FROM v3.4 → v3.5 (retained):
#   [B-1..B-8] Inline SDN — no external sdn_enforcer.py
#
# CHANGES FROM v2.1 → v3.4 (retained):
#   [A-1..A-8] Core agent features
#
# SETUP:
#   pip3 install docker flask
#   sudo -u cowrie python3 adapt_agent.py
#
# SUDOERS:
#   cowrie ALL=(ALL) NOPASSWD: /sbin/tc
#   cowrie ALL=(ALL) NOPASSWD: /sbin/iptables
#   cowrie ALL=(ALL) NOPASSWD: /usr/bin/docker
#
# PORT FILTERING MODEL (v3.7):
#   On first action from any IP →  default-deny all TCP except port 2222
#   expose_port(ip, P)         →  ACCEPT rule inserted above the DROP
#   hide_port(ip, P)           →  ACCEPT rule for P removed; DROP resumes
#   containment(ip)            →  DROP everything including 2222 (full cut)
#   sdn_reset(ip)              →  all tagged rules removed (session end)
# ============================================================

import os
import re
import sys
import shutil
import subprocess
import logging
import ipaddress
import time
import threading
import hashlib
from collections import defaultdict
from pathlib import Path
from datetime import datetime
from flask import Flask, request, jsonify
import socket

# Honeyfs manager — file registry + pickle management + per-session rendering
try:
    from honeyfs_manager import (
        SessionRenderer,
        generate_dynamic_tokens as _hm_generate_tokens,
        cleanup_session_tokens,
    )
    HONEYFS_MANAGER_AVAILABLE = True
except ImportError:
    HONEYFS_MANAGER_AVAILABLE = False
    _tmp_log = logging.getLogger('adapt_agent')
    _tmp_log.warning("[INIT] honeyfs_manager.py not found — using inline fallback")

# ==============================
# 1. CONFIGURATION
# ==============================

COWRIE_HOME      = Path.home() / 'cowrie'
COWRIE_VENV      = COWRIE_HOME / 'cowrie-env'
COWRIE_BIN       = COWRIE_VENV / 'bin' / 'cowrie'
COWRIE_ACTIVATE  = COWRIE_VENV / 'bin' / 'activate'

COWRIE_CFG       = COWRIE_HOME / 'etc' / 'cowrie.cfg'
COWRIE_HONEYFS   = COWRIE_HOME / 'honeyfs'
COWRIE_FS_PICKLE = COWRIE_HOME / 'src' / 'cowrie' / 'data' / 'fs.pickle'
PERSONAS_DIR     = COWRIE_HOME / 'cowrie_personas'

HONEYTOKEN_SCRIPT = Path.home() / 'generate_honeytokens.py'

# NOTE: SDN_ENFORCER and SYSTEM_PYTHON3 removed in v3.5 — all SDN is inline.

# [A-1] Default port — matches adaptive_engine.py AGENT_URL
AGENT_PORT    = int(os.environ.get("AGENT_PORT",   "7000"))
AGENT_SECRET  = os.environ.get("AGENT_SECRET", "fyp-secret-2024")
AGENT_LOG     = Path.home() / 'lab' / 'logs' / 'adapt_agent.log'
RESTART_GRACE = 5

# Sandbox
SANDBOX_IMAGE     = os.environ.get("SANDBOX_IMAGE",   "sandbox-honeypot")
SANDBOX_NETWORK   = os.environ.get("SANDBOX_NETWORK", "lab-net")
SANDBOX_LOG_BASE  = Path(os.environ.get("SANDBOX_LOG_DIR",
                         str(Path.home() / 'lab' / 'logs' / 'sandbox_logs')))
SANDBOX_TTL       = int(os.environ.get("SANDBOX_TTL",       "1800"))
HONEYPOT_SSH_PORT = int(os.environ.get("HONEYPOT_SSH_PORT", "2222"))

# [A-5] Rate limiting
RATE_LIMIT_MAX    = 10
RATE_LIMIT_WINDOW = 60

# [A-6] Session cap
MAX_TRACKED_SESSIONS = 500

# [B-4] Throttle bandwidth
THROTTLE_RATE_KBPS = int(os.environ.get("THROTTLE_RATE_KBPS", "512"))

# [C-2] Username sanitization
_USERNAME_RE     = re.compile(r'[^a-zA-Z0-9._-]')
DEFAULT_USERNAME = "admin"

# ==============================
# 2. TTP MAPS
# ==============================

TTP_PERSONA_MAP = {
    "T1003": "ubuntu_server", "T1552": "ubuntu_server",
    "T1087": "ubuntu_server", "T1555": "ubuntu_server",
    "T1046": "iot_router",    "T1018": "iot_router",
    "T1083": "iot_router",    "T1070": "iot_router",    "T1595": "iot_router",
    "T1021": "windows_server","T1110": "windows_server",
    "T1550": "windows_server","T1558": "windows_server","T1136": "windows_server",
}

TTP_DECEPTION_LEVEL = {
    "T1046": "low",      "T1083": "low",
    "T1110": "medium",   "T1087": "medium",
    "T1003": "high",     "T1552": "high",
    "T1485": "critical", "T1048": "critical",
    "T1014": "critical", "T1611": "critical", "T1041": "critical",
    "T1098": "high",     "T1068": "high",     "T1562": "high",
    "T1574": "high",     "T1056": "high",     "T1074": "high",
    "T1505": "high",
    "T1027": "medium",   "T1070": "medium",   "T1105": "medium",
    "T1059": "medium",   "T1053": "medium",   "T1136": "medium",
    "T1021": "medium",   "T1078": "medium",
    "T1496": "low",
}

DECEPTION_LEVEL_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_PERSONA = "ubuntu_server"

# ==============================
# 3. LOGGING
# ==============================

Path(AGENT_LOG).parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(str(AGENT_LOG)),
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger('adapt_agent')

# ==============================
# 4. FLASK + STATE
# ==============================

app = Flask(__name__)

agent_state = {
    "active_persona":  "ubuntu_server",
    "last_switch":     None,
    "switch_count":    0,
    "start_time":      datetime.utcnow().isoformat(),
    "last_error":      None,
    "active_sessions": {},
}

_rate_buckets: dict = defaultdict(list)
_rate_lock = threading.Lock()

_sandbox_lock    = threading.Lock()
active_sandboxes = []

_attacker_last_level: dict = {}
_level_lock = threading.Lock()

# [C-6] Login username registry  attacker_ip → sanitized username
_session_username: dict = {}
_username_lock = threading.Lock()

# ==============================
# 5. AUTH + HELPERS
# ==============================

def check_auth(req) -> bool:
    return req.headers.get("X-Agent-Secret") == AGENT_SECRET


def check_rate_limit(source_ip: str) -> bool:
    now = time.time()
    with _rate_lock:
        ts = _rate_buckets[source_ip]
        _rate_buckets[source_ip] = [t for t in ts if now - t < RATE_LIMIT_WINDOW]
        if len(_rate_buckets[source_ip]) >= RATE_LIMIT_MAX:
            return False
        _rate_buckets[source_ip].append(now)
        return True


def validate_ip(ip_str: str) -> bool:
    if ip_str == 'unknown':
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_loopback or addr.is_unspecified:
            logger.warning(f"[SECURITY] Rejected loopback/unspecified IP: {ip_str}")
            return False
        return True
    except ValueError:
        return False


def validate_port(port_val) -> bool:
    try:
        return 1 <= int(port_val) <= 65535
    except (TypeError, ValueError):
        return False


def sanitize_username(raw: str) -> str:
    """
    [C-2] Strip characters that could enable path traversal or shell
    injection.  Permitted: a-z A-Z 0-9 . _ -
    Falls back to DEFAULT_USERNAME when the result would be empty.
    """
    cleaned = _USERNAME_RE.sub('', (raw or '').strip())
    return cleaned if cleaned else DEFAULT_USERNAME

# ==============================
# 6. PERSONA SWITCHER
# ==============================

def apply_persona(persona_name: str):
    source_dir = PERSONAS_DIR / persona_name
    if not source_dir.is_dir():
        return False, f"Persona directory not found: {source_dir}"
    if not (source_dir / 'cowrie.cfg').exists():
        return False, f"Missing cowrie.cfg in persona '{persona_name}'"
    if not (source_dir / 'fs.pickle').exists():
        logger.warning(f"No fs.pickle in {persona_name} — directory tree unchanged")

    try:
        logger.info(f"[PERSONA] Applying '{persona_name}'...")
        shutil.copy2(source_dir / 'cowrie.cfg', COWRIE_CFG)
        logger.info("  ✅ cowrie.cfg swapped")

        source_honeyfs = source_dir / 'honeyfs'
        if source_honeyfs.is_dir():
            if COWRIE_HONEYFS.exists():
                shutil.rmtree(str(COWRIE_HONEYFS))
            shutil.copytree(str(source_honeyfs), str(COWRIE_HONEYFS))
            logger.info("  ✅ honeyfs swapped")

        if (source_dir / 'fs.pickle').exists():
            shutil.copy2(str(source_dir / 'fs.pickle'), str(COWRIE_FS_PICKLE))
            logger.info("  ✅ fs.pickle swapped")

        venv_bin = str(COWRIE_VENV / "bin")
        env = os.environ.copy()
        env["PATH"]        = f"{venv_bin}:{env.get('PATH', '')}"
        env["VIRTUAL_ENV"] = str(COWRIE_VENV)

        result = subprocess.run(
            [str(COWRIE_BIN), "restart"],
            cwd=str(COWRIE_HOME), env=env,
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0 and result.stderr and "error" in result.stderr.lower():
            return False, f"Cowrie restart failed: {result.stderr.strip()}"

        logger.info("  ✅ Cowrie restarted")
        time.sleep(RESTART_GRACE)
        agent_state["active_persona"] = persona_name
        agent_state["last_switch"]    = datetime.utcnow().isoformat()
        agent_state["switch_count"]  += 1
        return True, f"Persona '{persona_name}' applied"

    except PermissionError as e:
        msg = f"PermissionError: {e} — run as cowrie user"
        logger.error(msg)
        agent_state["last_error"] = msg
        return False, msg
    except subprocess.TimeoutExpired:
        return False, "Cowrie restart timed out after 30s"
    except Exception as e:
        return False, f"apply_persona error: {e}"

# ==============================
# 7. HONEYTOKEN GENERATOR
# ==============================

def generate_dynamic_tokens(deception_level: str,
                             attacker_ip:    str,
                             username:       str = DEFAULT_USERNAME,
                             persona:        str = DEFAULT_PERSONA) -> tuple:
    """
    [C-3] Central token entry point — username flows through to
    honeyfs_manager (primary) or _inject_inline_tokens (fallback)
    so every home-directory path uses the attacker's real login name.
    """
    logger.info(f"[TOKEN_DEBUG] level={repr(deception_level)} "
                f"ip={attacker_ip} user={repr(username)} "
                f"hm available={HONEYFS_MANAGER_AVAILABLE}")
    username = sanitize_username(username)

    # [C-6] Record for use in /cleanup
    with _username_lock:
        _session_username[attacker_ip] = username

    if HONEYFS_MANAGER_AVAILABLE:
        with _level_lock:
            _attacker_last_level[attacker_ip] = deception_level
        return _hm_generate_tokens(
            deception_level, attacker_ip,
            username=username, persona=persona
        )

    # ── Legacy fallback (honeyfs_manager unavailable) ────────
    if not HONEYTOKEN_SCRIPT.exists():
        return _inject_inline_tokens(deception_level, attacker_ip, username)

    clean_first = False
    with _level_lock:
        prev = _attacker_last_level.get(attacker_ip)
        if prev and prev != deception_level:
            clean_first = True
            logger.info(f"  [TOKENS] Level {prev}→{deception_level} "
                        f"for {attacker_ip} — clean first")
        _attacker_last_level[attacker_ip] = deception_level

    cmd = [
        sys.executable, str(HONEYTOKEN_SCRIPT),
        '--base-dir',        str(COWRIE_HONEYFS),
        '--deception-level', deception_level,
        '--attacker-ip',     attacker_ip,
        '--username',        username,
        '--silent',
    ]
    if clean_first:
        cmd.append('--clean-first')

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if result.returncode != 0:
            return False, f"Token generation failed: {result.stderr.strip()}"
        logger.info(f"[TOKENS] {deception_level.upper()} tokens for "
                    f"{attacker_ip} (user={username})")
        return True, f"Generated {deception_level} tokens for user '{username}'"
    except subprocess.TimeoutExpired:
        return False, "Token generation timed out"
    except Exception as e:
        return False, f"Token generation error: {e}"


def _inject_inline_tokens(deception_level: str,
                           attacker_ip:    str,
                           username:       str = DEFAULT_USERNAME) -> tuple:
    """
    Inline fallback — all paths built from `username`, never a hardcoded name.
    """
    try:
        home_dir = COWRIE_HONEYFS / 'home' / username
        home_dir.mkdir(parents=True, exist_ok=True)

        history_file = home_dir / '.bash_history'
        existing_hist = history_file.read_text() if history_file.exists() else ""
        if "# pivot-lures" not in existing_hist:
            with open(history_file, 'a') as fh:
                fh.write(
                    "# pivot-lures\n"
                    "sudo apt-get update\n"
                    "ssh -i ~/.ssh/prod_key devops@10.0.1.10\n"
                    "mysql -h prod-db-01 -u app_user -p\n"
                    "ls -la ~/.aws/\n"
                    "cat /opt/app/config.env\n"
                    "kubectl get pods --all-namespaces\n"
                    "find / -name '*.pem' 2>/dev/null\n"
                    "cat ~/db_creds.txt\n"
                )

        notice_file = home_dir / 'NOTICE.txt'
        if not notice_file.exists():
            notice_file.write_text(
                "== SECURITY NOTICE ==\n"
                "This system has already been accessed by another party.\n"
                "Your activities on this host are being monitored.\n"
                "Continuing access may interfere with an ongoing operation.\n"
                "== END NOTICE ==\n"
            )

        if deception_level in ("high", "critical"):
            aws_dir = home_dir / '.aws'
            aws_dir.mkdir(exist_ok=True)
            (aws_dir / 'credentials').write_text(
                "[default]\n"
                "aws_access_key_id=AKIAIOSFODNN7FAKE01\n"
                "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEY\n"
                "region=us-east-1\n"
            )
            ssh_dir = home_dir / '.ssh'
            ssh_dir.mkdir(exist_ok=True)
            (ssh_dir / 'id_rsa').write_text(
                "-----BEGIN RSA PRIVATE KEY-----\n"
                "MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4nAAFAKEKEY...\n"
                "-----END RSA PRIVATE KEY-----\n"
            )

        if deception_level in ("medium", "high", "critical"):
            (home_dir / 'db_creds.txt').write_text(
                "DB_HOST=prod-db-01.internal\n"
                "DB_USER=app_user\n"
                "DB_PASS=Pr0d@pp2024!\n"
                "DB_NAME=customers\n"
            )
            passwd_file = COWRIE_HONEYFS / 'etc' / 'passwd'
            passwd_file.parent.mkdir(parents=True, exist_ok=True)
            existing_pw = passwd_file.read_text() if passwd_file.exists() else ""
            if "backup_admin" not in existing_pw:
                with open(passwd_file, 'a') as fh:
                    fh.write(
                        "backup_admin:x:1005:1005:Backup Service,,,:"
                        "/home/backup_admin:/bin/bash\n"
                        "app_user:x:1006:1006:App Service,,,:/opt/app:/bin/bash\n"
                    )

        logger.info(f"[TOKENS] Inline {deception_level} → "
                    f"/home/{username}/ for {attacker_ip}")
        return True, f"Inline {deception_level} tokens written to /home/{username}/"

    except Exception as e:
        return False, f"Inline token injection failed: {e}"

# ==============================
# 8. SDN ENFORCEMENT  [B-1..B-8, D-1..D-5]
#
# Rule tagging  [B-6]:
#   Comment "sdn_adn_<ip_with_dots_as_underscores>" on every rule
#   so sdn_reset() deletes only this attacker's rules on cleanup.
#
# Port filtering model  [D-1..D-5]:
#   1. sdn_init_session()  — one-time default-deny per attacker IP
#      Appends:  INPUT DROP  -s <ip>  -p tcp  ! --dport 2222
#      This blocks all TCP except the cowrie SSH listener.
#   2. sdn_expose_port()   — inserts ACCEPT at top (-I position 1)
#      ACCEPT lands BEFORE the DROP so iptables hits it first.
#   3. sdn_hide_port()     — removes the ACCEPT for that port.
#      Default-deny DROP resumes blocking that port automatically.
#   4. sdn_containment()   — inserts DROP for ALL traffic at top,
#      cutting even SSH (full isolation of the attacker).
#   5. sdn_reset()         — removes every tagged rule at session end.
# ==============================

def _get_primary_iface() -> str:
    """[B-5] Resolve default-route NIC name at runtime."""
    try:
        r = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        parts = r.stdout.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


def _sdn_comment(attacker_ip: str) -> str:
    """[B-6] Unique iptables comment tag for this attacker."""
    return f"sdn_adn_{attacker_ip.replace('.', '_')}"


def _stable_mark(attacker_ip: str) -> int:
    """Stable mark [1-254] from IP via MD5 — avoids /24 collisions."""
    digest = hashlib.md5(attacker_ip.encode()).hexdigest()
    return (int(digest, 16) % 254) + 1


def _flush_attacker_iptables(attacker_ip: str) -> list:
    """
    FIX: The original looped up to 30 iterations per chain, but each
    iteration ran two subprocess calls (list + delete). On a busy
    system with many rules this could block the Flask thread for
    several seconds per cleanup, causing request timeouts.

    Changes:
    - Hard cap raised to 30 but now uses a single iptables-save/restore
      approach: dump all rules, strip tagged ones, restore atomically.
      Falls back to line-by-line delete if iptables-save is unavailable.
    - Timeout added to every subprocess call (was missing on del_r).
    """
    comment = _sdn_comment(attacker_ip)
    tables_chains = [
        ("filter", "INPUT"),
        ("filter", "FORWARD"),
        ("mangle", "PREROUTING"),
        ("mangle", "POSTROUTING"),
    ]
    errors = []

    for table, chain in tables_chains:
        # Try fast path: save → strip → restore
        try:
            save_r = subprocess.run(
                ["sudo", "iptables-save", "-t", table],
                capture_output=True, text=True, timeout=10
            )
            if save_r.returncode == 0 and comment in save_r.stdout:
                filtered = "\n".join(
                    line for line in save_r.stdout.splitlines()
                    if comment not in line
                )
                restore_r = subprocess.run(
                    ["sudo", "iptables-restore", "--noflush"],
                    input=filtered, capture_output=True, text=True, timeout=10
                )
                if restore_r.returncode == 0:
                    logger.debug(f"[SDN] Fast-path flush OK: {table}/{chain}")
                    continue
                logger.warning(
                    f"[SDN] iptables-restore failed ({restore_r.stderr.strip()})"
                    " — falling back to line-by-line"
                )
        except FileNotFoundError:
            pass  # iptables-save not available, fall through
        except subprocess.TimeoutExpired:
            errors.append(f"{table}/{chain}: iptables-save timed out")
            continue

        # Slow path: line-by-line deletion (bounded)
        for attempt in range(30):
            try:
                list_r = subprocess.run(
                    ["sudo", "iptables", "-t", table, "-L", chain,
                     "--line-numbers", "-n"],
                    capture_output=True, text=True, timeout=10
                )
            except subprocess.TimeoutExpired:
                errors.append(f"{table}/{chain}: list timed out at attempt {attempt}")
                break

            line_num = None
            for line in list_r.stdout.splitlines():
                if comment in line:
                    try:
                        line_num = int(line.split()[0])
                    except (ValueError, IndexError):
                        pass
                    break
            if line_num is None:
                break

            try:
                del_r = subprocess.run(
                    ["sudo", "iptables", "-t", table, "-D", chain, str(line_num)],
                    capture_output=True, text=True, timeout=10  # FIX: was missing
                )
                if del_r.returncode != 0:
                    errors.append(
                        f"{table}/{chain}:{line_num} — {del_r.stderr.strip()}"
                    )
                    break
            except subprocess.TimeoutExpired:
                errors.append(f"{table}/{chain}:{line_num}: delete timed out")
                break

    return errors


def _cleanup_tc_for_ip(attacker_ip: str):
    """Best-effort tc class + filter removal for this IP."""
    iface    = _get_primary_iface()
    mark_id  = _stable_mark(attacker_ip)
    class_id = f"1:{mark_id}"
    subprocess.run(
        ["sudo", "tc", "filter", "del", "dev", iface,
         "parent", "1:", "handle", str(mark_id), "fw"],
        capture_output=True, timeout=10
    )
    subprocess.run(
        ["sudo", "tc", "class", "del", "dev", iface, "classid", class_id],
        capture_output=True, timeout=10
    )
    logger.debug(f"[SDN] tc cleaned for {attacker_ip} (mark={mark_id})")


def sdn_init_session(attacker_ip: str) -> tuple:
    """
    [D-1] Default-deny for a new attacker session.

    Appends a DROP rule for ALL TCP from this IP EXCEPT the cowrie
    SSH port.  Using -A (append) puts it AFTER any subsequently
    inserted ACCEPT rules (which use -I / insert at top), so the
    rule ordering is always:

        [top]  ACCEPT  -s <ip>  --dport <exposed_port>   ← expose_port()
        ...
        [low]  DROP    -s <ip>  ! --dport 2222           ← this rule

    iptables walks top-to-bottom and stops at first match, so:
      • Port 2222 (SSH) → no ACCEPT for it, falls through the DROP
        because the DROP has ! --dport 2222 → SSH is allowed.
      • Port 3306 (not exposed) → no ACCEPT for it → hits DROP.
      • Port 3306 (exposed) → hits ACCEPT first → allowed.

    The rule is tagged so sdn_reset() removes it automatically.
    """
    comment = _sdn_comment(attacker_ip)

    # Check if init rule already exists to stay idempotent
    check = subprocess.run(
        ["sudo", "iptables", "-L", "INPUT", "-n"],
        capture_output=True, text=True, timeout=10
    )
    if comment in check.stdout and "!dpt:" in check.stdout:
        logger.debug(f"[SDN] Default-deny already active for {attacker_ip}")
        return True, f"Default-deny already initialised for {attacker_ip}"

    r = subprocess.run(
        [
            "sudo", "iptables", "-A", "INPUT",
            "-s", attacker_ip,
            "-p", "tcp",
            "!", "--dport", str(HONEYPOT_SSH_PORT),
            "-m", "comment", "--comment", comment,
            "-j", "DROP",
        ],
        capture_output=True, text=True, timeout=10
    )
    if r.returncode != 0:
        msg = f"Session init DROP failed: {r.stderr.strip()}"
        logger.error(f"[SDN] {msg}")
        return False, msg

    logger.info(f"[SDN] Default-deny initialised for {attacker_ip} "
                f"(SSH port {HONEYPOT_SSH_PORT} exempt)")
    return True, (f"Default-deny active for {attacker_ip} "
                  f"— only port {HONEYPOT_SSH_PORT} open until expose_port fires")


def sdn_reset(attacker_ip: str) -> tuple:
    """Remove all tagged iptables rules and tc shaping for this attacker."""
    errors = _flush_attacker_iptables(attacker_ip)
    _cleanup_tc_for_ip(attacker_ip)
    if errors:
        msg = f"Partial reset — errors: {'; '.join(errors)}"
        logger.warning(f"[SDN] {msg} for {attacker_ip}")
        return False, msg
    logger.info(f"[SDN] Full reset for {attacker_ip}")
    return True, f"SDN reset for {attacker_ip}"


def sdn_containment(attacker_ip: str) -> tuple:
    """
    Full isolation — insert DROP for ALL traffic from attacker at top of
    INPUT chain, overriding any existing ACCEPT rules.  This cuts even
    the SSH session (intended for high-severity containment).
    """
    comment = _sdn_comment(attacker_ip)
    r = subprocess.run(
        [
            "sudo", "iptables", "-I", "INPUT",
            "-s", attacker_ip,
            "-m", "comment", "--comment", comment,
            "-j", "DROP",
        ],
        capture_output=True, text=True, timeout=10
    )
    if r.returncode != 0:
        return False, f"Containment DROP failed: {r.stderr.strip()}"
    logger.info(f"[SDN] Full containment DROP for {attacker_ip}")
    return True, f"Containment active — {attacker_ip} fully isolated"


def sdn_throttle(attacker_ip: str,
                 rate_kbps: int = THROTTLE_RATE_KBPS) -> tuple:
    """Bandwidth-limit traffic from attacker_ip via MANGLE mark + HTB."""
    comment  = _sdn_comment(attacker_ip)
    mark_id  = _stable_mark(attacker_ip)
    iface    = _get_primary_iface()
    class_id = f"1:{mark_id}"

    r = subprocess.run(
        [
            "sudo", "iptables", "-t", "mangle", "-I", "PREROUTING",
            "-s", attacker_ip,
            "-m", "comment", "--comment", comment,
            "-j", "MARK", "--set-mark", str(mark_id),
        ],
        capture_output=True, text=True, timeout=10
    )
    if r.returncode != 0:
        return False, f"MANGLE MARK failed: {r.stderr.strip()}"

    subprocess.run(
        ["sudo", "tc", "qdisc", "add", "dev", iface,
         "root", "handle", "1:", "htb", "default", "999"],
        capture_output=True, timeout=10
    )
    r2 = subprocess.run(
        ["sudo", "tc", "class", "add", "dev", iface,
         "parent", "1:", "classid", class_id,
         "htb", "rate", f"{rate_kbps}kbit", "burst", "32k"],
        capture_output=True, text=True, timeout=10
    )
    if r2.returncode != 0 and "already exists" not in r2.stderr:
        logger.warning(f"[SDN] tc class note: {r2.stderr.strip()}")

    subprocess.run(
        ["sudo", "tc", "filter", "add", "dev", iface, "parent", "1:",
         "handle", str(mark_id), "fw", "classid", class_id],
        capture_output=True, timeout=10
    )

    logger.info(f"[SDN] Throttle {rate_kbps}kbps → {attacker_ip} "
                f"(mark={mark_id}, iface={iface})")
    return True, f"Throttle {rate_kbps} kbps applied to {attacker_ip}"


def sdn_expose_port(attacker_ip: str, port: str) -> tuple:
    """
    [D-2] Insert an ACCEPT rule at top of INPUT chain for this port.
    Using -I (insert) places ACCEPT before the default-deny DROP so
    iptables hits the ACCEPT first for this specific port.
    """
    comment = _sdn_comment(attacker_ip)
    r = subprocess.run(
        [
            "sudo", "iptables", "-I", "INPUT",
            "-s", attacker_ip, "-p", "tcp", "--dport", str(port),
            "-m", "comment", "--comment", comment,
            "-j", "ACCEPT",
        ],
        capture_output=True, text=True, timeout=10
    )
    if r.returncode != 0:
        return False, f"expose_port {port} failed: {r.stderr.strip()}"
    logger.info(f"[SDN] Port {port} exposed to {attacker_ip} (ACCEPT at top)")
    return True, f"Port {port} opened for {attacker_ip}"


def sdn_hide_port(attacker_ip: str, port: str) -> tuple:
    """
    [D-3] Remove the ACCEPT rule for this port.

    With default-deny in place, removing the ACCEPT is sufficient —
    the DROP rule lower in the chain resumes blocking that port.
    Adding another DROP on top would duplicate rules and leave
    stale entries that trip up sdn_reset() cleanup.

    Loops until no ACCEPT rule for this port remains (handles the
    edge case where expose_port was called multiple times).
    """
    comment = _sdn_comment(attacker_ip)
    removed = 0

    for _ in range(10):
        list_r = subprocess.run(
            ["sudo", "iptables", "-L", "INPUT", "--line-numbers", "-n"],
            capture_output=True, text=True, timeout=10
        )
        line_num = None
        for line in list_r.stdout.splitlines():
            # Match lines that have our comment, the specific port, and ACCEPT
            if comment in line and f"dpt:{port}" in line and "ACCEPT" in line:
                try:
                    line_num = int(line.split()[0])
                except (ValueError, IndexError):
                    pass
                break

        if line_num is None:
            break   # No more ACCEPT rules for this port

        del_r = subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", str(line_num)],
            capture_output=True, text=True, timeout=10
        )
        if del_r.returncode == 0:
            removed += 1
        else:
            logger.error(f"[SDN] Failed to remove ACCEPT for port {port}: "
                         f"{del_r.stderr.strip()}")
            break

    if removed > 0:
        logger.info(f"[SDN] Port {port} hidden from {attacker_ip} "
                    f"(removed {removed} ACCEPT rule{'s' if removed > 1 else ''})")
        return True, f"Port {port} hidden for {attacker_ip} — default-deny resumes"
    else:
        logger.info(f"[SDN] hide_port {port} for {attacker_ip} — "
                    f"no ACCEPT found (already blocked by default-deny)")
        return True, f"Port {port} already blocked for {attacker_ip}"


def run_sdn_action(action: str,
                   attacker_ip: str,
                   target_port: str = "") -> tuple:
    """[B-7] Dispatcher — all SDN resolved inline."""
    if not validate_ip(attacker_ip):
        return False, f"Invalid attacker IP: {attacker_ip}"
    if action == "reset":
        return sdn_reset(attacker_ip)
    elif action == "containment":
        return sdn_containment(attacker_ip)
    elif action == "throttle":
        return sdn_throttle(attacker_ip)
    elif action == "expose_port":
        if not target_port or not validate_port(target_port):
            return False, "Missing or invalid target_port"
        return sdn_expose_port(attacker_ip, target_port)
    elif action == "hide_port":
        if not target_port or not validate_port(target_port):
            return False, "Missing or invalid target_port"
        return sdn_hide_port(attacker_ip, target_port)
    else:
        return False, f"Unknown SDN action: '{action}'"

# ==============================
# 9. DIONAEA DECOY SERVICES
# ==============================

def _is_dionaea_running() -> bool:
    try:
        r = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", "dionaea"],
            capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip() == "true":
            return True
    except Exception:
        pass
    try:
        r = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=5)
        if ":3306" in r.stdout:
            return True
    except Exception:
        pass
    return False


def _start_dionaea() -> bool:
    try:
        r = subprocess.run(["docker", "restart", "dionaea"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            time.sleep(3)
            logger.info("  ✅ Dionaea restarted")
            return True
        r = subprocess.run(
            ["docker", "run", "-d", "--name", "dionaea",
             "-p", "21:21", "-p", "445:445", "-p", "3306:3306",
             "honeynet/dionaea"],
            capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            time.sleep(3)
            logger.info("  ✅ Dionaea started")
            return True
        logger.error(f"  ❌ Dionaea start failed: {r.stderr.strip()}")
        return False
    except Exception as e:
        logger.error(f"  ❌ Dionaea error: {e}")
        return False


def deploy_decoy_services(attacker_ip: str,
                          username: str = DEFAULT_USERNAME) -> tuple:
    """[A-4] Verifies Dionaea, exposes ports, drops tokens."""
    if not _is_dionaea_running():
        logger.warning("  ⚠️  Dionaea not running — attempting start...")
        if not _start_dionaea():
            return False, "Dionaea not running and failed to start"

    exposed = []
    for port in [21, 445, 3306]:
        ok, _ = run_sdn_action("expose_port", attacker_ip, str(port))
        if ok:
            exposed.append(str(port))

    level = TTP_DECEPTION_LEVEL.get("T1046", "high")
    token_ok, token_msg = generate_dynamic_tokens(
        level, attacker_ip, username=username
    )

    if exposed or token_ok:
        return True, (f"Ports [{','.join(exposed) or 'none'}] exposed | "
                      f"Tokens: {token_msg}")
    return False, "Port exposure and token generation both failed"

# ==============================
# 10. SANDBOX
# ==============================

def _get_honeypot_host_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"


def deploy_sandbox_container(attacker_ip: str):
    try:
        import docker as docker_sdk
    except ImportError:
        logger.error("[SANDBOX] docker-py not installed — pip3 install docker")
        return None, None

    with _sandbox_lock:
        for sb in active_sandboxes:
            if sb["ip"] == attacker_ip:
                return sb["container_id"], sb["port"]

    try:
        client  = docker_sdk.from_env()
        log_dir = SANDBOX_LOG_BASE / attacker_ip.replace(".", "_")
        log_dir.mkdir(parents=True, exist_ok=True)
        log_dir.chmod(0o777)

        container_name = f"sandbox_{attacker_ip.replace('.', '_')}"
        try:
            docker_sdk.from_env().containers.get(container_name).remove(force=True)
        except Exception:
            pass

        container = client.containers.run(
            SANDBOX_IMAGE, detach=True,
            ports={'2222/tcp': None}, name=container_name,
            remove=False, network=SANDBOX_NETWORK,
            cap_add=['SYS_PTRACE', 'SYS_ADMIN'],
            volumes={str(log_dir): {'bind': '/var/log/audit', 'mode': 'rw'}},
        )
        container.reload()
        raw_port = container.ports.get('2222/tcp', [{}])[0].get('HostPort')
        if not validate_port(raw_port):
            container.remove(force=True)
            return None, None
        host_port = int(raw_port)
        logger.info(f"[SANDBOX] Container {container.id[:12]} on port {host_port}")
        return container.id, host_port
    except Exception as e:
        logger.error(f"[SANDBOX] Deploy failed: {e}")
        return None, None


def redirect_to_sandbox(attacker_ip: str, sandbox_port: int) -> bool:
    if not validate_ip(attacker_ip) or not validate_port(sandbox_port):
        return False
    honeypot_ip = _get_honeypot_host_ip()
    cmd = [
        "sudo", "iptables", "-t", "nat", "-I", "PREROUTING", "1",
        "-s", attacker_ip,
        "-p", "tcp", 
        "-m", "multiport", "--dport", "22,2222",
        "-m", "conntrack", "--ctstate", "NEW",
        "-m", "comment", "--comment", f"sandbox_{attacker_ip}",
        "-j", "REDIRECT", "--to-port", str(sandbox_port),
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            logger.error(f"[SANDBOX] iptables failed: {r.stderr.strip()}")
            return False
        verify = subprocess.run(
            ["sudo", "iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v"],
            capture_output=True, text=True, timeout=10
        )
        if f"sandbox_{attacker_ip}" not in verify.stdout:
            logger.error(f"[SANDBOX] Rule not found after insert for {attacker_ip}")
            return False
        logger.info(f"[SANDBOX] {attacker_ip}:{HONEYPOT_SSH_PORT} → :{sandbox_port}")
        return True
    except subprocess.TimeoutExpired:
        logger.error(f"[SANDBOX] iptables timed out for {attacker_ip}")
        return False
    except Exception as e:
        logger.error(f"[SANDBOX] Error: {e}")
        return False


def _remove_iptables_rule(attacker_ip: str, sandbox_port: int) -> bool:
    if not validate_ip(attacker_ip) or not validate_port(sandbox_port):
        return False
    honeypot_ip = _get_honeypot_host_ip()
    cmd = [
        "sudo", "iptables", "-t", "nat", "-D", "PREROUTING",
        "-s", attacker_ip, "-d", honeypot_ip,
        "-p", "tcp", "--dport", str(HONEYPOT_SSH_PORT),
        "-m", "conntrack", "--ctstate", "NEW",
        "-m", "comment", "--comment", f"sandbox_{attacker_ip}",
        "-j", "REDIRECT", "--to-port", str(sandbox_port),
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            logger.error(f"[SANDBOX] Remove failed: {r.stderr.strip()}")
            return False
        logger.info(f"[SANDBOX] Rule removed for {attacker_ip}")
        return True
    except Exception as e:
        logger.error(f"[SANDBOX] Remove error: {e}")
        return False


def _stop_sandbox_container(container_id: str) -> bool:
    try:
        import docker as docker_sdk
        c = docker_sdk.from_env().containers.get(container_id)
        c.stop(timeout=5)
        c.remove(force=True)
        return True
    except Exception:
        r = subprocess.run(["docker", "rm", "-f", container_id],
                           capture_output=True, text=True, timeout=10)
        return r.returncode == 0


def deploy_sandbox(attacker_ip: str) -> tuple:
    container_id, host_port = deploy_sandbox_container(attacker_ip)
    if not container_id or not host_port:
        return False, "Sandbox container deployment failed"
    if not redirect_to_sandbox(attacker_ip, host_port):
        _stop_sandbox_container(container_id)
        return False, "iptables redirect failed — sandbox removed"
    with _sandbox_lock:
        active_sandboxes[:] = [s for s in active_sandboxes if s["ip"] != attacker_ip]
        active_sandboxes.append({
            "ip":           attacker_ip,
            "port":         host_port,
            "container_id": container_id,
            "start_time":   time.time(),
        })
    return True, (f"Sandbox on port {host_port}. "
                  f"{attacker_ip}:{HONEYPOT_SSH_PORT} redirected. "
                  f"Auto-cleanup in {SANDBOX_TTL // 60}min.")


def teardown_sandbox(attacker_ip: str) -> tuple:
    with _sandbox_lock:
        record = next((s for s in active_sandboxes if s["ip"] == attacker_ip), None)
        if not record:
            return False, f"No active sandbox for {attacker_ip}"
        active_sandboxes.remove(record)
    ip_ok  = _remove_iptables_rule(attacker_ip, record["port"])
    cnt_ok = _stop_sandbox_container(record["container_id"])
    if ip_ok and cnt_ok:
        return True, f"Sandbox for {attacker_ip} torn down"
    return cnt_ok, "Partial teardown — check logs"

# ==============================
# 11. SESSION TRACKING
# ==============================

def _track_session(attacker_ip: str, action_type: str, mitre_id: str,
                   action_succeeded: bool = True):
    """
    FIX: Previously _track_session was only called when success=True,
    meaning sdn_init_session() was never fired for failed actions.
    If the first action for a new IP failed (e.g. token write error),
    the default-deny rule was never installed, leaving the attacker
    unrestricted on the network layer for their entire session.

    Now: SDN init fires on FIRST ENTRY regardless of action outcome.
    The session record is always created; last_action only updated on success.
    """
    if attacker_ip in ('unknown', '127.0.0.1'):
        return
    sessions = agent_state["active_sessions"]
    if len(sessions) >= MAX_TRACKED_SESSIONS:
        oldest = min(sessions, key=lambda k: sessions[k].get("start_time", ""))
        del sessions[oldest]

    if attacker_ip not in sessions:
        # Always install default-deny on first contact, regardless of
        # whether the application-layer action succeeded.
        ok, msg = sdn_init_session(attacker_ip)
        if not ok:
            logger.warning(
                f"[SESSION] Default-deny init FAILED for {attacker_ip}: {msg}. "
                f"Network layer unprotected — check iptables permissions."
            )
        sessions[attacker_ip] = {
            "start_time":  datetime.utcnow().isoformat(),
            "last_action": action_type if action_succeeded else None,
            "mitre":       mitre_id,
        }
    else:
        if action_succeeded:
            sessions[attacker_ip]["last_action"] = action_type

# ==============================
# 12. CLEANUP DAEMON
# ==============================

def cleanup_sandbox_daemon():
    logger.info(f"[CLEANUP] Daemon started TTL={SANDBOX_TTL}s")
    while True:
        time.sleep(60)
        now = time.time()
        with _sandbox_lock:
            expired = [s for s in active_sandboxes
                       if now - s["start_time"] > SANDBOX_TTL]
        for record in expired:
            ok, msg = teardown_sandbox(record["ip"])
            logger.info(f"[CLEANUP] {record['ip']}: {msg}")

# ==============================
# 13. FLASK ENDPOINTS
# ==============================

@app.route('/health', methods=['GET'])
def health():
    with _sandbox_lock:
        n = len(active_sandboxes)
    return jsonify({
        "status":    "online",
        "agent":     "AI-ADN Adaptation Agent v3.7",
        "persona":   agent_state["active_persona"],
        "uptime":    agent_state["start_time"],
        "sandboxes": n,
    }), 200


@app.route('/status', methods=['GET'])
def status():
    if not check_auth(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    with _sandbox_lock:
        sb_list = [{"ip": s["ip"], "port": s["port"],
                    "age_min": round((time.time() - s["start_time"]) / 60, 1)}
                   for s in active_sandboxes]
    return jsonify({**agent_state, "active_sandboxes": sb_list,
                    "config": {
                        "cowrie_home":    str(COWRIE_HOME),
                        "cowrie_venv":    str(COWRIE_VENV),
                        "primary_iface":  _get_primary_iface(),
                        "throttle_kbps":  THROTTLE_RATE_KBPS,
                        "sdn_mode":       "inline — default-deny per session",
                        "token_paths":    "dynamic — attacker login username",
                        "ssh_port_exempt": HONEYPOT_SSH_PORT,
                    }}), 200


@app.route('/personas', methods=['GET'])
def personas():
    if not check_auth(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    result = {}
    for p in ["ubuntu_server", "iot_router", "windows_server"]:
        d = PERSONAS_DIR / p
        result[p] = {
            "ready":    d.is_dir() and (d/'cowrie.cfg').exists() and (d/'fs.pickle').exists(),
            "triggers": [k for k, v in TTP_PERSONA_MAP.items() if v == p],
        }
    return jsonify({
        "personas":       result,
        "active_persona": agent_state["active_persona"],
        "ttp_map":        TTP_PERSONA_MAP,
    }), 200


@app.route('/cleanup', methods=['POST'])
def cleanup():
    """[A-2] Called by adaptive_engine on cowrie.session.closed."""
    if not check_auth(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    data        = request.get_json(silent=True) or {}
    attacker_ip = data.get('attacker_ip', '').strip()
    if not attacker_ip or not validate_ip(attacker_ip):
        return jsonify({"status": "error", "message": "Invalid attacker_ip"}), 400

    logger.info(f"[CLEANUP] Session ended for {attacker_ip}")

    # sdn_reset removes ALL tagged rules including the default-deny init rule [D-5]
    ok, msg = run_sdn_action("reset", attacker_ip)

    if HONEYFS_MANAGER_AVAILABLE:
        with _username_lock:
            uname = _session_username.get(attacker_ip, DEFAULT_USERNAME)
        hm_ok, hm_msg = cleanup_session_tokens(attacker_ip, username=uname)
        msg += f" | Tokens: {hm_msg}"

    with _sandbox_lock:
        has_sandbox = any(s["ip"] == attacker_ip for s in active_sandboxes)
    if has_sandbox:
        sb_ok, sb_msg = teardown_sandbox(attacker_ip)
        msg += f" | Sandbox: {sb_msg}"

    agent_state["active_sessions"].pop(attacker_ip, None)
    with _level_lock:
        _attacker_last_level.pop(attacker_ip, None)
    with _username_lock:
        _session_username.pop(attacker_ip, None)

    return jsonify({
        "status": "success" if ok else "partial",
        "action": msg,
        "note":   "SDN reset + default-deny removed + session cleared",
    }), 200


@app.route('/sandbox/status', methods=['GET'])
def sandbox_status():
    if not check_auth(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    now = time.time()
    with _sandbox_lock:
        sandboxes = [{
            "ip":           s["ip"],
            "port":         s["port"],
            "container_id": s["container_id"][:12],
            "age_minutes":  round((now - s["start_time"]) / 60, 1),
            "expires_in_s": max(0, int(SANDBOX_TTL - (now - s["start_time"]))),
        } for s in active_sandboxes]
    return jsonify({"active_count": len(sandboxes), "sandboxes": sandboxes}), 200


@app.route('/sandbox/cleanup', methods=['POST'])
def sandbox_cleanup():
    """[A-8] Tears down sandbox + resets SDN."""
    if not check_auth(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    data        = request.get_json(silent=True) or {}
    attacker_ip = data.get("attacker_ip", "").strip()
    if not attacker_ip or not validate_ip(attacker_ip):
        return jsonify({"status": "error", "message": "Invalid attacker_ip"}), 400

    sb_ok,  sb_msg  = teardown_sandbox(attacker_ip)
    sdn_ok, sdn_msg = run_sdn_action("reset", attacker_ip)

    return jsonify({
        "status":  "success" if (sb_ok or sdn_ok) else "error",
        "sandbox": sb_msg,
        "sdn":     sdn_msg,
    }), 200


@app.route('/trigger_adaptation', methods=['POST'])
def trigger_adaptation():
    if not check_auth(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    caller_ip = request.remote_addr or "unknown"
    if not check_rate_limit(caller_ip):
        return jsonify({
            "status":  "error",
            "message": f"Rate limit exceeded — max {RATE_LIMIT_MAX} req/{RATE_LIMIT_WINDOW}s"
        }), 429

    data        = request.get_json(silent=True) or {}
    action_type = data.get('action_type',     'live_bait').strip().lower()
    mitre_id    = data.get('mitre_technique', 'UNKNOWN').upper().strip()
    attacker_ip = data.get('attacker_ip',     'unknown').strip()
    username    = sanitize_username(data.get('username', DEFAULT_USERNAME))

    if not validate_ip(attacker_ip):
        return jsonify({"status": "error", "message": "Invalid attacker_ip"}), 400

    logger.info(f"[REQUEST] action={action_type} | ttp={mitre_id} | "
                f"ip={attacker_ip} | user={username}")

    success, message = False, "No action taken"
    persona = TTP_PERSONA_MAP.get(mitre_id, DEFAULT_PERSONA)
    level   = TTP_DECEPTION_LEVEL.get(mitre_id, "low")

    # ── Persona ──────────────────────────────────────────────
    if action_type == "adapt_persona":
        success, message = apply_persona(persona)

    # ── Token bait ───────────────────────────────────────────
    elif action_type == "live_bait":
        success, message = generate_dynamic_tokens(
            level, attacker_ip, username=username, persona=persona
        )

    elif action_type == "adapt_and_bait":
        ok1, msg1 = apply_persona(persona)
        ok2, msg2 = generate_dynamic_tokens(
            level, attacker_ip, username=username, persona=persona
        )
        success = ok1 and ok2
        message = f"Persona: {msg1} | Tokens: {msg2}"

    # ── Decoy services ───────────────────────────────────────
    elif action_type == "deploy_decoy_service":
        success, message = deploy_decoy_services(attacker_ip, username=username)

    # ── Psychological deceptions (all via generate_dynamic_tokens) ──
    elif action_type == "inject_history":
        success, message = generate_dynamic_tokens(
            level, attacker_ip, username=username, persona=persona
        )

    elif action_type == "rival_scare":
        success, message = generate_dynamic_tokens(
            level, attacker_ip, username=username, persona=persona
        )

    elif action_type == "spawn_admin":
        eff_level = level if DECEPTION_LEVEL_RANK.get(level, 0) >= \
                             DECEPTION_LEVEL_RANK["medium"] else "medium"
        success, message = generate_dynamic_tokens(
            eff_level, attacker_ip, username=username, persona=persona
        )

    # ── SDN ──────────────────────────────────────────────────
    elif action_type in ("containment", "throttle"):
        success, message = run_sdn_action(action_type, attacker_ip)

    elif action_type in ("expose_port", "hide_port"):
        port = data.get('target_port', '')
        if not port or not validate_port(str(port)):
            return jsonify({"status": "error",
                            "message": "Missing or invalid target_port"}), 400
        success, message = run_sdn_action(action_type, attacker_ip, str(port))

    # ── Sandbox ──────────────────────────────────────────────
    elif action_type == "sandbox_redirect":
        success, message = deploy_sandbox(attacker_ip)

    else:
        return jsonify({
            "status":        "error",
            "message":       f"Unknown action_type '{action_type}'",
            "valid_actions": [
                "adapt_persona", "live_bait", "adapt_and_bait",
                "deploy_decoy_service",
                "inject_history", "rival_scare", "spawn_admin",
                "containment", "throttle",
                "expose_port", "hide_port",
                "sandbox_redirect",
            ],
        }), 400

    # [D-4] _track_session auto-fires sdn_init_session on first action
    
    _track_session(attacker_ip, action_type, mitre_id, action_succeeded=success)

    return jsonify({
        "status":         "success" if success else "error",
        "action":         message,
        "active_persona": agent_state["active_persona"],
        "switch_count":   agent_state["switch_count"],
    }), 200 if success else 500

# ==============================
# 14. STARTUP VALIDATION
# ==============================

def validate_environment():
    print("\n" + "=" * 62)
    print("  ADAPT AGENT v3.7 — ENVIRONMENT CHECK")
    print("=" * 62)

    checks = [
        ("Cowrie home",        COWRIE_HOME,       True),
        ("Cowrie venv",        COWRIE_VENV,       True),
        ("Cowrie activate",    COWRIE_ACTIVATE,   True),
        ("Cowrie binary",      COWRIE_BIN,        True),
        ("Cowrie cfg",         COWRIE_CFG,        True),
        ("Cowrie fs.pickle",   COWRIE_FS_PICKLE,  True),
        ("Personas directory", PERSONAS_DIR,      True),
        ("Honeytoken script",  HONEYTOKEN_SCRIPT, False),
    ]
    sdn_bins = [
        ("/sbin/iptables",  True),
        ("/sbin/tc",        True),
        ("/usr/bin/docker", False),
    ]

    all_ok = True
    for label, path, critical in checks:
        exists = Path(path).exists()
        icon   = "✅" if exists else ("❌" if critical else "⚠️ ")
        req    = "REQUIRED" if critical else "optional"
        print(f"  {icon}  {label:<26} [{req}]  {path}")
        if critical and not exists:
            all_ok = False

    print()
    print("  System binaries (inline SDN):")
    for binary, critical in sdn_bins:
        exists = Path(binary).exists()
        icon   = "✅" if exists else ("❌" if critical else "⚠️ ")
        req    = "REQUIRED" if critical else "optional"
        print(f"    {icon}  {binary:<30} [{req}]")
        if critical and not exists:
            all_ok = False

    print()
    print("  Personas:")
    for p in ["ubuntu_server", "iot_router", "windows_server"]:
        d     = PERSONAS_DIR / p
        ready = d.is_dir() and (d/'cowrie.cfg').exists() and (d/'fs.pickle').exists()
        print(f"    {'✅' if ready else '❌'}  {p}")

    iface = _get_primary_iface()
    print()
    print(f"  Agent port       : {AGENT_PORT}")
    print(f"  Primary iface    : {iface}  (tc HTB target)")
    print(f"  Throttle rate    : {THROTTLE_RATE_KBPS} kbps")
    print(f"  SDN mode         : inline — default-deny per attacker session")
    print(f"  Port model       : default-deny TCP except :{HONEYPOT_SSH_PORT}")
    print(f"                     expose_port = ACCEPT inserted above DROP")
    print(f"                     hide_port   = ACCEPT removed, DROP resumes")
    print(f"  Token paths      : /home/<attacker_login>/... (username-dynamic)")
    print(f"  honeyfs_manager  : {'available ✅' if HONEYFS_MANAGER_AVAILABLE else 'NOT FOUND — inline fallback ⚠️'}")
    print(f"  Rate limit       : {RATE_LIMIT_MAX} req / {RATE_LIMIT_WINDOW}s")
    print(f"  Session cap      : {MAX_TRACKED_SESSIONS}")
    print(f"  Sandbox TTL      : {SANDBOX_TTL}s ({SANDBOX_TTL // 60}min)")
    print(f"  Running as       : {os.getenv('USER', 'unknown')} (should be 'cowrie')")
    print("=" * 62)

    if not all_ok:
        print("\n  ⚠️  Some required paths missing.\n")
    else:
        print("\n  ✅ All critical paths verified. Agent ready.\n")
    return all_ok

# ==============================
# 15. MAIN
# ==============================

if __name__ == '__main__':
    validate_environment()
    SANDBOX_LOG_BASE.mkdir(parents=True, exist_ok=True)

    threading.Thread(
        target=cleanup_sandbox_daemon, daemon=True, name="SandboxCleanup"
    ).start()
    logger.info("Sandbox cleanup daemon started")

    logger.info(f"Starting Adapt Agent v3.7 on port {AGENT_PORT}")
    logger.info(f"Running as    : {os.getenv('USER', 'unknown')}")
    logger.info(f"SDN mode      : inline iptables + tc — default-deny per session")
    logger.info(f"Port model    : default-deny TCP except :{HONEYPOT_SSH_PORT}")
    logger.info(f"Token paths   : /home/<attacker_login>/... (username-dynamic)")

    app.run(host='0.0.0.0', port=AGENT_PORT, debug=False, threaded=True)
