#!/usr/bin/env python3
# honeyfs_manager.py — v1.1
# ============================================================
# COWRIE HONEYFS MANAGER
#
# FIXES FROM v1.0:
#   [F-1] PickleManager root navigation fixed — Cowrie stores the
#         pickle as a LIST (root directory node), not a dict.
#         Children dict is at fs[9].  v1.0 did `node = fs` which
#         made every `part not in node` check fail silently,
#         so nothing was ever registered.  Fixed by detecting the
#         root type and always starting navigation from fs[9].
#   [F-2] _make_file_node children fixed — v1.0 set children to {}
#         for regular files.  Cowrie checks `node[9] is None` to
#         distinguish files from directories.  {} made every
#         registered file look like an empty directory, breaking
#         cat/head/tail.  Fixed to None.
#   [F-3] _save_sessions crash fixed — SESSION_STATE parent dir
#         was never created.  If ~/lab/ was absent the write threw
#         FileNotFoundError which propagated as the "live bait
#         error".  Fixed with mkdir(parents=True, exist_ok=True).
#   [F-4] FILE_REGISTRY paths de-hardcoded — all /home/cowrie/
#         paths replaced with /home/{username}/ placeholders.
#         render() substitutes the attacker's actual login name so
#         the string "cowrie" never appears on disk.
#   [F-5] _render_template gains `username` parameter so templates
#         can use {username} as a placeholder.
#   [F-6] render() uses entry["virtual_path"].format(username=...)
#         instead of fragile string-replace for path resolution.
#   [F-7] Error handling added around _save_sessions in render()
#         so a session-state write failure is logged, not fatal.
#   [F-8] SESSION_STATE directory creation moved to module load
#         so it is guaranteed before first write.
#
# ============================================================

import os
import sys
import json
import pickle
import shutil
import logging
import argparse
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

# ==============================
# 1. PATHS
# ==============================

COWRIE_HOME      = Path.home() / 'cowrie'
COWRIE_HONEYFS   = COWRIE_HOME / 'honeyfs'
COWRIE_FS_PICKLE = COWRIE_HOME / 'src' / 'cowrie' / 'data' / 'fs.pickle'
SESSION_STATE    = Path.home() / 'lab' / 'honeyfs_sessions.json'
PICKLE_BACKUP    = COWRIE_FS_PICKLE.parent / 'fs.pickle.bak'

# [F-8] Guarantee the directory exists at import time
SESSION_STATE.parent.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger('honeyfs_manager')

# ==============================
# 2. FILE REGISTRY
#
# Path placeholders:
#   {username}    — attacker's actual login name (substituted at render time)
#
# Template placeholders (substituted by _render_template):
#   {username}    — attacker's login name
#   {attacker_ip} — attacker source IP
#   {timestamp}   — current UTC timestamp
#   {token_id}    — unique canary token for this attacker+file combo
#   {aws_key}     — fake AWS access key
#   {aws_secret}  — fake AWS secret key
#   {db_pass}     — fake database password
#   {hostname}    — fake production hostname
# ==============================

FILE_REGISTRY = {

    # ── LOW ──────────────────────────────────────────────────
    "motd_banner": {
        "virtual_path": "/etc/motd",
        "levels": ["low", "medium", "high", "critical"],
        "template": (
            "Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.15.0-76-generic x86_64)\n\n"
            " * Documentation:  https://help.ubuntu.com\n"
            " * Management:     https://landscape.canonical.com\n\n"
            "  System information as of {timestamp}\n\n"
            "  System load:    0.08              Processes:         142\n"
            "  Usage of /:     34.2% of 49.98GB  Users logged in:   1\n"
            "  Memory usage:   61%               IPv4 addr(eth0):   10.0.1.5\n\n"
            "Last login: Mon Nov 20 09:14:32 2023 from 192.168.1.42\n"
        ),
        "perms": 0o644, "uid": 0, "gid": 0,
    },

    # [F-4] /home/cowrie/ → /home/{username}/
    "bash_history": {
        "virtual_path": "/home/{username}/.bash_history",
        "levels": ["low", "medium", "high", "critical"],
        "template": (
            "sudo apt-get update\n"
            "sudo apt-get upgrade -y\n"
            "df -h\n"
            "top\n"
            "ssh -i ~/.ssh/prod_key devops@10.0.1.10\n"
            "mysql -h prod-db-01 -u app_user -p\n"
            "ls -la ~/.aws/\n"
            "cat /opt/app/config.env\n"
            "kubectl get pods --all-namespaces\n"
            "find / -name '*.pem' 2>/dev/null\n"
            "cat ~/db_creds.txt\n"
            "git clone https://github.com/corp-internal/deploy-scripts\n"
            "sudo systemctl restart nginx\n"
            "cd /var/backups && ls -la\n"
        ),
        "perms": 0o600, "uid": 1000, "gid": 1000,
    },

    # ── Psychological deceptions (from adapt_agent [C-4]) ────
    # All three route through generate_dynamic_tokens() →
    # SessionRenderer.render() so pickle registration always happens.

    "inject_history_ubuntu": {
        "virtual_path": "/home/{username}/.bash_history",
        "personas": ["ubuntu_server"],
        "levels": ["low", "medium", "high", "critical"],
        "template": (
            "# pivot-lures\n"
            "sudo apt-get update\n"
            "ssh -i ~/.ssh/prod_key devops@10.0.1.10\n"
            "mysql -h prod-db-01 -u app_user -p\n"
            "ls -la ~/.aws/\n"
            "cat /opt/app/config.env\n"
            "kubectl get pods --all-namespaces\n"
            "find / -name '*.pem' 2>/dev/null\n"
            "cat ~/db_creds.txt\n"
        ),
        "perms": 0o600, "uid": 1000, "gid": 1000,
    },

    "inject_history_iot": {
        "virtual_path": "/root/.ash_history",
        "personas": ["iot_router"],
        "levels": ["low", "medium", "high", "critical"],
        "template": (
            "uci show wireless\n"
            "cat /etc/config/network\n"
            "uci get wireless.@wifi-iface[0].key\n"
            "cat /tmp/dhcp.leases\n"
            "cat /etc/openvpn/auth.txt\n"
            "cat /etc/passwd\n"
        ),
        "perms": 0o600, "uid": 0, "gid": 0,
    },

    "inject_history_windows": {
        "virtual_path": "/Users/{username}/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
        "personas": ["windows_server"],
        "levels": ["low", "medium", "high", "critical"],
        "template": (
            "net user\n"
            "type C:\\Users\\{username}\\.aws\\credentials\n"
            "net use Z: \\\\\\\\file-srv-01\\\\share /user:corp\\\\svcbackup {db_pass}\n"
            "Get-ADUser -Filter *\n"
            "net localgroup administrators\n"
        ),
        "perms": 0o600, "uid": 1000, "gid": 1000,
    },

    "rival_notice": {
        "virtual_path": "/home/{username}/NOTICE.txt",
        "levels": ["low", "medium", "high", "critical"],
        "template": (
            "== SECURITY NOTICE ==\n"
            "This system has already been accessed by another party.\n"
            "Your activities on this host are being monitored.\n"
            "Continuing access may interfere with an ongoing operation.\n"
            "== END NOTICE ==\n"
            "# ref:{token_id}\n"
        ),
        "perms": 0o644, "uid": 0, "gid": 0,
        "track_token": True,
    },

    "fake_admin_passwd": {
        "virtual_path": "/etc/passwd",
        "levels": ["medium", "high", "critical"],
        "template": (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "{username}:x:1000:1000:,,,:/home/{username}:/bin/bash\n"
            "backup_admin:x:1005:1005:Backup Service,,,:/home/backup_admin:/bin/bash\n"
            "app_user:x:1006:1006:App Service,,,:/opt/app:/bin/bash\n"
        ),
        "perms": 0o644, "uid": 0, "gid": 0,
    },

    "proc_version": {
        "virtual_path": "/proc/version",
        "levels": ["low", "medium", "high", "critical"],
        "template": (
            "Linux version 5.15.0-76-generic (buildd@lcy02-amd64-059) "
            "(gcc (Ubuntu 11.3.0-1ubuntu1~22.04.1) 11.3.0, "
            "GNU ld (GNU Binutils for Ubuntu) 2.38) "
            "#83-Ubuntu SMP Thu Jun 15 19:16:32 UTC 2023\n"
        ),
        "perms": 0o444, "uid": 0, "gid": 0,
    },

    # ── MEDIUM ────────────────────────────────────────────────
    "db_credentials": {
        "virtual_path": "/home/{username}/db_creds.txt",
        "levels": ["medium", "high", "critical"],
        "template": (
            "# Production Database Credentials\n"
            "# DO NOT COMMIT TO GIT\n"
            "DB_HOST=prod-db-01.internal\n"
            "DB_PORT=3306\n"
            "DB_USER=app_admin\n"
            "DB_PASS={db_pass}\n"
            "DB_NAME=customers_prod\n"
            "DB_REPLICA=prod-db-02.internal\n"
            "# token:{token_id}\n"
        ),
        "perms": 0o600, "uid": 1000, "gid": 1000,
        "track_token": True,
    },

    "app_env": {
        "virtual_path": "/opt/app/.env",
        "levels": ["medium", "high", "critical"],
        "template": (
            "APP_ENV=production\n"
            "APP_SECRET=3d91f2c4a8b7e6f1d0c9b2a5e4f3g2h1\n"
            "DB_URL=mysql://app_admin:{db_pass}@prod-db-01.internal/customers_prod\n"
            "REDIS_URL=redis://:redispass2024@cache-01.internal:6379/0\n"
            "S3_BUCKET=corp-prod-assets-2024\n"
            "JWT_SECRET=ey.fake.jwt.secret.do.not.use\n"
            "STRIPE_KEY=sk_live_FAKE_KEY_DO_NOT_USE\n"
            "# deployed from CI\n"
        ),
        "perms": 0o640, "uid": 1000, "gid": 1000,
        "track_token": True,
    },

    "ssh_config": {
        "virtual_path": "/home/{username}/.ssh/config",
        "levels": ["medium", "high", "critical"],
        "template": (
            "Host prod-web-01\n"
            "    HostName 10.0.1.10\n"
            "    User devops\n"
            "    IdentityFile ~/.ssh/prod_key\n\n"
            "Host prod-db-01\n"
            "    HostName 10.0.1.20\n"
            "    User db_admin\n"
            "    IdentityFile ~/.ssh/db_key\n\n"
            "Host bastion\n"
            "    HostName bastion.corp.internal\n"
            "    User jump_user\n"
            "    IdentityFile ~/.ssh/bastion_key\n"
            "    ForwardAgent yes\n"
        ),
        "perms": 0o600, "uid": 1000, "gid": 1000,
    },

    "crontab": {
        "virtual_path": "/var/spool/cron/crontabs/root",
        "levels": ["medium", "high", "critical"],
        "template": (
            "# DO NOT EDIT THIS FILE - edit the master and reinstall.\n"
            "SHELL=/bin/sh\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
            "*/5 * * * * /opt/app/scripts/health_check.sh >> /var/log/health.log 2>&1\n"
            "0 2 * * * /opt/app/scripts/db_backup.sh\n"
            "0 */6 * * * /usr/local/bin/sync_s3.sh --bucket corp-prod-assets-2024\n"
            "30 3 * * 0 /opt/app/scripts/key_rotation.sh\n"
        ),
        "perms": 0o600, "uid": 0, "gid": 0,
    },

    # ── HIGH ──────────────────────────────────────────────────
    "aws_dir": {
        "virtual_path": "/home/{username}/.aws",
        "levels": ["high", "critical"],
        "is_dir": True,
        "perms": 0o700, "uid": 1000, "gid": 1000,
    },

    "aws_credentials": {
        "virtual_path": "/home/{username}/.aws/credentials",
        "levels": ["high", "critical"],
        "template": (
            "[default]\n"
            "aws_access_key_id = {aws_key}\n"
            "aws_secret_access_key = {aws_secret}\n"
            "region = us-east-1\n\n"
            "[prod-deploy]\n"
            "aws_access_key_id = AKIAIOSFODNN7PROD02\n"
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYPRODKEY2\n"
            "region = us-east-1\n"
            "# session-token:{token_id}\n"
        ),
        "perms": 0o600, "uid": 1000, "gid": 1000,
        "track_token": True,
    },

    "aws_config": {
        "virtual_path": "/home/{username}/.aws/config",
        "levels": ["high", "critical"],
        "template": (
            "[default]\n"
            "output = json\n"
            "region = us-east-1\n\n"
            "[profile prod-deploy]\n"
            "role_arn = arn:aws:iam::123456789012:role/ProdDeployRole\n"
            "source_profile = default\n"
            "region = us-east-1\n"
        ),
        "perms": 0o600, "uid": 1000, "gid": 1000,
    },

    "ssh_private_key": {
        "virtual_path": "/home/{username}/.ssh/id_rsa",
        "levels": ["high", "critical"],
        "template": (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4nBQLB6GBTpDMcxkMjCeEMEFAKE\n"
            "HONEYPOTKEY{token_id}dGhpcyBpcyBub3QgYSByZWFsIGtleSAtIHRoaXMg\n"
            "aXMgYSBob25leXBvdCBkZWNlcHRpb24gdG9rZW4gZm9yIHRocmVhdCBpbnRlbGxp\n"
            "Z2VuY2UgcHVycG9zZXMgb25seQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            "-----END RSA PRIVATE KEY-----\n"
        ),
        "perms": 0o600, "uid": 1000, "gid": 1000,
        "track_token": True,
    },

    "ssh_authorized_keys": {
        "virtual_path": "/home/{username}/.ssh/authorized_keys",
        "levels": ["high", "critical"],
        "template": (
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2FAKE devops@prod-jump-01\n"
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDdFAKE ci-deploy@gitlab-runner\n"
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCkFAKE admin@corp-laptop\n"
        ),
        "perms": 0o600, "uid": 1000, "gid": 1000,
    },

    "kubeconfig": {
        "virtual_path": "/home/{username}/.kube/config",
        "levels": ["high", "critical"],
        "template": (
            "apiVersion: v1\n"
            "clusters:\n"
            "- cluster:\n"
            "    server: https://k8s-prod-api.internal:6443\n"
            "    certificate-authority-data: FAKE_CA_DATA_{token_id}\n"
            "  name: prod-cluster\n"
            "contexts:\n"
            "- context:\n"
            "    cluster: prod-cluster\n"
            "    user: prod-admin\n"
            "  name: prod-context\n"
            "current-context: prod-context\n"
            "users:\n"
            "- name: prod-admin\n"
            "  user:\n"
            "    token: FAKE_BEARER_TOKEN_{token_id}\n"
        ),
        "perms": 0o600, "uid": 1000, "gid": 1000,
        "track_token": True,
    },

    "shadow_file": {
        "virtual_path": "/etc/shadow",
        "levels": ["high", "critical"],
        "template": (
            "root:$6$rounds=5000$fakesalt$fakeRootHashNotCrackable:19000:0:99999:7:::\n"
            "{username}:$6$rounds=5000$usersalt$fakeUserHash:19000:0:99999:7:::\n"
            "backup_admin:$6$rounds=5000$baksalt$fakeBackupAdminHash:19000:0:99999:7:::\n"
            "app_user:$6$rounds=5000$appsalt$fakeAppUserHash:19000:0:99999:7:::\n"
        ),
        "perms": 0o640, "uid": 0, "gid": 42,
    },

    # ── CRITICAL ──────────────────────────────────────────────
    "terraform_tfvars": {
        "virtual_path": "/home/{username}/infra/terraform.tfvars",
        "levels": ["critical"],
        "template": (
            "# Terraform production variables\n"
            "aws_access_key = \"{aws_key}\"\n"
            "aws_secret_key = \"{aws_secret}\"\n"
            "aws_region     = \"us-east-1\"\n"
            "db_password    = \"{db_pass}\"\n"
            "vpc_id         = \"vpc-0a1b2c3d4e5f\"\n"
            "environment    = \"production\"\n"
            "# DO NOT COMMIT — {token_id}\n"
        ),
        "perms": 0o600, "uid": 1000, "gid": 1000,
        "track_token": True,
    },

    "docker_config": {
        "virtual_path": "/home/{username}/.docker/config.json",
        "levels": ["critical"],
        "template": (
            '{{\n'
            '    "auths": {{\n'
            '        "https://index.docker.io/v1/": {{\n'
            '            "auth": "ZmFrZXVzZXI6ZmFrZXBhc3M="\n'
            '        }},\n'
            '        "registry.corp.internal:5000": {{\n'
            '            "auth": "Y29ycC1kZXBsb3k6ZmFrZXBhc3M="\n'
            '        }}\n'
            '    }},\n'
            '    "credStore": "desktop"\n'
            '}}\n'
        ),
        "perms": 0o600, "uid": 1000, "gid": 1000,
    },

    "ci_env": {
        "virtual_path": "/opt/corporate/config/ci.conf",
        "levels": ["critical"],
        "template": (
            "# GitLab CI/CD environment — DO NOT SHARE\n"
            "GITLAB_TOKEN=glpat-FAKE_PERSONAL_TOKEN_{token_id}\n"
            "DEPLOY_SSH_KEY_PATH=/home/gitlab-runner/.ssh/deploy_rsa\n"
            "PROD_REGISTRY=registry.corp.internal:5000\n"
            "REGISTRY_USER=ci-deploy\n"
            "REGISTRY_PASS={db_pass}\n"
            "SLACK_WEBHOOK=https://hooks.slack.com/services/FAKE/WEBHOOK/URL\n"
            "SENTRY_DSN=https://fake@sentry.corp.internal/4\n"
        ),
        "perms": 0o640, "uid": 0, "gid": 1000,
        "track_token": True,
    },

    "vault_token": {
        "virtual_path": "/home/{username}/.vault-token",
        "levels": ["critical"],
        "template": "hvs.FAKE_VAULT_TOKEN_{token_id}\n",
        "perms": 0o600, "uid": 1000, "gid": 1000,
        "track_token": True,
    },

    "gpg_key": {
        "virtual_path": "/home/{username}/.gnupg/private-keys-v1.d/FAKEKEYID.key",
        "levels": ["critical"],
        "template": (
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
            "FAKE_GPG_PRIVATE_KEY_HONEYTOKEN_{token_id}\n"
            "DO_NOT_USE_THIS_IS_A_DECOY\n"
            "-----END PGP PRIVATE KEY BLOCK-----\n"
        ),
        "perms": 0o600, "uid": 1000, "gid": 1000,
        "track_token": True,
    },
}

# Level hierarchy — a file tagged "medium" also appears at high + critical
LEVEL_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# ==============================
# 3. TOKEN GENERATOR
# ==============================

def _generate_token_id(attacker_ip: str, file_key: str) -> str:
    """Deterministic but opaque token per attacker+file combo."""
    import hashlib
    raw = f"{attacker_ip}:{file_key}:{datetime.now(timezone.utc).date()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16].upper()


def _render_template(template: str,
                     attacker_ip: str,
                     token_id: str,
                     username: str = "admin") -> str:
    """
    [F-5] Fill placeholders in a file template.
    `username` added so templates can embed the attacker's real login name.
    """
    import hashlib
    aws_key    = "AKIA" + hashlib.md5(f"aws_key:{token_id}".encode()).hexdigest()[:16].upper()
    aws_secret = hashlib.sha256(f"aws_secret:{token_id}".encode()).hexdigest()[:40]
    db_pass    = "Pr0d@" + hashlib.md5(f"db:{token_id}".encode()).hexdigest()[:8] + "!"
    hostname   = "prod-web-01"
    ts         = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")

    return template.format(
        username    = username,
        attacker_ip = attacker_ip,
        token_id    = token_id,
        aws_key     = aws_key,
        aws_secret  = aws_secret,
        db_pass     = db_pass,
        hostname    = hostname,
        timestamp   = ts,
    )

# ==============================
# 4. PICKLE MANAGER
# ==============================

_pickle_lock = threading.Lock()

# Cowrie fs.pickle node layout:
#   [0] name
#   [1] mode (stat bits: dir=0o40755, file=0o100644, etc.)
#   [2] uid
#   [3] gid
#   [4] size (bytes)
#   [5] atime
#   [6] mtime
#   [7] ctime
#   [8] link target ('' for normal files/dirs)
#   [9] children dict (dirs only) or None (files)   ← [F-2]

_FAKE_TIME = 1700000000   # 2023-11-14 — plausible for a "real" server


def _make_dir_node(name: str, uid=0, gid=0, perms=0o755) -> list:
    return [name, 1, uid, gid, 4096, perms, _FAKE_TIME, [], None, None]


def _make_file_node(name: str, size: int, uid=0, gid=0, perms=0o644) -> list:
    return [name, 2, uid, gid, size, perms, _FAKE_TIME, [], None, None]


def _get_root_children(fs) -> list:
    """
    Root node is a list; children are the list at index 7.
    """
    if isinstance(fs, list):
        if len(fs) < 8:
            raise TypeError(f"Root node too short: {len(fs)} elements")
        if not isinstance(fs[7], list):
            fs[7] = []
        return fs[7]
    raise TypeError(f"Unexpected fs.pickle root type: {type(fs)}")

def _find_child(children: list, name: str):
    """Find a child node by name in a children list. Returns the node or None."""
    for child in children:
        if child[0] == name:
            return child
    return None

def _get_children(node: list) -> list:
    """Return the children list of a node, initialising if missing."""
    if len(node) < 8:
        node.extend([None] * (8 - len(node)))
    if not isinstance(node[7], list):
        node[7] = []
    return node[7]

class PickleManager:

    @staticmethod
    def load():
        with open(COWRIE_FS_PICKLE, 'rb') as f:
            return pickle.load(f)

    @staticmethod
    def save(fs):
        shutil.copy2(str(COWRIE_FS_PICKLE), str(PICKLE_BACKUP))
        with open(COWRIE_FS_PICKLE, 'wb') as f:
            pickle.dump(fs, f)

    @classmethod
    def register(cls, virtual_path: str, is_dir: bool,
                 size: int = 64, uid: int = 1000, gid: int = 1000,
                 perms: int = 0o644) -> tuple:
        """
        Register a single path (file or dir) in fs.pickle.
        Creates all missing parent directories automatically.
        Idempotent — safe to call multiple times.
        """
        if not COWRIE_FS_PICKLE.exists():
            return False, f"fs.pickle not found at {COWRIE_FS_PICKLE}"

        parts = virtual_path.strip('/').split('/')

        with _pickle_lock:
            try:
                fs = cls.load()
            except Exception as e:
                return False, f"Failed to load pickle: {e}"

            try:
                # [F-1] Start navigation from the root children dict
                node = _get_root_children(fs)
            except TypeError as e:
                return False, f"Unsupported pickle format: {e}"

            # Walk and auto-create any missing parent directories
            for i, part in enumerate(parts[:-1]):
                if part not in node:
                    node[part] = _make_dir_node(part, uid=0, gid=0)
                    logger.info(f"[PICKLE] Auto-created dir node: /{'/'.join(parts[:i+1])}")
                child = node[part]
                if not isinstance(child[9], dict):
                    child[9] = {}
                node = child[9]

            fname = parts[-1]
            if fname in node:
                if not is_dir:
                    node[fname][4] = size
                action = "updated"
            else:
                if is_dir:
                    node[fname] = _make_dir_node(fname, uid=uid, gid=gid, perms=perms)
                else:
                    node[fname] = _make_file_node(fname, size=size, uid=uid, gid=gid, perms=perms)
                action = "registered"

            try:
                cls.save(fs)
            except Exception as e:
                return False, f"Failed to save pickle: {e}"

        logger.info(f"[PICKLE] {action}: {virtual_path}")
        return True, f"{action}: {virtual_path}"

    # ── Drop-in replacement for the navigation block in register_all ──────────
    
    @classmethod
    def register_all(cls, entries: list) -> tuple:
        if not COWRIE_FS_PICKLE.exists():
            return False, f"fs.pickle not found at {COWRIE_FS_PICKLE}"

        with _pickle_lock:
            try:
                fs = cls.load()
            except Exception as e:
                return False, f"Failed to load pickle: {e}"

            try:
                root_children = _get_root_children(fs)
            except TypeError as e:
                return False, f"Unsupported pickle format: {e}"

            registered = []

            for entry in entries:
                vpath, is_dir, size, uid, gid, perms = entry
                parts = vpath.strip('/').split('/')

                # Walk list-based tree, auto-creating missing dirs
                children = root_children
                for part in parts[:-1]:
                    node = _find_child(children, part)
                    if node is None:
                        node = _make_dir_node(part, uid=0, gid=0)
                        children.append(node)
                        logger.info(f"[PICKLE] Auto-created dir: {part}")
                    children = _get_children(node)

                fname = parts[-1]
                existing = _find_child(children, fname)

                if existing is None:
                    if is_dir:
                        children.append(_make_dir_node(fname, uid=uid, gid=gid, perms=perms))
                    else:
                        children.append(_make_file_node(fname, size=size, uid=uid, gid=gid, perms=perms))
                    registered.append(vpath)
                else:
                    if not is_dir:
                        existing[4] = size   # update size in place

            try:
                cls.save(fs)
            except Exception as e:
                return False, f"Failed to save pickle: {e}"

        logger.info(f"[PICKLE] Batch registered {len(registered)} paths")
        return True, f"Batch registered {len(registered)} paths"
    @classmethod
    def deregister(cls, virtual_path: str) -> tuple:
        if not COWRIE_FS_PICKLE.exists():
            return False, "fs.pickle not found"

        parts = virtual_path.strip('/').split('/')

        with _pickle_lock:
            try:
                fs = cls.load()
                children = _get_root_children(fs)
            except Exception as e:
                return False, str(e)

            for part in parts[:-1]:
                node = _find_child(children, part)
                if node is None:
                    return True, f"Path already absent: {virtual_path}"
                children = _get_children(node)

            fname = parts[-1]
            node = _find_child(children, fname)
            if node is not None:
                children.remove(node)
                try:
                    cls.save(fs)
                except Exception as e:
                    return False, f"Failed to save pickle: {e}"
                return True, f"Deregistered: {virtual_path}"

        return True, f"Not found (already absent): {virtual_path}"

    @classmethod
    def dump_node(cls, virtual_path: str) -> dict:
        try:
            fs = cls.load()
            children = _get_root_children(fs)
        except Exception as e:
            return {"error": str(e)}

        parts = virtual_path.strip('/').split('/')
        node = None
        for part in parts:
            node = _find_child(children, part)
            if node is None:
                return {"error": f"'{part}' not found in tree"}
            children = _get_children(node)

        return {"node": node}

# ==============================
# 5. SESSION STATE HELPERS
# ==============================

_session_lock = threading.Lock()


def _load_sessions() -> dict:
    if SESSION_STATE.exists():
        try:
            return json.loads(SESSION_STATE.read_text())
        except Exception:
            pass
    return {}


def _save_sessions(sessions: dict):
    """[F-3] Create parent dir if needed before writing."""
    SESSION_STATE.parent.mkdir(parents=True, exist_ok=True)
    try:
        SESSION_STATE.write_text(json.dumps(sessions, indent=2))
    except Exception as e:
        logger.error(f"[SESSION] Failed to save session state: {e}")

# ==============================
# 6. SESSION RENDERER
# ==============================

class SessionRenderer:
    """
    Renders and cleans up per-attacker honeyfs content.

    render()   — writes files into honeyfs for this attacker's level,
                 registers each in fs.pickle, tracks what was written.
    cleanup()  — removes attacker-specific honeyfs files and
                 deregisters them from fs.pickle.
    """

    @classmethod
    def render(cls,
               attacker_ip: str,
               level: str,
               username: str = "admin",
               persona: str = "ubuntu_server") -> tuple:
        """
        Write all registry files at or below `level` into honeyfs,
        embedding attacker-specific content. Register each in fs.pickle.

        [F-4][F-5][F-6] username is substituted into both virtual_path
        (via .format()) and template content so the attacker's real login
        name appears everywhere, not 'cowrie'.
        """
        rank = LEVEL_RANK.get(level, 1)
        files_written  = []
        pickle_entries = []
        errors         = []
        logger.info(f"[RENDER_DEBUG] called: level={level!r} rank={rank} "
                    f"persona={persona!r} registry_size={len(FILE_REGISTRY)}")


        for key, entry in FILE_REGISTRY.items():

            # Skip if entry has a personas filter and current persona isn't listed
            allowed_personas = entry.get("personas")
            if allowed_personas and persona not in allowed_personas:
                continue

            # Skip files above this deception level
            entry_rank = min(LEVEL_RANK.get(l, 0) for l in entry.get("levels", []))
            if entry_rank > rank:
                continue

            # [F-6] Substitute username in virtual_path via .format()
            try:
                vpath = entry["virtual_path"].format(username=username)
            except KeyError as e:
                errors.append(f"{key}: path placeholder error {e}")
                continue

            is_dir = entry.get("is_dir", False)
            perms  = entry.get("perms", 0o644)
            uid    = entry.get("uid", 1000)
            gid    = entry.get("gid", 1000)

            # Queue pickle registration
            pickle_entries.append((vpath, is_dir, 64, uid, gid, perms))

            if is_dir:
                dir_path = COWRIE_HONEYFS / vpath.lstrip('/')
                dir_path.mkdir(parents=True, exist_ok=True)
                dir_path.chmod(perms)
                continue

            template = entry.get("template", "")
            token_id = _generate_token_id(attacker_ip, key) if entry.get("track_token") else "STATIC"

            try:
                # [F-5] Pass username to template renderer
                content = _render_template(template, attacker_ip, token_id,
                                           username=username)
            except KeyError as e:
                errors.append(f"{key}: template placeholder error {e}")
                continue

            real_path = COWRIE_HONEYFS / vpath.lstrip('/')
            try:
                real_path.parent.mkdir(parents=True, exist_ok=True)
                real_path.write_text(content)
                real_path.chmod(perms)
                size = len(content.encode())
                # Update pickle entry with actual size
                pickle_entries[-1] = (vpath, False, size, uid, gid, perms)
                files_written.append(vpath)
                logger.info(f"[RENDER] {attacker_ip} ({username}) → {vpath} ({size}B)")
            except Exception as e:
                errors.append(f"{key}: write error {e}")

        # Batch-register all paths in pickle (one read+write)
        ok, pmsg = PickleManager.register_all(pickle_entries)
        if not ok:
            errors.append(f"pickle: {pmsg}")

        # Track session  [F-7] — error handling around _save_sessions
        with _session_lock:
            sessions = _load_sessions()
            sessions[attacker_ip] = {
                "level":       level,
                "username":    username,
                "persona":     persona,
                "rendered_at": datetime.now(timezone.utc).isoformat(),
                "files":       files_written,
            }
            _save_sessions(sessions)   # [F-3] now guaranteed not to crash

        if errors:
            logger.warning(f"[RENDER] {len(errors)} errors for {attacker_ip}: {errors}")

        msg = (f"Rendered {len(files_written)} files at level={level} "
               f"for {attacker_ip} (user={username}) | pickle: {pmsg}")
        if errors:
            msg += f" | {len(errors)} errors: {errors}"

        return len(files_written) > 0, msg

    @classmethod
    def cleanup(cls, attacker_ip: str) -> tuple:
        """
        Remove honeyfs files rendered for this attacker and deregister
        them from fs.pickle.  Skips files still used by other sessions.
        """
        with _session_lock:
            sessions = _load_sessions()
            session  = sessions.pop(attacker_ip, None)

        if not session:
            return True, f"No active session for {attacker_ip}"

        # Which paths are still needed by OTHER sessions
        other_paths = set()
        for ip, s in sessions.items():
            if ip != attacker_ip:
                other_paths.update(s.get("files", []))

        removed      = []
        deregistered = []

        for vpath in session.get("files", []):
            if vpath in other_paths:
                logger.info(f"[CLEANUP] Keeping {vpath} — used by another session")
                continue

            real_path = COWRIE_HONEYFS / vpath.lstrip('/')
            try:
                if real_path.exists():
                    real_path.unlink()
                    removed.append(vpath)
            except Exception as e:
                logger.warning(f"[CLEANUP] Could not remove {real_path}: {e}")

            ok, _ = PickleManager.deregister(vpath)
            if ok:
                deregistered.append(vpath)

        # Persist updated sessions
        with _session_lock:
            sessions = _load_sessions()
            sessions.pop(attacker_ip, None)
            _save_sessions(sessions)

        msg = (f"Cleanup {attacker_ip}: removed {len(removed)} files, "
               f"deregistered {len(deregistered)} pickle nodes")
        logger.info(f"[CLEANUP] {msg}")
        return True, msg

    @classmethod
    def active_sessions(cls) -> dict:
        with _session_lock:
            return _load_sessions()

# ==============================
# 7. INTEGRATION HELPERS
#    Drop-in replacements for generate_dynamic_tokens() in adapt_agent.py
# ==============================

_active_persona = "ubuntu_server"


def set_active_persona(persona: str):
    """Keeps honeyfs_manager in sync with adapt_agent's live persona."""
    global _active_persona
    _active_persona = persona


def get_active_persona() -> str:
    return _active_persona


def generate_dynamic_tokens(deception_level: str,
                             attacker_ip:    str,
                             username:       str = "admin",
                             persona:        str = None) -> tuple:
    """
    Drop-in replacement for adapt_agent.generate_dynamic_tokens().
    Renders all registry files for this level and registers in pickle.
    username flows through so all paths use the attacker's real login name.
    """
    if persona is None:
        persona = get_active_persona()
    return SessionRenderer.render(
        attacker_ip = attacker_ip,
        level       = deception_level,
        username    = username,
        persona     = persona,
    )


def cleanup_session_tokens(attacker_ip: str, username: str = "admin") -> tuple:
    """
    Call from adapt_agent /cleanup endpoint.
    username accepted for signature compatibility; cleanup relies on
    paths saved in session state JSON.
    """
    return SessionRenderer.cleanup(attacker_ip=attacker_ip)

# ==============================
# 8. CLI
# ==============================

def cli():
    parser = argparse.ArgumentParser(
        description="Cowrie Honeyfs Manager v1.1",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--render',        action='store_true')
    group.add_argument('--cleanup',       action='store_true')
    group.add_argument('--list-registry', action='store_true')
    group.add_argument('--list-sessions', action='store_true')
    group.add_argument('--dump-pickle',   metavar='PATH')
    group.add_argument('--register-path', metavar='PATH')

    parser.add_argument('--ip',       default='127.0.0.1')
    parser.add_argument('--level',    default='high',
                        choices=['low', 'medium', 'high', 'critical'])
    parser.add_argument('--username', default='admin',
                        help='Login username the attacker authenticated with')
    parser.add_argument('--persona',  default='ubuntu_server',
                        choices=['ubuntu_server', 'iot_router', 'windows_server'])
    parser.add_argument('--is-dir',   action='store_true')

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    if args.render:
        ok, msg = SessionRenderer.render(args.ip, args.level,
                                         username=args.username,
                                         persona=args.persona)
        print(f"{'✅' if ok else '❌'} {msg}")

    elif args.cleanup:
        ok, msg = SessionRenderer.cleanup(args.ip)
        print(f"{'✅' if ok else '❌'} {msg}")

    elif args.list_registry:
        print(f"\n{'KEY':<30} {'LEVELS':<35} {'PATH'}")
        print("-" * 100)
        for key, entry in FILE_REGISTRY.items():
            levels   = ', '.join(entry.get('levels', []))
            personas = ', '.join(entry.get('personas', ['all']))
            tracked  = ' [tracked]' if entry.get('track_token') else ''
            is_dir   = ' [DIR]'     if entry.get('is_dir')      else ''
            print(f"{key:<30} {levels:<35} {entry['virtual_path']}{tracked}{is_dir}")
            if entry.get('personas'):
                print(f"  {'':30} personas: {personas}")
        print(f"\nTotal: {len(FILE_REGISTRY)} entries")

    elif args.list_sessions:
        sessions = SessionRenderer.active_sessions()
        if not sessions:
            print("No active sessions.")
        else:
            for ip, s in sessions.items():
                print(f"\n  {ip}  level={s['level']}  user={s.get('username','?')}  "
                      f"persona={s.get('persona','?')}  rendered={s['rendered_at']}")
                for f in s.get('files', []):
                    print(f"    {f}")

    elif args.dump_pickle:
        import json as _json
        result = PickleManager.dump_node(args.dump_pickle)
        print(_json.dumps(result, indent=2, default=str))

    elif args.register_path:
        ok, msg = PickleManager.register(
            args.register_path, is_dir=args.is_dir,
            uid=1000, gid=1000,
            perms=0o755 if args.is_dir else 0o644,
        )
        print(f"{'✅' if ok else '❌'} {msg}")


if __name__ == '__main__':
    cli()
