# adaptive_engine.py
# ============================================================
# ADAPTIVE DECEPTION ENGINE (SOAR) — PRODUCTION v4 (ULTIMATE)
# ============================================================
# Features:
#   - Hybrid Decision Mode (DQN Reinforcement Learning + RULE)
#   - Honeypot Log Normalizer (Cowrie + Dionaea translation)
#   - Attacker profiling with JSON persistence
#   - Thread-safe action queuing and Async SSH
#   - IP Command-Injection protection
# ============================================================

import os
import re
import json
import socket
import threading
import queue
import requests
import time
import signal
import sys
import logging
import ipaddress
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    print("[WARN] paramiko not installed — SSH actions disabled")

try:
    from elasticsearch import Elasticsearch
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False
    print("[WARN] elasticsearch-py not installed — ES logging disabled")

try:
    from stable_baselines3 import DQN
    DQN_AVAILABLE = True
except ImportError:
    DQN_AVAILABLE = False
    print("[WARN] stable-baselines3 not installed - DQN policy disabled")

try:
    from dqn_adaptive_deception import (
        ACTIONS as DQN_ACTIONS,
        SessionState,
        build_obs_from_ttp,
        load_ttp_vocab,
        resolve_ttp_for_vocab,
    )
    DQN_MODULE_AVAILABLE = True
except ImportError:
    DQN_MODULE_AVAILABLE = False
    DQN_ACTIONS = {
        0: "monitor",
        1: "regenerate_tokens",
        2: "deploy_decoy_service",
        3: "throttle",
        4: "containment",
    }
    SessionState = None
    build_obs_from_ttp = None
    load_ttp_vocab = None
    resolve_ttp_for_vocab = None
    print("[WARN] dqn_adaptive_deception module not available - using RULE fallbacks")

# ============================================================
# 1. CONFIGURATION
# ============================================================
GENERATOR_SCRIPT = "/home/cowrie/generate_honeytokens.py"
LISTEN_IP   = '0.0.0.0'
LISTEN_PORT = 9000

ML_API         = "http://localhost:5000/analyze_log"
ML_API_TIMEOUT = 5

ES_HOST        = "http://127.0.0.1:9200"
ABUSE_IPDB_KEY = "YOUR_API_KEY_HERE"
LOGSTASH_URL = "http://127.0.0.1:5000"
HONEYPOT_IP   = "100.113.245.10"
HONEYPOT_USER = "cowrie"
SSH_PORT      = 2200
SSH_KEY       = r"C:\Users\PMLS\.ssh\id_rsa"
HONEYFS       = "/home/cowrie/cowrie/src/cowrie/data/honeyfs"
SDN_SCRIPT    = "/home/cowrie/sdn_enforcer.py"

COOLDOWN_WINDOW = 60
SSH_TIMEOUT     = 5
SSH_WORKERS     = 3
LOGSTASH_TIME_OUT = 5
RISK_SCORE_CAP  = 500.0
HISTORY_CAP     = 100

PROFILES_PATH   = "attacker_profiles.json"

# DQN policy integration
USE_DQN_POLICY = os.getenv("USE_DQN_POLICY", "1") == "1"
DQN_MODEL_PATH = os.getenv("DQN_MODEL_PATH", "dqn_adaptive_deception_quick")
DQN_VOCAB_PATH = os.getenv("DQN_VOCAB_PATH", f"{DQN_MODEL_PATH}.ttp_vocab.json")
DQN_MAX_MINUTES = int(os.getenv("DQN_MAX_MINUTES", "30"))
DQN_DECISION_COOLDOWN = int(os.getenv("DQN_DECISION_COOLDOWN", str(COOLDOWN_WINDOW)))

# Mock SSH for testing
MOCK_SSH = os.getenv("MOCK_SSH", "1") == "1"

# Threat weights & Sequences
TTP_WEIGHTS = {
    "T1046": 1.0,  "T1083": 1.1,  "T1033": 1.1,
    "T1003": 1.8,  "T1548": 1.6,  "T1021": 1.7,
    "T1105": 1.5,  "T1048": 2.0,  "T1485": 2.0,
    "T1059": 1.3,  "T1070": 1.4,  "T1110": 1.2,
    "T1136": 1.5,  "T1098": 1.6,  "T1496": 1.4,
}

TTP_SEQUENCES = {
    ("T1087", "T1069", "T1548"): 2.5,
    ("T1046", "T1021", "T1105"): 2.0,
    ("T1003", "T1552", "T1041"): 3.0,
    ("T1059", "T1105", "T1053"): 2.2,
    ("T1110", "T1021", "T1003"): 2.8,
}

STAGE_THRESHOLDS = {1: 20.0, 2: 50.0, 3: 100.0, 4: 150.0}
RL_ACTIONS = dict(DQN_ACTIONS)

# ============================================================
# 2. LOGGING
# ============================================================
logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s [%(levelname)s] %(message)s",
    handlers= [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("adaptive_engine.log", encoding="utf-8"),
    ]
)
log = logging.getLogger("adaptive_engine")

# ============================================================
# 3. STATE
# ============================================================
def _default_profile():
    return {
        "risk_score":       0.0,
        "current_stage":    0,
        "last_action_time": 0.0,
        "last_seen":        time.time(),
        "history":          [],
        "engagement_minutes": 0,
        "deception_exposure": 0.0,
        "rl_last_action": 0,
    }

attacker_profiles: dict = defaultdict(_default_profile)
profile_lock  = threading.Lock()

ip_cache      = {}
ip_cache_lock = threading.Lock()

es_queue     = queue.Queue(maxsize=5000)
action_queue = queue.Queue(maxsize=500)

_shutdown_event = threading.Event()

dqn_model = None
dqn_ttp_vocab = ["BENIGN"]
dqn_ttp_to_idx = {"BENIGN": 0}
dqn_lock = threading.Lock()
dqn_enabled = False

# ============================================================
# 4. HONEYPOT LOG NORMALIZER
# ============================================================
class HoneypotLogNormalizer:
    DIONAEA_PORT_MAP = {
        445: "smbclient -L {src_ip}", 139: "smbclient -L {src_ip}",
        21: "ftp -nv {src_ip}", 22: "ssh user@{src_ip}", 23: "telnet {src_ip}",
        80: "curl http://{src_ip}/", 443: "curl -k https://{src_ip}/",
        3306: "mysql -h {src_ip} -u root -p", 5900: "xfreerdp /v:{src_ip}",
        1433: "sqlcmd -S {src_ip} -U sa", 6379: "redis-cli -h {src_ip}", 27017: "mongo {src_ip}"
    }

    DIONAEA_PROTOCOL_MAP = {
        'smb': "smbclient -L {src_ip}", 'ftp': "ftp -nv {src_ip}",
        'http': "curl http://{src_ip}/", 'https': "curl -k https://{src_ip}/",
        'mysql': "mysql -h {src_ip} -u root -p", 'mssql': "sqlcmd -S {src_ip} -U sa",
        'upnp': "nmap -sV --script upnp-info {src_ip}", 'tftp': "tftp -i {src_ip} GET shell.bin",
        'epmap': "nmap -p 135 {src_ip}"
    }

    def normalize(self, entry: dict) -> dict:
        eventid = entry.get('eventid', '')
        src_ip  = entry.get('src_ip', 'unknown')
        session = entry.get('session', src_ip)
        
        if 'cowrie' in eventid or 'input' in entry:
            return self._normalize_cowrie(entry, eventid, src_ip, session)
        elif 'dionaea' in eventid or 'dst_port' in entry or 'proto' in entry:
            return self._normalize_dionaea(entry, eventid, src_ip, session)
            
        command = entry.get('input', entry.get('message', f"connection from {src_ip}"))
        return {'session_id': session, 'src_ip': src_ip, 'command': str(command), 'source': 'unknown'}

    def _normalize_cowrie(self, entry, eventid, src_ip, session):
        if 'command.input' in eventid or 'input' in entry:
            command = entry.get('input', '').strip()
        elif 'file_download' in eventid:
            command = f"wget {entry.get('url', 'http://unknown/file')}"
        elif 'login' in eventid:
            command = f"ssh {entry.get('username', 'root')}@{src_ip}"
        else:
            command = entry.get('input', entry.get('message', f"ssh user@{src_ip}"))
        return {'session_id': session, 'src_ip': src_ip, 'command': command, 'source': 'cowrie'}

    def _normalize_dionaea(self, entry, eventid, src_ip, session):
        dst_port = entry.get('dst_port', 0)
        proto    = entry.get('proto', entry.get('protocol', '')).lower()
        
        if 'download' in eventid:
            command = f"wget {entry.get('url', f'http://{src_ip}/malware')} -O /tmp/payload.bin"
        elif 'shellcode' in eventid or 'exploit' in eventid:
            command = "bash -c 'echo payload | base64 -d | bash'"
        elif 'login' in eventid or 'auth' in eventid:
            command = f"hydra -l root -P wordlist.txt {proto}://{src_ip}"
        elif proto in self.DIONAEA_PROTOCOL_MAP:
            command = self.DIONAEA_PROTOCOL_MAP[proto].format(src_ip=src_ip)
        elif dst_port in self.DIONAEA_PORT_MAP:
            command = self.DIONAEA_PORT_MAP[dst_port].format(src_ip=src_ip)
        else:
            command = f"nmap -sV -p {dst_port} {src_ip}"
            
        return {'session_id': session, 'src_ip': src_ip, 'command': command, 'source': 'dionaea'}

normalizer = HoneypotLogNormalizer()

# ============================================================
# 5. UTILITIES (Profiles, Validation, Background Workers)
# ============================================================
def save_profiles():
    try:
        with profile_lock:
            data = {ip: dict(p) for ip, p in attacker_profiles.items()}
        with open(PROFILES_PATH, "w") as fh:
            json.dump(data, fh, indent=2)
    except Exception as e: log.error(f"Profile save failed: {e}")

def load_profiles():
    path = Path(PROFILES_PATH)
    if not path.exists(): return
    try:
        with open(path) as fh: data = json.load(fh)
        with profile_lock:
            for ip, p in data.items(): attacker_profiles[ip].update(p)
        log.info(f"[*] Profiles restored ← {PROFILES_PATH} ({len(data)} entries)")
    except Exception as e: log.warning(f"Profile restore failed: {e}")

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def es_writer_worker():
    if not ES_AVAILABLE:
        while True:
            if es_queue.get() is None: break
        return
    es = Elasticsearch(ES_HOST, verify_certs=False)
    while True:
        try:
            doc = es_queue.get()
            if doc is None: break
            es.index(index="deception-actions", document=doc)
            es_queue.task_done()
        except Exception as e: log.error(f"ES write failed: {e}")

def ssh_action_worker():
    while True:
        try:
            task = action_queue.get()
            if task is None: break
            action_type, attacker_ip = task
            if MOCK_SSH:
                log.info(f"      [MOCK] Would execute: {action_type} for {attacker_ip}")
                action_queue.task_done()
                continue
            if not PARAMIKO_AVAILABLE:
                action_queue.task_done()
                continue
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(HONEYPOT_IP, port=SSH_PORT, username=HONEYPOT_USER, key_filename=SSH_KEY, timeout=SSH_TIMEOUT)
                execute_defense(ssh, action_type, attacker_ip)
                ssh.close()
            except Exception as e: log.error(f"SSH execution failed: {e}")
            finally: action_queue.task_done()
        except Exception as e: log.error(f"SSH loop error: {e}")

def async_enrich_ip(ip: str):
    score = 0
    try:
        if "YOUR_API_KEY_HERE" not in ABUSE_IPDB_KEY:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSE_IPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 30}, timeout=5
            )
            score = int(r.json()["data"]["abuseConfidenceScore"])
            with profile_lock: attacker_profiles[ip]["risk_score"] += score * 0.1
            log.info(f"[*] Threat Intel: {ip} AbuseScore={score}/100")
    except Exception: pass
    finally:
        with ip_cache_lock: ip_cache[ip] = score

def shutdown_handler(sig, frame):
    log.info("\n[!] Shutting down — saving profiles and flushing queues …")
    _shutdown_event.set()
    save_profiles()
    es_queue.put(None)
    for _ in range(SSH_WORKERS): action_queue.put(None)
    time.sleep(2)
    sys.exit(0)

signal.signal(signal.SIGINT,  shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)

threading.Thread(target=es_writer_worker, daemon=True, name="ES-Writer").start()
for i in range(SSH_WORKERS): threading.Thread(target=ssh_action_worker, daemon=True, name=f"SSH-Worker-{i}").start()

# ============================================================
# 6. DEFENSE ACTIONS
# ============================================================
def _run_ssh_cmd(ssh, cmd: str) -> tuple:
    if MOCK_SSH: return "", ""
    try:
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=10)
        stdout.channel.recv_exit_status()
        return stdout.read().decode(errors='replace').strip(), stderr.read().decode(errors='replace').strip()
    except Exception as e: return "", str(e)

def execute_defense(ssh, action_type: str, attacker_ip: str):
    # --- ACTIVE DECEPTION: DEPLOY DECOY SERVICES ---
    if action_type == "deploy_decoy_service":
        log.info(f"      [APP] Deploying active decoy services (Dionaea) for {attacker_ip}")
        # Spin up the Dionaea Docker container to open juicy ports (SMB, FTP, MSSQL)
        _run_ssh_cmd(ssh, "sudo docker start dionaea")
        
        # We ALSO trigger a token regeneration to drop the DB credentials pointing to Dionaea
        cmd = f"python3 {GENERATOR_SCRIPT} --base-dir {HONEYFS} --deception-level high --mutate --attacker-ip {attacker_ip} --silent"
        _run_ssh_cmd(ssh, cmd)
        log.info(f"      [APP] ✓ Live Decoys and Lateral Movement Tokens deployed.")
        return

    # --- PASSIVE DECEPTION: REGENERATE TOKENS ---
    elif action_type == "regenerate_tokens":
        risk = 0.0
        stage = 0
        with profile_lock:
            if attacker_ip in attacker_profiles:
                risk, stage = attacker_profiles[attacker_ip].get("risk_score", 0.0), attacker_profiles[attacker_ip].get("current_stage", 0)

        # Map risk to token level
        level = "critical" if (stage >= 4 or risk >= 150.0) else \
                "high" if (stage >= 3 or risk >= 100.0) else \
                "medium" if (stage >= 2 or risk >= 50.0) else "low"

        log.info(f"      [DECEPTION] Mutating Honeytokens → Level: {level.upper()} | Attacker: {attacker_ip}")
        clean_flag = "--clean-first" if level == "critical" else ""
        cmd = f"python3 {GENERATOR_SCRIPT} --base-dir {HONEYFS} --deception-level {level} --mutate --attacker-ip {attacker_ip} --silent {clean_flag}".strip()
        
        out, err = _run_ssh_cmd(ssh, cmd)
        if err and not MOCK_SSH:
            log.error(f"      [DECEPTION] Script failed: {err}")
        else:
            log.info(f"      [DECEPTION] ✓ Honeytokens deployed safely.")
        return

    # --- NETWORK DEFENSE: SDN ACTIONS ---
    elif action_type == "throttle":
        log.warning(f"      [SDN] Throttling {attacker_ip}")
        _run_ssh_cmd(ssh, "sudo tc qdisc replace dev enp0s3 root netem delay 500ms rate 50kbit")
        return

    elif action_type == "containment":
        log.warning(f"      [SDN] Containing {attacker_ip} → tarpit")
        _run_ssh_cmd(ssh, f"sudo iptables -t nat -A PREROUTING -s {attacker_ip} -p tcp --dport 2200 -j REDIRECT --to-port 2222")
        _run_ssh_cmd(ssh, f"nohup sudo python3 {SDN_SCRIPT} > /dev/null 2>&1 &")
        return
# def execute_defense(ssh, action_type: str, attacker_ip: str):
#     if action_type == "inject_canary":
#         log.info(f"      [APP] Injecting canary tokens for {attacker_ip}")
#         _run_ssh_cmd(ssh, f"mkdir -p {HONEYFS}/home/cowrie/.aws")
#         _run_ssh_cmd(ssh, f"printf '[default]\\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\\naws_secret_access_key=CANARY\\n' > {HONEYFS}/home/cowrie/.aws/credentials")

#     elif action_type == "deploy_decoy":
#         log.info(f"      [APP] Deploying Dionaea decoy for {attacker_ip}")
#         _run_ssh_cmd(ssh, "sudo docker start dionaea")
#         _run_ssh_cmd(ssh, f"printf 'DB_USER=admin\\nDB_PASS=P@ssw0rd123\\n' > {HONEYFS}/home/cowrie/db_creds.txt")

#     elif action_type == "throttle":
#         log.warning(f"      [SDN] Throttling {attacker_ip}")
#         _run_ssh_cmd(ssh, "sudo tc qdisc replace dev enp0s3 root netem delay 500ms rate 50kbit")

#     elif action_type == "containment":
#         log.warning(f"      [SDN] Containing {attacker_ip} → tarpit")
#         _run_ssh_cmd(ssh, f"sudo iptables -t nat -A PREROUTING -s {attacker_ip} -p tcp --dport 2200 -j REDIRECT --to-port 2222")
#         _run_ssh_cmd(ssh, f"nohup sudo python3 {SDN_SCRIPT} > /dev/null 2>&1 &")

# ============================================================
# 7. CORE LOGIC & DQN
# ============================================================
def check_sequence_bonus(history: list) -> float:
    if len(history) < 3: return 1.0
    recent = tuple(h.split("_")[0] for h in history[-3:])
    return TTP_SEQUENCES.get(recent, 1.0)

def _load_dqn_policy() -> bool:
    global dqn_model, dqn_ttp_vocab, dqn_ttp_to_idx, dqn_enabled
    if not USE_DQN_POLICY or not DQN_AVAILABLE or not DQN_MODULE_AVAILABLE:
        dqn_enabled = False
        return False

    model_path = Path(DQN_MODEL_PATH)
    if not model_path.exists() and model_path.with_suffix(".zip").exists():
        model_path = model_path.with_suffix(".zip")
    elif not model_path.exists():
        dqn_enabled = False
        return False
    
    vocab_path = Path(DQN_VOCAB_PATH)
    if not vocab_path.exists(): vocab_path = Path(DQN_MODEL_PATH).with_suffix(".ttp_vocab.json")

    try:
        dqn_model = DQN.load(str(model_path))
        vocab = load_ttp_vocab(str(vocab_path))
        dqn_ttp_vocab = [str(v) for v in vocab]
        dqn_ttp_to_idx = {t: i for i, t in enumerate(dqn_ttp_vocab)}
        dqn_enabled = True
        log.info(f"[RL] ✅ DQN policy loaded: {model_path.name}")
        return True
    except Exception as e:
        dqn_enabled = False
        return False

def _build_dqn_obs(profile: dict, threat: str):
    mapped = resolve_ttp_for_vocab(threat, dqn_ttp_vocab)
    state = SessionState(
        risk_score=float(profile["risk_score"]),
        engagement_minutes=int(profile.get("engagement_minutes", 0)),
        deception_exposure=float(profile.get("deception_exposure", 0.0)),
        last_action=int(profile.get("rl_last_action", 0)),
    )
    obs = build_obs_from_ttp(mapped, state, dqn_ttp_vocab, max_minutes=max(1, DQN_MAX_MINUTES))
    return obs, mapped

def _action_layer(action_name: str) -> str:
    if action_name in ("regenerate_tokens", "deploy_decoy"): return "APP"
    if action_name in ("throttle", "containment"): return "NETWORK"
    return "NONE"

def _determine_action_rule(profile: dict, threat: str, now: float):
    risk, stage = profile.get("risk_score", 0.0), profile.get("current_stage", 0)
    
    if risk > STAGE_THRESHOLDS[4] and stage < 4:
        profile["current_stage"], profile["last_action_time"] = 4, now
        return "containment", "NETWORK"
        
    if risk > STAGE_THRESHOLDS[3] and stage < 3:
        profile["current_stage"], profile["last_action_time"] = 3, now
        return "throttle", "NETWORK"
        
    # Stage 2: Spin up active decoy services (Lateral Movement Bait)
    if risk > STAGE_THRESHOLDS[2] and stage < 2:
        profile["current_stage"], profile["last_action_time"] = 2, now
        return "deploy_decoy_service", "APP"
        
    # Stage 1: Drop Honeytokens and Canaries
    if risk > STAGE_THRESHOLDS[1] and stage < 1:
        profile["current_stage"], profile["last_action_time"] = 1, now
        return "regenerate_tokens", "APP"
        
    return None, "NONE"

def _determine_action(profile: dict, threat: str, confidence: float, now: float):
    cooldown = DQN_DECISION_COOLDOWN if dqn_enabled else COOLDOWN_WINDOW
    if (now - profile.get("last_action_time", 0)) <= cooldown:
        return None, "NONE", "COOLDOWN"

    if dqn_enabled and dqn_model is not None:
        try:
            obs, mapped_ttp = _build_dqn_obs(profile, threat)
            with dqn_lock: action_id, _ = dqn_model.predict(obs, deterministic=True)
            action_id = int(action_id)
            action_name = RL_ACTIONS.get(action_id, "monitor")

            profile["engagement_minutes"] = min(profile.get("engagement_minutes", 0) + 1, DQN_MAX_MINUTES)
            profile["deception_exposure"] = max(0.0, profile.get("deception_exposure", 0.0) - 0.04) if action_name == "monitor" else min(1.0, profile.get("deception_exposure", 0.0) + 0.08)
            profile["rl_last_action"] = action_id

            if action_name == "monitor": return None, "NONE", "DQN"
            profile["current_stage"] = max(profile.get("current_stage", 0), min(action_id, 4))
            profile["last_action_time"] = now
            return action_name, _action_layer(action_name), "DQN"
        except Exception: pass

    action_needed, layer = _determine_action_rule(profile, threat, now)
    if action_needed: return action_needed, layer, "RULE"
    return None, "NONE", "RULE"

# ============================================================
# 8. MAIN PIPELINE
# ============================================================
def process_log_entry(log_line: str):
    try:
        data = json.loads(log_line)
        
        # --- Normalization (Fix Applied Here) ---
        norm_data   = normalizer.normalize(data)
        log_text    = norm_data['command']
        attacker_ip = norm_data['src_ip']
        session_id  = norm_data['session_id']
        source      = norm_data['source']

        if not log_text or attacker_ip == 'unknown': return
        if not is_valid_ip(attacker_ip): return

        with ip_cache_lock:
            if attacker_ip not in ip_cache:
                ip_cache[attacker_ip] = "pending"
                threading.Thread(target=async_enrich_ip, args=(attacker_ip,), daemon=True, name=f"Intel-{attacker_ip}").start()

        try:
            resp = requests.post(ML_API, json={"log_text": log_text, "src_ip": attacker_ip}, timeout=ML_API_TIMEOUT).json()
            if "error" in resp: return
            threat, confidence = resp["threat_type"], float(resp["confidence"])
        except Exception: return

        action_needed, layer, decision_mode = None, "NONE", "RULE"

        with profile_lock:
            profile = attacker_profiles[attacker_ip]
            now = time.time()

            idle_hours = (now - profile["last_seen"]) / 3600.0
            profile["risk_score"] = max(0.0, profile["risk_score"] - idle_hours * 10.0)
            profile["last_seen"] = now

            t_code = threat.split("_")[0]
            profile["history"].append(threat)
            if len(profile["history"]) > HISTORY_CAP: profile["history"] = profile["history"][-HISTORY_CAP:]

            seq_bonus = check_sequence_bonus(profile["history"])
            delta = (confidence / 100.0) * 10.0 * TTP_WEIGHTS.get(t_code, 1.0) * seq_bonus
            profile["risk_score"] = min(profile["risk_score"] + delta, RISK_SCORE_CAP)
            current_risk = profile["risk_score"]

            action_needed, layer, decision_mode = _determine_action(profile, threat, confidence, now)

        log.info(f"[+] {attacker_ip} | {threat} ({confidence:.1f}%) | Risk: {current_risk:.1f} | Mode: {decision_mode}")

        if action_needed:
            log.warning(f"    [!!!] QUEUING: {action_needed.upper()} for {attacker_ip}")
            try: action_queue.put_nowait((action_needed, attacker_ip))
            except queue.Full: log.error("Action queue full — dropping defense task.")

        event_data = {
        "@timestamp":       datetime.now(timezone.utc).isoformat(),
        "event.module":     "adaptive_defense",
        "data_source":      "adaptive_engine",
        "type":             "adaptive_engine",
        
        # Threat Information
        "attacker_ip":      attacker_ip,
        "threat_trigger":   threat,
        "confidence":       confidence,
        "session_id":       session_id,
        "honeypot_type":    source,
        
        # Response Information
        "action":           action_needed or "MONITOR",
        "layer":            layer,
        "decision_mode":    decision_mode,
        
        # Risk & Stage Information
        "risk":             current_risk,
        "stage":            attacker_profiles[attacker_ip].get("current_stage", 0),
        "seq_bonus":        seq_bonus,
        }
        try:
            response = requests.post(
                LOGSTASH_URL,
                json=event_data,
                headers={"Content-Type": "application/json"},
                timeout=LOGSTASH_TIME_OUT
            )
            if response.status_code == 200:
                log.debug(f"Event sent to Logstash")
            else:
                log.warning(f"Logstash {response.status_code}, ES fallback")
                try:
                    es_queue.put_nowait(event_data)
                except queue.Full: pass
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            try:
                es_queue.put_nowait(event_data)
            except queue.Full: pass
        except Exception as e:
            log.error(f"Event sending error: {e}")

    except json.JSONDecodeError: pass
    except Exception as e: log.error(f"Processing error: {e}", exc_info=True)


# ============================================================
# 9. TCP SERVER
# ============================================================
def handle_client(client_socket: socket.socket, client_ip: str):
    log.info(f"[>] Honeypot connected: {client_ip}")
    client_socket.settimeout(10)
    buffer = ""
    try:
        while not _shutdown_event.is_set():
            try:
                chunk = client_socket.recv(4096).decode('utf-8', errors='replace')
                if not chunk: break
                buffer += chunk
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if line.strip(): process_log_entry(line)
            except socket.timeout: continue
            except UnicodeDecodeError:
                buffer = ""
                continue
    except Exception as e: log.debug(f"Client handler error ({client_ip}): {e}")
    finally:
        client_socket.close()
        log.info(f"[<] Honeypot disconnected: {client_ip}")

def start_server():
    load_profiles()
    _load_dqn_policy()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_IP, LISTEN_PORT))
    server.listen(50)
    server.settimeout(1)

    print("\n" + "=" * 60)
    print("  ADAPTIVE DECEPTION ENGINE — SOAR v4 ULTIMATE")
    print("=" * 60)
    print(f"  Listening  : {LISTEN_IP}:{LISTEN_PORT}")
    print(f"  ML API     : {ML_API}  (timeout={ML_API_TIMEOUT}s)")
    print(f"  Honeypot   : {HONEYPOT_IP}:{SSH_PORT}")
    print(f"  SSH Workers: {SSH_WORKERS}")
    print(f"  Risk Cap   : {RISK_SCORE_CAP}")
    print(f"  Mock SSH   : {'ON' if MOCK_SSH else 'OFF'}")
    
    if dqn_enabled:
        print(f"  Decision   : HYBRID (DQN + RULE fallback)")
        print(f"  DQN Model  : {DQN_MODEL_PATH}")
    else:
        print(f"  Decision   : RULE (DQN disabled)")
        print(f"  [Tip] Run 'python create_dqn_policy.py' to enable DQN mode")
    
    print("=" * 60 + "\n")

    while not _shutdown_event.is_set():
        try:
            client, addr = server.accept()
            threading.Thread(target=handle_client, args=(client, addr[0]), daemon=True, name=f"Client-{addr[0]}").start()
        except socket.timeout: continue
        except Exception as e:
            if not _shutdown_event.is_set(): log.error(f"Server accept error: {e}")

    server.close()

if __name__ == "__main__":
    start_server()