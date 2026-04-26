# adaptive_engine.py
# ============================================================
# ADAPTIVE DECEPTION ENGINE (SOAR) — PRODUCTION v3
# ============================================================
# Features:
#   - Hybrid Decision Mode (DQN + RULE fallback)
#   - Seamless fallback if DQN unavailable
#   - Attacker profiling with persistence
#   - Thread-safe action queuing
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
        1: "inject_canary",
        2: "deploy_decoy",
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

LISTEN_IP   = '0.0.0.0'
LISTEN_PORT = 9000

ML_API         = "http://localhost:5000/analyze_log"
ML_API_TIMEOUT = 5

ES_HOST        = "http://100.80.22.20:9200"
ABUSE_IPDB_KEY = "YOUR_API_KEY_HERE"

HONEYPOT_IP   = "100.113.245.10"
HONEYPOT_USER = "cowrie"
SSH_PORT      = 2200
SSH_KEY       = r"C:\Users\PMLS\.ssh\id_rsa"
HONEYFS       = "/home/cowrie/cowrie/honeyfs"
SDN_SCRIPT    = "/home/cowrie/sdn_enforcer.py"

COOLDOWN_WINDOW = 60
SSH_TIMEOUT     = 5
SSH_WORKERS     = 3

RISK_SCORE_CAP  = 500.0
HISTORY_CAP     = 100

PROFILES_PATH   = "attacker_profiles.json"

# DQN policy integration
USE_DQN_POLICY = os.getenv("USE_DQN_POLICY", "1") == "1"
DQN_MODEL_PATH = os.getenv("DQN_MODEL_PATH", "dqn_adaptive_deception_quick")
DQN_VOCAB_PATH = os.getenv(
    "DQN_VOCAB_PATH",
    f"{DQN_MODEL_PATH}.ttp_vocab.json"
)
DQN_MAX_MINUTES = int(os.getenv("DQN_MAX_MINUTES", "30"))
DQN_DECISION_COOLDOWN = int(os.getenv("DQN_DECISION_COOLDOWN", str(COOLDOWN_WINDOW)))

# Mock SSH for testing (set MOCK_SSH=1 to simulate actions)
MOCK_SSH = os.getenv("MOCK_SSH", "1") == "1"

# ── Threat weights ───────────────────────────────────────────
TTP_WEIGHTS = {
    "T1046": 1.0,  "T1083": 1.1,  "T1033": 1.1,
    "T1003": 1.8,  "T1548": 1.6,  "T1021": 1.7,
    "T1105": 1.5,  "T1048": 2.0,  "T1485": 2.0,
    "T1059": 1.3,  "T1070": 1.4,  "T1110": 1.2,
    "T1136": 1.5,  "T1098": 1.6,  "T1496": 1.4,
}

# ── Kill-chain sequence multipliers ─────────────────────────
TTP_SEQUENCES = {
    ("T1087", "T1069", "T1548"): 2.5,
    ("T1046", "T1021", "T1105"): 2.0,
    ("T1003", "T1552", "T1041"): 3.0,
    ("T1059", "T1105", "T1053"): 2.2,
    ("T1110", "T1021", "T1003"): 2.8,
}

# ── Escalation thresholds ────────────────────────────────────
STAGE_THRESHOLDS = {
    1: 20.0,
    2: 50.0,
    3: 100.0,
    4: 150.0,
}

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
# 4. PROFILE PERSISTENCE
# ============================================================

def save_profiles():
    try:
        with profile_lock:
            data = {ip: dict(p) for ip, p in attacker_profiles.items()}
        with open(PROFILES_PATH, "w") as fh:
            json.dump(data, fh, indent=2)
        log.info(f"[*] Profiles saved → {PROFILES_PATH} ({len(data)} entries)")
    except Exception as e:
        log.error(f"Profile save failed: {e}")


def load_profiles():
    path = Path(PROFILES_PATH)
    if not path.exists():
        return
    try:
        with open(path) as fh:
            data = json.load(fh)
        with profile_lock:
            for ip, p in data.items():
                attacker_profiles[ip].update(p)
        log.info(f"[*] Profiles restored ← {PROFILES_PATH} ({len(data)} entries)")
    except Exception as e:
        log.warning(f"Profile restore failed (starting fresh): {e}")


# ============================================================
# 5. IP VALIDATION
# ============================================================

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# ============================================================
# 6. BACKGROUND WORKERS
# ============================================================

def es_writer_worker():
    if not ES_AVAILABLE:
        while True:
            item = es_queue.get()
            if item is None:
                break
        return

    es = Elasticsearch(ES_HOST, verify_certs=False)
    while True:
        try:
            doc = es_queue.get()
            if doc is None:
                break
            es.index(index="deception-actions", document=doc)
            es_queue.task_done()
        except Exception as e:
            log.error(f"ES write failed: {e}")


def ssh_action_worker():
    while True:
        try:
            task = action_queue.get()
            if task is None:
                break

            action_type, attacker_ip = task
            
            if MOCK_SSH:
                log.info(f"      [MOCK] Would execute: {action_type} for {attacker_ip}")
                action_queue.task_done()
                continue
                
            if not PARAMIKO_AVAILABLE:
                log.error("SSH action failed: paramiko not installed")
                action_queue.task_done()
                continue
                
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    HONEYPOT_IP,
                    port        = SSH_PORT,
                    username    = HONEYPOT_USER,
                    key_filename= SSH_KEY,
                    timeout     = SSH_TIMEOUT,
                )
                execute_defense(ssh, action_type, attacker_ip)
                ssh.close()
            except Exception as e:
                log.error(f"SSH execution failed for {attacker_ip}: {e}")
            finally:
                action_queue.task_done()

        except Exception as e:
            log.error(f"SSH worker loop error: {e}")


def async_enrich_ip(ip: str):
    score = 0
    try:
        if "YOUR_API_KEY_HERE" not in ABUSE_IPDB_KEY:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSE_IPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 30},
                timeout=5,
            )
            score = int(r.json()["data"]["abuseConfidenceScore"])
            with profile_lock:
                attacker_profiles[ip]["risk_score"] += score * 0.1
            log.info(f"[*] Threat Intel: {ip} AbuseScore={score}/100")
    except Exception as e:
        if "YOUR_API_KEY_HERE" not in ABUSE_IPDB_KEY:
            log.debug(f"Threat intel skipped for {ip}: No API key")
    finally:
        with ip_cache_lock:
            ip_cache[ip] = score


# ============================================================
# 7. GRACEFUL SHUTDOWN
# ============================================================

def shutdown_handler(sig, frame):
    log.info("\n[!] Shutting down — saving profiles and flushing queues …")
    _shutdown_event.set()
    save_profiles()
    es_queue.put(None)
    for _ in range(SSH_WORKERS):
        action_queue.put(None)
    time.sleep(2)
    log.info("[!] Shutdown complete.")
    sys.exit(0)


signal.signal(signal.SIGINT,  shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)


# ============================================================
# 8. WORKER STARTUP
# ============================================================

threading.Thread(target=es_writer_worker, daemon=True, name="ES-Writer").start()

for i in range(SSH_WORKERS):
    threading.Thread(target=ssh_action_worker, daemon=True, name=f"SSH-Worker-{i}").start()


# ============================================================
# 9. DEFENSE ACTIONS
# ============================================================

def _run_ssh_cmd(ssh, cmd: str) -> tuple:
    if MOCK_SSH:
        log.debug(f"[MOCK] SSH cmd: {cmd[:60]}...")
        return "", ""
    try:
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=10)
        stdout.channel.recv_exit_status()
        out = stdout.read().decode(errors='replace').strip()
        err = stderr.read().decode(errors='replace').strip()
        return out, err
    except Exception as e:
        log.error(f"SSH cmd failed [{cmd[:60]}]: {e}")
        return "", str(e)


def execute_defense(ssh, action_type: str, attacker_ip: str):
    if action_type == "inject_canary":
        log.info(f"      [APP] Injecting canary tokens for {attacker_ip}")
        _run_ssh_cmd(ssh, f"mkdir -p {HONEYFS}/home/cowrie/.aws")
        out, err = _run_ssh_cmd(
            ssh,
            f"printf '[default]\\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\\n"
            f"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/CANARY\\n' "
            f"> {HONEYFS}/home/cowrie/.aws/credentials"
        )
        if not err or MOCK_SSH:
            log.info(f"      [APP] Canary deployed ✓")

    elif action_type == "deploy_decoy":
        log.info(f"      [APP] Deploying Dionaea decoy for {attacker_ip}")
        out, err = _run_ssh_cmd(
            ssh, "sudo docker start dionaea"
        )
        _run_ssh_cmd(
            ssh,
            f"printf 'DB_USER=admin\\nDB_PASS=P@ssw0rd123\\n' "
            f"> {HONEYFS}/home/cowrie/db_creds.txt"
        )
        log.info(f"      [APP] Decoy deployed ✓")

    elif action_type == "throttle":
        log.warning(f"      [SDN] Throttling {attacker_ip}")
        out, err = _run_ssh_cmd(
            ssh,
            "sudo tc qdisc replace dev enp0s3 root netem delay 500ms rate 50kbit"
        )
        log.info(f"      [SDN] tc result: {out or err or 'OK'}")

    elif action_type == "containment":
        log.warning(f"      [SDN] Containing {attacker_ip} → tarpit")
        _run_ssh_cmd(
            ssh,
            f"sudo iptables -t nat -A PREROUTING "
            f"-s {attacker_ip} -p tcp --dport 2200 "
            f"-j REDIRECT --to-port 2222"
        )
        _run_ssh_cmd(
            ssh,
            f"nohup sudo python3 {SDN_SCRIPT} > /dev/null 2>&1 &"
        )
        log.warning(f"      [SDN] Containment rule applied ✓")

    else:
        log.warning(f"Unknown action type: {action_type}")


# ============================================================
# 10. CORE LOGIC
# ============================================================

def check_sequence_bonus(history: list) -> float:
    if len(history) < 3:
        return 1.0
    recent = tuple(h.split("_")[0] for h in history[-3:])
    return TTP_SEQUENCES.get(recent, 1.0)


def _load_dqn_policy() -> bool:
    global dqn_model, dqn_ttp_vocab, dqn_ttp_to_idx, dqn_enabled

    if not USE_DQN_POLICY:
        log.info("[RL] DQN disabled via USE_DQN_POLICY=0")
        dqn_enabled = False
        return False

    if not DQN_AVAILABLE:
        log.warning("[RL] stable-baselines3 not installed - using RULE mode")
        dqn_enabled = False
        return False

    if not DQN_MODULE_AVAILABLE:
        log.warning("[RL] dqn_adaptive_deception import failed - using RULE mode")
        dqn_enabled = False
        return False

    model_path = Path(DQN_MODEL_PATH)
    if not model_path.exists():
        zip_candidate = model_path.with_suffix(".zip")
        if zip_candidate.exists():
            model_path = zip_candidate
        else:
            log.warning(f"[RL] DQN model not found: {DQN_MODEL_PATH}")
            log.info("[RL] Run 'python create_dqn_policy.py' to generate a policy")
            dqn_enabled = False
            return False
    
    vocab_path = Path(DQN_VOCAB_PATH)
    if not vocab_path.exists():
        default_vocab = Path(DQN_MODEL_PATH).with_suffix(".ttp_vocab.json")
        if default_vocab.exists():
            vocab_path = default_vocab
        else:
            log.warning(f"[RL] DQN vocab not found: {DQN_VOCAB_PATH}")
            dqn_enabled = False
            return False

    try:
        dqn_model = DQN.load(str(model_path))
        vocab = load_ttp_vocab(str(vocab_path))
        dqn_ttp_vocab = [str(v) for v in vocab]
        dqn_ttp_to_idx = {t: i for i, t in enumerate(dqn_ttp_vocab)}
        dqn_enabled = True
        log.info(f"[RL] ✅ DQN policy loaded: {model_path.name}")
        log.info(f"[RL]    Vocab size: {len(dqn_ttp_vocab)} techniques")
        return True
    except Exception as e:
        log.warning(f"[RL] Failed to load DQN policy: {e}")
        log.info("[RL] Falling back to RULE mode")
        dqn_enabled = False
        return False


def _build_dqn_obs(profile: dict, threat: str):
    if resolve_ttp_for_vocab is None or build_obs_from_ttp is None or SessionState is None:
        raise RuntimeError("DQN helper functions unavailable.")

    mapped = resolve_ttp_for_vocab(threat, dqn_ttp_vocab)
    state = SessionState(
        risk_score=float(profile["risk_score"]),
        engagement_minutes=int(profile.get("engagement_minutes", 0)),
        deception_exposure=float(profile.get("deception_exposure", 0.0)),
        last_action=int(profile.get("rl_last_action", 0)),
    )
    obs = build_obs_from_ttp(
        mapped, state, dqn_ttp_vocab, max_minutes=max(1, DQN_MAX_MINUTES)
    )
    return obs, mapped


def _action_layer(action_name: str) -> str:
    if action_name in ("inject_canary", "deploy_decoy"):
        return "APP"
    if action_name in ("throttle", "containment"):
        return "NETWORK"
    return "NONE"


def _determine_action_rule(profile: dict, threat: str, now: float):
    risk = profile.get("risk_score", 0.0)
    stage = profile.get("current_stage", 0)

    if risk > STAGE_THRESHOLDS[4] and stage < 4:
        profile["current_stage"] = 4
        profile["last_action_time"] = now
        return "containment", "NETWORK"

    if risk > STAGE_THRESHOLDS[3] and stage < 3:
        profile["current_stage"] = 3
        profile["last_action_time"] = now
        return "throttle", "NETWORK"

    if risk > STAGE_THRESHOLDS[2] and stage < 2:
        profile["current_stage"] = 2
        profile["last_action_time"] = now
        return "deploy_decoy", "APP"

    if risk > STAGE_THRESHOLDS[1] and stage < 1:
        profile["current_stage"] = 1
        profile["last_action_time"] = now
        if any(t in threat for t in ("T1003", "T1087", "T1552")):
            return "inject_canary", "APP"
        if any(t in threat for t in ("T1046", "T1083", "T1018")):
            return "deploy_decoy", "APP"
        return "inject_canary", "APP"

    return None, "NONE"


def _determine_action(profile: dict, threat: str, confidence: float, now: float):
    cooldown = DQN_DECISION_COOLDOWN if dqn_enabled else COOLDOWN_WINDOW
    
    if (now - profile.get("last_action_time", 0)) <= cooldown:
        return None, "NONE", "COOLDOWN"

    if dqn_enabled and dqn_model is not None:
        try:
            obs, mapped_ttp = _build_dqn_obs(profile, threat)
            with dqn_lock:
                action_id, _ = dqn_model.predict(obs, deterministic=True)
            action_id = int(action_id)
            action_name = RL_ACTIONS.get(action_id, "monitor")

            profile["engagement_minutes"] = min(
                profile.get("engagement_minutes", 0) + 1,
                DQN_MAX_MINUTES
            )
            if action_name == "monitor":
                profile["deception_exposure"] = max(
                    0.0, profile.get("deception_exposure", 0.0) - 0.04
                )
            else:
                profile["deception_exposure"] = min(
                    1.0, profile.get("deception_exposure", 0.0) + 0.08
                )
            profile["rl_last_action"] = action_id

            if action_name == "monitor":
                log.debug(f"[RL] DQN recommended: MONITOR (threat: {mapped_ttp})")
                return None, "NONE", "DQN"
            
            profile["current_stage"] = max(profile.get("current_stage", 0), min(action_id, 4))
            profile["last_action_time"] = now
            log.info(f"[RL] DQN action: {action_name.upper()} for {threat}")
            return action_name, _action_layer(action_name), "DQN"
            
        except Exception as e:
            log.warning(f"[RL] DQN inference failed, falling back to RULE: {e}")

    action_needed, layer = _determine_action_rule(profile, threat, now)
    if action_needed:
        return action_needed, layer, "RULE"
    return None, "NONE", "RULE"


def process_log_entry(log_line: str):
    try:
        data        = json.loads(log_line)
        log_text    = data.get('input') or data.get('message', '')
        attacker_ip = data.get('src_ip', 'unknown')

        if not log_text or attacker_ip == 'unknown':
            return

        if not is_valid_ip(attacker_ip):
            log.warning(f"Invalid src_ip rejected: {attacker_ip!r}")
            return

        with ip_cache_lock:
            if attacker_ip not in ip_cache:
                ip_cache[attacker_ip] = "pending"
                threading.Thread(
                    target=async_enrich_ip,
                    args=(attacker_ip,),
                    daemon=True,
                    name=f"Intel-{attacker_ip}",
                ).start()

        try:
            resp = requests.post(
                ML_API,
                json    = {"log_text": log_text, "src_ip": attacker_ip},
                timeout = ML_API_TIMEOUT,
            ).json()
            if "error" in resp:
                return
            threat     = resp["threat_type"]
            confidence = float(resp["confidence"])
        except requests.Timeout:
            log.debug(f"ML API timeout for: {log_text[:60]}")
            return
        except Exception as e:
            log.debug(f"ML API error: {e}")
            return

        action_needed  = None
        layer          = "NONE"
        decision_mode  = "RULE"

        with profile_lock:
            profile = attacker_profiles[attacker_ip]
            now     = time.time()

            idle_hours           = (now - profile["last_seen"]) / 3600.0
            profile["risk_score"] = max(
                0.0, profile["risk_score"] - idle_hours * 10.0
            )
            profile["last_seen"]  = now

            t_code     = threat.split("_")[0]
            weight     = TTP_WEIGHTS.get(t_code, 1.0)
            profile["history"].append(threat)
            if len(profile["history"]) > HISTORY_CAP:
                profile["history"] = profile["history"][-HISTORY_CAP:]

            seq_bonus             = check_sequence_bonus(profile["history"])
            delta                 = (confidence / 100.0) * 10.0 * weight * seq_bonus
            profile["risk_score"] = min(
                profile["risk_score"] + delta,
                RISK_SCORE_CAP
            )
            current_risk = profile["risk_score"]

            action_needed, layer, decision_mode = _determine_action(
                profile, threat, confidence, now
            )

        log.info(
            f"[+] {attacker_ip} | {threat} ({confidence:.1f}%) "
            f"| Risk: {current_risk:.1f} | Decision: {decision_mode}"
        )

        if action_needed:
            log.warning(
                f"    [!!!] QUEUING: {action_needed.upper()} for {attacker_ip}"
            )
            try:
                action_queue.put_nowait((action_needed, attacker_ip))
            except queue.Full:
                log.error("Action queue full — dropping defense task.")

        try:
            es_queue.put_nowait({
                "@timestamp":    datetime.now(timezone.utc).isoformat(),
                "event.module":  "adaptive_defense",
                "attacker_ip":   attacker_ip,
                "threat_trigger": threat,
                "confidence":    confidence,
                "action":        action_needed or "MONITOR",
                "layer":         layer,
                "decision_mode": decision_mode,
                "risk":          current_risk,
                "stage":         attacker_profiles[attacker_ip]["current_stage"],
            })
        except queue.Full:
            pass

    except json.JSONDecodeError:
        log.debug(f"Non-JSON line skipped: {log_line[:80]}")
    except Exception as e:
        log.error(f"Processing error: {e}", exc_info=True)


# ============================================================
# 11. TCP SERVER
# ============================================================

def handle_client(client_socket: socket.socket, client_ip: str):
    log.info(f"[>] Honeypot connected: {client_ip}")
    client_socket.settimeout(10)
    buffer = ""
    try:
        while not _shutdown_event.is_set():
            try:
                chunk = client_socket.recv(4096).decode('utf-8', errors='replace')
                if not chunk:
                    break
                buffer += chunk
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if line.strip():
                        process_log_entry(line)
            except socket.timeout:
                continue
            except UnicodeDecodeError:
                buffer = ""
                continue
    except Exception as e:
        log.debug(f"Client handler error ({client_ip}): {e}")
    finally:
        client_socket.close()
        log.info(f"[<] Honeypot disconnected: {client_ip}")


def start_server():
    load_profiles()
    dqn_loaded = _load_dqn_policy()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_IP, LISTEN_PORT))
    server.listen(50)
    server.settimeout(1)

    print("\n" + "=" * 60)
    print("  ADAPTIVE DECEPTION ENGINE — SOAR v3 PRODUCTION")
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
            threading.Thread(
                target=handle_client,
                args=(client, addr[0]),
                daemon=True,
                name=f"Client-{addr[0]}",
            ).start()
        except socket.timeout:
            continue
        except Exception as e:
            if not _shutdown_event.is_set():
                log.error(f"Server accept error: {e}")

    server.close()


# ============================================================
# 12. ENTRY POINT
# ============================================================

if __name__ == "__main__":
    start_server()