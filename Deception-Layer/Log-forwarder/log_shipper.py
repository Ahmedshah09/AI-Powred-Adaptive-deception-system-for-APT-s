import time
import socket
import os
import threading
import logging
import json

# ==============================
# CONFIGURATION
# ==============================

# Paths to your logs (Verify these on your VM!)
COWRIE_LOG  = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
DIONAEA_LOG = "/home/cowrie/dionaea-data/var/log/dionaea/attack_logs.json"

# Windows Brain IP
TARGET_IP   = "100.79.41.116"
TARGET_PORT = 9000

# ==============================
# LOGGING SETUP
# ==============================
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("multi_shipper")

# ==============================
# SHARED CONNECTION OBJECT
# ==============================
# A lock ensures two threads don't write to the socket at the exact same instant
socket_lock = threading.Lock()
sock = None

def connect_to_brain():
    """Establishes (or re-establishes) the TCP connection."""
    global sock
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((TARGET_IP, TARGET_PORT))
            s.settimeout(None) # Remove timeout for blocking send
            log.info(f"Connected to Brain ({TARGET_IP}:{TARGET_PORT})")
            return s
        except Exception as e:
            log.error(f"Connection failed: {e}. Retrying in 5s...")
            time.sleep(5)

# ==============================
# ROTATION-AWARE FOLLOWER
# ==============================
def follow(filepath, source_tag):
    """
    Generator that tails a file, handles rotation, and tags the log.
    source_tag: 'cowrie' or 'dionaea' (added to JSON if missing)
    """
    while True:
        if not os.path.exists(filepath):
            log.warning(f"Waiting for {source_tag} log: {filepath}")
            time.sleep(5)
            continue

        try:
            with open(filepath, "r") as f:
                # Get initial inode
                try:
                    current_ino = os.fstat(f.fileno()).st_ino
                except OSError:
                    continue

                f.seek(0, 2) # Start at end
                log.info(f"Tailing {source_tag} logs...")

                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        # Rotation Check
                        try:
                            if os.stat(filepath).st_ino != current_ino:
                                log.info(f"{source_tag} log rotated. Reopening...")
                                break
                        except FileNotFoundError:
                            continue
                        continue

                    # ENRICHMENT: Add "type" tag if it's not strictly JSON
                    # (Dionaea logs are JSON, but we ensure consistency)
                    yield line

        except Exception as e:
            log.error(f"Error reading {source_tag}: {e}")
            time.sleep(2)

# ==============================
# WORKER THREAD
# ==============================
def worker(filepath, source_type):
    global sock
    
    for line in follow(filepath, source_type):
        if not line.strip(): continue

        # 1. OPTIONAL: Normalize the JSON here if needed
        # (e.g., if Dionaea format differs from Cowrie, unify them)
        try:
            # Quick check if valid JSON
            # data = json.loads(line)
            # data['source'] = source_type
            # line = json.dumps(data) + "\n"
            pass 
        except:
            pass 

        # 2. Send over Socket (Thread-Safe)
        with socket_lock:
            try:
                if sock:
                    sock.sendall(line.encode('utf-8'))
                else:
                    # If socket is dead, wait for main thread to reconnect
                    time.sleep(1)
            except (socket.error, BrokenPipeError):
                log.warning("Socket disconnected during send.")
                sock = None # Signal main loop to reconnect

# ==============================
# MAIN LOOP
# ==============================
def main():
    global sock
    
    # 1. Start threads for each log source
    t1 = threading.Thread(target=worker, args=(COWRIE_LOG, "cowrie"), daemon=True)
    t2 = threading.Thread(target=worker, args=(DIONAEA_LOG, "dionaea"), daemon=True)
    
    t1.start()
    t2.start()

    # 2. Main loop manages the connection
    while True:
        if sock is None:
            sock = connect_to_brain()
        
        # Keep main thread alive to let daemon threads work
        time.sleep(1)

if __name__ == "__main__":
    main()
