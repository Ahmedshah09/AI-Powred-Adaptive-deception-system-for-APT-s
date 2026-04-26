import argparse
import json
import pickle
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

PORT_SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 1433: "mssql",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 6379: "redis",
}


def service_name(port: Any) -> str:
    try:
        p = int(port)
    except Exception:
        return "unknown"
    return PORT_SERVICE_MAP.get(p, "unknown")


def canonicalize_command(cmd: str) -> str:
    if not isinstance(cmd, str):
        cmd = str(cmd)
    c = cmd.lower().strip()
    c = re.sub(r"https?://\S+|ftp://\S+|sftp://\S+", "<url>", c)
    c = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", c)
    c = re.sub(r"\b[a-f0-9]{32,64}\b", "<hash>", c)
    c = re.sub(r":\d{2,5}\b", ":<port>", c)
    c = re.sub(r"\b\d{2,5}\b", "<num>", c)
    c = re.sub(r"\s+", " ", c).strip()
    return c


def extract_soc_features(cmd: str) -> List[float]:
    if not isinstance(cmd, str):
        cmd = str(cmd)
    c = cmd.lower()

    has_ip = int(bool(re.search(r"\d{1,3}(?:\.\d{1,3}){3}", cmd)))
    has_url = int(any(p in c for p in ["http://", "https://", "ftp://", "sftp://"]))
    has_net_tool = int(any(t in c for t in [
        "wget", "curl", "nc ", "ncat", "scp ", "rsync",
        "tftp", "socat", "dig ", "nslookup",
    ]))
    has_port = int(bool(re.search(r":\d{2,5}(\s|$|\")", cmd)))

    has_elevation = int(any(t in c for t in ["sudo", "pkexec", "su ", "doas", "runas"]))
    has_suid = int("chmod +s" in c or "chmod 4" in c)

    has_cron = int(any(t in c for t in ["crontab", "/etc/cron", "/var/spool/cron"]))
    has_persistence = int(any(t in c for t in [
        ".bashrc", ".bash_profile", ".profile",
        "rc.local", "/etc/init.d", "systemctl enable",
    ]))
    has_tmp = int("/tmp" in c or "/var/tmp" in c or "/dev/shm" in c)

    has_log_tamper = int(any(t in c for t in [
        "history -c", "history -d", "/var/log",
        "journalctl", "shred", "wipe", "srm",
    ]))
    has_base64 = int("base64" in c or bool(re.search(r"[A-Za-z0-9+/]{40,}={0,2}", cmd)))
    has_hex = int(bool(re.search(r"\\x[0-9a-fA-F]{2}", cmd)))
    has_dev_null = int("/dev/null" in c)

    has_recon = int(any(t in c for t in [
        "nmap", "masscan", "arp", "netstat", "ss ",
        "lsof", "ps aux", "who ", "id ", "uname",
    ]))
    has_exfil = int(any(t in c for t in [
        "tar ", "zip ", "gzip", "7z ", "xz ",
        "bzip2", "dd if", "split ",
    ]))

    pipe_count = min(cmd.count("|") / 5.0, 1.0)
    arg_count = min(len(cmd.split()) / 25.0, 1.0)

    has_chaining = int(any(op in cmd for op in ["&&", " ; ", " | "]))
    has_payload_exec = int("chmod +x" in c or cmd.strip().startswith("./"))

    return [
        has_ip, has_url, has_net_tool, has_port,
        has_elevation, has_suid,
        has_cron, has_persistence, has_tmp,
        has_log_tamper, has_base64, has_hex, has_dev_null,
        has_recon, has_exfil,
        pipe_count, arg_count,
        has_chaining, has_payload_exec,
    ]


def find_latest_model_base(search_dir: Path) -> str:
    candidates = []
    for pkl_path in search_dir.glob("*_components.pkl"):
        base = pkl_path.name.replace("_components.pkl", "")
        keras_path = search_dir / f"{base}.keras"
        if keras_path.exists():
            candidates.append((pkl_path.stat().st_mtime, base))

    if not candidates:
        raise FileNotFoundError(
            "No matching model artifacts found. Expected '<base>.keras' and '<base>_components.pkl'."
        )

    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


class TTPPredictor:
    def __init__(self, model_base: str, model_dir: Path):
        self.model_base = model_base
        self.model_dir = model_dir

        comp_path = model_dir / f"{model_base}_components.pkl"
        model_path = model_dir / f"{model_base}.keras"

        if not comp_path.exists() or not model_path.exists():
            raise FileNotFoundError(
                f"Model files missing for base '{model_base}'. "
                f"Need: {model_path.name} and {comp_path.name}"
            )

        with open(comp_path, "rb") as fh:
            comp = pickle.load(fh)

        self.tokenizer = comp["tokenizer"]
        self.label_encoder = comp["label_encoder"]
        self.max_sequence_length = int(comp["max_sequence_length"])
        self.num_features = int(comp.get("num_features", 19))
        self.per_class_thresholds = comp.get("per_class_thresholds")

        self.model = load_model(model_path, compile=False)

    def _pad(self, texts: List[str]) -> np.ndarray:
        seqs = self.tokenizer.texts_to_sequences(texts)
        return pad_sequences(seqs, maxlen=self.max_sequence_length, padding="post")

    def predict_command(
        self,
        command: str,
        min_confidence: Optional[float] = None,
        top_k: int = 3,
    ) -> List[Dict[str, float]]:
        cmd = str(command).lower().strip()
        text = self._pad([cmd])

        feats = np.array([extract_soc_features(command)], dtype=np.float32)
        if feats.shape[1] > self.num_features:
            feats = feats[:, : self.num_features]
        elif feats.shape[1] < self.num_features:
            pad = np.zeros((1, self.num_features - feats.shape[1]), dtype=np.float32)
            feats = np.concatenate([feats, pad], axis=1)

        probs = self.model.predict([text, feats], verbose=0)[0]
        labels = list(self.label_encoder.classes_)

        ranked = sorted(zip(labels, probs), key=lambda x: float(x[1]), reverse=True)

        selected = []
        for idx, (label, score) in enumerate(ranked):
            label_index = labels.index(label)
            threshold = None
            if min_confidence is not None:
                threshold = float(min_confidence)
            elif self.per_class_thresholds is not None:
                threshold = float(self.per_class_thresholds[label_index])
            else:
                threshold = 0.5

            if float(score) >= threshold:
                selected.append({"ttp": label, "confidence": round(float(score), 6)})

            if len(selected) >= top_k:
                break

        if not selected and ranked:
            best_label, best_score = ranked[0]
            selected = [{"ttp": best_label, "confidence": round(float(best_score), 6)}]

        return selected


def parse_cowrie_logs(paths: Iterable[Path]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []

    for path in paths:
        if not path.exists():
            print(f"[WARN] Cowrie log not found: {path}")
            continue

        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line_num, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                eventid = obj.get("eventid", "")
                cmd = ""
                if eventid == "cowrie.command.input":
                    cmd = canonicalize_command(str(obj.get("input", "")).strip())
                elif eventid == "cowrie.session.file_download":
                    url = str(obj.get("url", "")).strip()
                    if url:
                        cmd = canonicalize_command(
                            f"file_download url_fetch {url} save payload"
                        )

                if not cmd:
                    continue

                events.append(
                    {
                        "sensor": "cowrie",
                        "eventid": eventid,
                        "timestamp": obj.get("timestamp", ""),
                        "src_ip": obj.get("src_ip", ""),
                        "dst_ip": obj.get("dst_ip", ""),
                        "src_port": obj.get("src_port", ""),
                        "dst_port": obj.get("dst_port", ""),
                        "command": cmd,
                        "source_file": str(path),
                        "line": line_num,
                    }
                )

    return events


def parse_dionaea_sqlite(path: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []

    if not path.exists():
        print(f"[WARN] Dionaea DB not found: {path}")
        return events

    try:
        conn = sqlite3.connect(str(path))
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r[0] for r in cur.fetchall()}

        if "downloads" in tables:
            cur.execute("SELECT url, md5hash, filelength FROM downloads")
            for idx, (url, md5, size) in enumerate(cur.fetchall(), start=1):
                if not url:
                    continue
                cmd = canonicalize_command(
                    f"file_download url_fetch {url} save {md5 or 'payload'}"
                )
                events.append(
                    {
                        "sensor": "dionaea",
                        "eventid": "downloads",
                        "timestamp": "",
                        "src_ip": "",
                        "dst_ip": "",
                        "src_port": "",
                        "dst_port": "",
                        "command": cmd,
                        "artifact": md5 or "",
                        "filelength": size,
                        "source_file": str(path),
                        "line": idx,
                    }
                )

        if "connections" in tables:
            cur.execute(
                "SELECT remote_host, remote_port, protocol, connection FROM connections "
                "WHERE remote_host IS NOT NULL"
            )
            for idx, row in enumerate(cur.fetchall(), start=1):
                host = row[0]
                port = row[1]
                proto = row[2] if len(row) > 2 else ""
                conn_id = row[3] if len(row) > 3 else ""
                svc = service_name(port)
                cmd = canonicalize_command(
                    f"connection_event protocol={proto or 'tcp'} "
                    f"service={svc} dport={port} remote={host}"
                )
                events.append(
                    {
                        "sensor": "dionaea",
                        "eventid": "connections",
                        "timestamp": "",
                        "src_ip": host or "",
                        "dst_ip": "",
                        "src_port": "",
                        "dst_port": port or "",
                        "command": cmd,
                        "protocol": proto or "",
                        "connection_id": conn_id,
                        "source_file": str(path),
                        "line": idx,
                    }
                )

        conn.close()
    except sqlite3.Error as exc:
        print(f"[WARN] Could not read Dionaea sqlite {path}: {exc}")

    return events


def parse_dionaea_json(path: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []

    if not path.exists():
        print(f"[WARN] Dionaea log not found: {path}")
        return events

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line_num, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            conn = obj.get("connection", {})
            src_ip = obj.get("src_ip", "")
            dst_ip = obj.get("dst_ip", "")
            src_port = obj.get("src_port", "")
            dst_port = obj.get("dst_port", "")
            protocol = conn.get("protocol", "") if isinstance(conn, dict) else ""

            cmd = ""
            if isinstance(obj.get("download"), dict):
                url = str(obj.get("download", {}).get("url", "")).strip()
                if url:
                    cmd = canonicalize_command(
                        f"file_download url_fetch {url} save payload"
                    )

            if not cmd and src_ip and dst_port:
                svc = service_name(dst_port)
                cmd = canonicalize_command(
                    f"connection_event protocol={protocol or 'tcp'} "
                    f"service={svc} dport={dst_port} remote={src_ip}"
                )

            if not cmd:
                continue

            events.append(
                {
                    "sensor": "dionaea",
                    "eventid": "connection" if "connection_event" in cmd else "download",
                    "timestamp": obj.get("timestamp", ""),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "command": cmd,
                    "source_file": str(path),
                    "line": line_num,
                }
            )

    return events


def parse_dionaea_logs(paths: Iterable[Path]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for path in paths:
        suffix = path.suffix.lower()
        if suffix in {".sqlite", ".db", ".sqlite3"}:
            events.extend(parse_dionaea_sqlite(path))
        else:
            events.extend(parse_dionaea_json(path))
    return events


def run_predictions(
    predictor: TTPPredictor,
    events: List[Dict[str, Any]],
    min_confidence: Optional[float],
    top_k: int,
) -> pd.DataFrame:
    rows = []

    for ev in events:
        preds = predictor.predict_command(
            ev["command"],
            min_confidence=min_confidence,
            top_k=top_k,
        )

        for rank, pred in enumerate(preds, start=1):
            row = dict(ev)
            row["ttp"] = pred["ttp"]
            row["confidence"] = pred["confidence"]
            row["rank"] = rank
            rows.append(row)

    return pd.DataFrame(rows)


def save_output(df: pd.DataFrame, output_path: Path):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_path.suffix.lower() == ".csv":
        df.to_csv(output_path, index=False)
    else:
        with open(output_path, "w", encoding="utf-8") as fh:
            for _, row in df.iterrows():
                fh.write(json.dumps(row.to_dict(), ensure_ascii=True) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Predict ATT&CK TTPs from Cowrie and Dionaea logs using your trained hybrid model."
    )
    parser.add_argument(
        "--cowrie",
        nargs="*",
        default=[],
        help="Cowrie JSON log file(s) (JSONL format).",
    )
    parser.add_argument(
        "--dionaea",
        nargs="*",
        default=[],
        help="Dionaea log file(s): JSONL or sqlite db.",
    )
    parser.add_argument(
        "--model-base",
        default=None,
        help="Model base name without extension. If omitted, latest model in current dir is used.",
    )
    parser.add_argument(
        "--model-dir",
        default=".",
        help="Directory containing model artifacts.",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=None,
        help="Optional fixed confidence threshold (overrides per-class thresholds).",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=3,
        help="Max TTP predictions per event.",
    )
    parser.add_argument(
        "--output",
        default="ttp_predictions.jsonl",
        help="Output file path (.jsonl or .csv).",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    model_dir = Path(args.model_dir).resolve()
    model_base = args.model_base or find_latest_model_base(model_dir)

    predictor = TTPPredictor(model_base=model_base, model_dir=model_dir)
    print(f"[INFO] Loaded model: {model_base}")

    cowrie_paths = [Path(p) for p in args.cowrie]
    dionaea_paths = [Path(p) for p in args.dionaea]

    if not cowrie_paths and not dionaea_paths:
        print("[INFO] No input logs provided. Example:")
        print("python predict_ttps_from_honeypot_logs.py --cowrie cowrie.json --dionaea attack_logs.json")
        return

    events = []
    if cowrie_paths:
        c_events = parse_cowrie_logs(cowrie_paths)
        events.extend(c_events)
        print(f"[INFO] Cowrie events parsed: {len(c_events)}")

    if dionaea_paths:
        d_events = parse_dionaea_logs(dionaea_paths)
        events.extend(d_events)
        print(f"[INFO] Dionaea events parsed: {len(d_events)}")

    if not events:
        print("[WARN] No parsable events found in provided logs.")
        return

    df = run_predictions(
        predictor=predictor,
        events=events,
        min_confidence=args.min_confidence,
        top_k=max(1, int(args.top_k)),
    )

    if df.empty:
        print("[WARN] No predictions produced.")
        return

    out_path = Path(args.output).resolve()
    save_output(df, out_path)

    print(f"[INFO] Predictions written: {out_path}")
    print(f"[INFO] Total predicted rows: {len(df)}")

    summary = (
        df.groupby("ttp")["confidence"]
        .agg(["count", "mean", "max"])
        .sort_values(["count", "mean"], ascending=[False, False])
        .head(10)
    )

    print("\nTop predicted TTPs:")
    print(summary.to_string(float_format=lambda x: f"{x:.4f}"))


if __name__ == "__main__":
    main()
