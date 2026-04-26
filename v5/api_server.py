import os
import time
import logging
import threading
from typing import Any, Dict, Optional
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

from predict_ttps_from_honeypot_logs import (
    TTPPredictor,
    canonicalize_command,
    find_latest_model_base
)

# ==========================================
# CONFIGURATION
# ==========================================
BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = Path(os.getenv("MODEL_DIR", str(BASE_DIR))).resolve()
TOP_K = int(os.getenv("TOP_K", "1"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("ml_api")

app = FastAPI(title="BiLSTM TTP Extractor API")

# Global State
predictor = None
loaded_model_base = None
predict_lock = threading.Lock()  # Prevents TF memory spikes from concurrent requests

# ==========================================
# STARTUP LIFECYCLE
# ==========================================
@app.on_event("startup")
def load_model():
    global predictor, loaded_model_base
    log.info("Starting up ML API Server...")
    try:
        model_base = find_latest_model_base(MODEL_DIR)
        predictor = TTPPredictor(model_base=model_base, model_dir=MODEL_DIR)
        loaded_model_base = model_base
        log.info(f"✅ Model '{model_base}' successfully loaded from {MODEL_DIR}")
    except Exception as e:
        log.error(f"❌ Failed to load model: {e}")
        raise RuntimeError("Could not load ML model. Halting API.")

# ==========================================
# REQUEST SCHEMA
# ==========================================
class LogRequest(BaseModel):
    log_text: str
    src_ip: Optional[str] = "unknown"

# ==========================================
# ENDPOINTS
# ==========================================
@app.get("/health")
def health():
    return {
        "status": "ok" if predictor is not None else "error",
        "model_loaded": predictor is not None,
        "model_base": loaded_model_base,
        "model_dir": str(MODEL_DIR)
    }

@app.post("/analyze_log")
def analyze_log(request: LogRequest):
    start_time = time.time()

    if not predictor:
        return {"error": "Model not loaded on server."}

    try:
        # 1. Canonicalize the already-normalized text from the SOAR engine
        command_for_model = canonicalize_command(request.log_text.strip())

        if not command_for_model:
            return {"error": "No parsable command found in payload."}

        # 2. Predict (Thread-safe inference)
        with predict_lock:
            predictions = predictor.predict_command(command_for_model, top_k=TOP_K)

        top_ttp = "BENIGN"
        confidence = 0.0

        if predictions:
            top_ttp = predictions[0]["ttp"]
            confidence = predictions[0]["confidence"] * 100.0

        # 3. Log and Return
        process_time = round((time.time() - start_time) * 1000, 2)
        log.info(f"[{request.src_ip}] Analyzed in {process_time}ms | {top_ttp} ({confidence:.1f}%)")

        return {
            "threat_type": top_ttp,
            "confidence": confidence,
            "processed_ms": process_time
        }

    except Exception as e:
        log.error(f"Prediction error: {e}")
        return {"error": str(e)}

# ==========================================
# SERVER EXECUTION
# ==========================================
if __name__ == "__main__":
    print("=" * 60)
    print("  BiLSTM TTP EXTRACTION API - PORT 5000")
    print("  Mode: Pure Inference (Stateless)")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=5000, log_level="warning")