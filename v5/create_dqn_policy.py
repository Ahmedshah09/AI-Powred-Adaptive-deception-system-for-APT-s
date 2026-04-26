"""
Create a DQN policy for Adaptive Deception.
Includes EvalCallback to guarantee the BEST model is saved, not just the LAST.
"""

import json
import numpy as np
import os
from pathlib import Path

try:
    from stable_baselines3 import DQN
    from stable_baselines3.common.evaluation import evaluate_policy
    from stable_baselines3.common.callbacks import EvalCallback
    from stable_baselines3.common.monitor import Monitor
    from dqn_adaptive_deception import AdaptiveDeceptionEnv, DEFAULT_TTPS, ACTIONS
    SB3_AVAILABLE = True
except ImportError:
    print("[ERROR] stable-baselines3 not installed. Run: pip install stable-baselines3 gymnasium")
    exit(1)

# ==========================================
# CONFIGURATION
# ==========================================
PRODUCTION_MODE = False  # Set to True for overnight training (250k steps)

MODEL_OUT   = "dqn_adaptive_deception_best"
VOCAB_OUT   = f"{MODEL_OUT}.ttp_vocab.json"
TRAIN_STEPS = 250000 if PRODUCTION_MODE else 5000
EVAL_FREQ   = 1000   if PRODUCTION_MODE else 500

print("=" * 60)
print(f"  CREATING DQN POLICY (Mode: {'PRODUCTION' if PRODUCTION_MODE else 'QUICK'})")
print("=" * 60)

# Save TTP vocabulary
ttp_vocab = DEFAULT_TTPS
with open(VOCAB_OUT, "w", encoding="utf-8") as fh:
    json.dump(ttp_vocab, fh, indent=2)
print(f"[✓] TTP vocabulary saved: {VOCAB_OUT} ({len(ttp_vocab)} techniques)")

# ==========================================
# ENVIRONMENT SETUP
# ==========================================
print(f"\n[>] Creating Gym environments...")
# Training Environment (Wrapped in Monitor to track stats)
train_env = Monitor(AdaptiveDeceptionEnv(ttp_vocab=ttp_vocab, max_episode_minutes=30, seed=42))

# Separate Evaluation Environment (crucial for unbiased evaluation during training)
eval_env = Monitor(AdaptiveDeceptionEnv(ttp_vocab=ttp_vocab, max_episode_minutes=30, seed=99))

# ==========================================
# CALLBACK: SAVE BEST MODEL
# ==========================================
# This ensures we don't suffer from "catastrophic forgetting". 
# It tests the model every EVAL_FREQ steps and saves the highest-scoring version.
eval_callback = EvalCallback(
    eval_env, 
    best_model_save_path='./best_dqn_model/',
    log_path='./logs/', 
    eval_freq=EVAL_FREQ,
    deterministic=True, 
    render=False,
    verbose=1
)

# ==========================================
# MODEL INITIALIZATION
# ==========================================
print(f"[>] Initializing DQN ({TRAIN_STEPS} steps scheduled)...")
model = DQN(
    "MlpPolicy",
    train_env,
    learning_rate=1e-3,
    buffer_size=10000 if not PRODUCTION_MODE else 100000,
    learning_starts=1000,
    batch_size=64,
    tau=1.0,
    gamma=0.98,
    train_freq=4,
    target_update_interval=500,
    exploration_fraction=0.3 if not PRODUCTION_MODE else 0.1,
    exploration_final_eps=0.05,
    policy_kwargs={"net_arch": [128, 128]},  # Increased capacity for better logic mapping
    verbose=0,
    seed=42,
)

# ==========================================
# TRAINING
# ==========================================
print(f"\n[>] Training in progress. Best models will be saved automatically...")
model.learn(total_timesteps=TRAIN_STEPS, callback=eval_callback)

# ==========================================
# FINAL EVALUATION
# ==========================================
print("\n" + "=" * 60)
print("  EVALUATING BEST DISCOVERED POLICY")
print("=" * 60)

# Load the absolute best model found during training (not just the last step)
best_model_path = os.path.join('./best_dqn_model/', 'best_model.zip')
if os.path.exists(best_model_path):
    best_model = DQN.load(best_model_path)
    
    # Use native stable-baselines3 evaluator
    mean_reward, std_reward = evaluate_policy(best_model, eval_env, n_eval_episodes=20)
    print(f"\n[✓] Evaluation Complete (20 Episodes):")
    print(f"    Mean Reward : {mean_reward:.2f} +/- {std_reward:.2f}")
    
    # Overwrite the final output with the verified best model
    best_model.save(MODEL_OUT)
    print(f"\n[✓] Best DQN policy promoted to: {MODEL_OUT}.zip")
else:
    print("\n[!] Warning: EvalCallback did not generate a best model. Saving final step.")
    model.save(MODEL_OUT)

print("\n  To use DQN mode in the Adaptive Engine, run:")
print(f"  export USE_DQN_POLICY='1'")
print(f"  export DQN_MODEL_PATH='{MODEL_OUT}'")
print(f"  python adaptive_engine.py")