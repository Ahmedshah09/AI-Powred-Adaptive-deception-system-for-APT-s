import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
try:
    import gymnasium as gym
    from gymnasium import spaces
    GYM_AVAILABLE = True
except ImportError:
    gym = None
    spaces = None
    GYM_AVAILABLE = False

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    pd = None
    PANDAS_AVAILABLE = False

try:
    from stable_baselines3 import DQN
    from stable_baselines3.common.monitor import Monitor
    SB3_AVAILABLE = True
except ImportError:
    DQN = None
    Monitor = None
    SB3_AVAILABLE = False


ACTIONS = {
    0: "monitor",
    1: "inject_canary",
    2: "deploy_decoy",
    3: "throttle",
    4: "containment",
}

DEFAULT_TTPS = [
    "BENIGN",
    "T1003_OS_Credential_Dumping",
    "T1005_Data_from_Local_System",
    "T1012_Query_Registry",
    "T1016_System_Network_Config_Discovery",
    "T1018_Remote_System_Discovery",
    "T1021_Remote_Services",
    "T1027_Obfuscated_Files_or_Information",
    "T1041_Exfiltration_Over_C2_Channel",
    "T1046_Network_Service_Scanning",
    "T1053_Scheduled_Task",
    "T1059_Command_and_Scripting_Interpreter",
    "T1068_Exploitation_for_Privilege_Escalation",
    "T1070_Indicator_Removal",
    "T1071_Application_Layer_Protocol",
    "T1078_Valid_Accounts",
    "T1082_System_Information_Discovery",
    "T1087_Account_Discovery",
    "T1090_Proxy",
    "T1098_Account_Manipulation",
    "T1105_Ingress_Tool_Transfer",
    "T1110_Brute_Force",
    "T1123_Audio_Capture",
    "T1136_Create_Account",
    "T1496_Resource_Hijacking",
]


def load_ttp_vocab(vocab_path: str = "") -> List[str]:
    if vocab_path:
        p = Path(vocab_path)
        with open(p, "r", encoding="utf-8") as fh:
            vocab = json.load(fh)
        if not isinstance(vocab, list) or not vocab:
            raise ValueError(f"Invalid vocab file: {p}")
        return [str(v) for v in vocab]
    return DEFAULT_TTPS


def resolve_ttp_for_vocab(raw_ttp: str, ttp_vocab: List[str]) -> str:
    """
    Map model output labels to the exact vocabulary used by the DQN policy.
    Falls back to BENIGN or first vocab item when no direct/technique-code
    match exists.
    """
    ttp = str(raw_ttp or "")
    if ttp in ttp_vocab:
        return ttp

    code = ttp.split("_")[0]
    if code:
        for item in ttp_vocab:
            if item == code or item.startswith(f"{code}_"):
                return item

    if "BENIGN" in ttp_vocab:
        return "BENIGN"
    return ttp_vocab[0]

CATEGORY_BY_PREFIX = {
    "T108": "discovery",
    "T101": "discovery",
    "T1046": "recon",
    "T1110": "credential_access",
    "T1003": "credential_access",
    "T1021": "lateral_movement",
    "T1105": "execution",
    "T1059": "execution",
    "T1068": "privilege_escalation",
    "T1098": "persistence",
    "T1136": "persistence",
    "T1053": "persistence",
    "T1041": "exfiltration",
    "T1496": "impact",
    "T1070": "defense_evasion",
    "T1027": "defense_evasion",
}

# Preferred response strength by category (higher is stronger containment).
PREFERRED_ACTIONS = {
    "benign": [0],
    "recon": [1, 2],
    "discovery": [1, 2],
    "credential_access": [2, 3],
    "execution": [2, 3],
    "privilege_escalation": [3, 4],
    "persistence": [3, 4],
    "lateral_movement": [3, 4],
    "defense_evasion": [2, 3],
    "exfiltration": [4],
    "impact": [4],
}


def technique_prefix(ttp: str) -> str:
    if not isinstance(ttp, str):
        return ""
    if ttp.startswith("T") and len(ttp) >= 5:
        return ttp.split("_")[0]
    return ""


def ttp_category(ttp: str) -> str:
    if ttp == "BENIGN":
        return "benign"
    prefix = technique_prefix(ttp)
    if prefix in CATEGORY_BY_PREFIX:
        return CATEGORY_BY_PREFIX[prefix]
    for key, value in CATEGORY_BY_PREFIX.items():
        if prefix.startswith(key):
            return value
    return "execution"


class AdaptiveDeceptionEnv(gym.Env if GYM_AVAILABLE else object):
    """
    Custom RL environment for adaptive deception in honeypots.

    State:
      - One-hot TTP vector from extracted ATT&CK prediction.
      - risk_score in [0, 1]
      - engagement_minutes normalized in [0, 1]
      - deception_exposure in [0, 1]
      - last_action normalized in [0, 1]

    Actions:
      0 monitor
      1 inject_canary
      2 deploy_decoy
      3 throttle
      4 containment

    Reward:
      +10 if attacker stays connected for one more minute.
      -50 if attacker detects honeypot and disconnects.
       0 if attacker disconnects for non-detection reasons.
    """

    metadata = {"render_modes": []}

    def __init__(self, ttp_vocab: List[str], max_episode_minutes: int = 30, seed: int = 42):
        if not GYM_AVAILABLE:
            raise ImportError("gymnasium is required for AdaptiveDeceptionEnv.")
        super().__init__()
        self.ttp_vocab = ttp_vocab
        self.ttp_to_idx = {t: i for i, t in enumerate(ttp_vocab)}
        self.max_episode_minutes = max_episode_minutes

        self.action_space = spaces.Discrete(len(ACTIONS))
        obs_dim = len(self.ttp_vocab) + 4
        self.observation_space = spaces.Box(low=0.0, high=1.0, shape=(obs_dim,), dtype=np.float32)

        self.np_random = np.random.default_rng(seed)

        self.current_ttp = "BENIGN"
        self.risk_score = 0.1
        self.engagement_minutes = 0
        self.deception_exposure = 0.0
        self.last_action = 0
        self.done = False

    def _sample_ttp(self, prev_ttp: str) -> str:
        prev_cat = ttp_category(prev_ttp)

        if prev_cat in {"recon", "discovery", "benign"}:
            pool = [t for t in self.ttp_vocab if ttp_category(t) in {"discovery", "credential_access", "execution", "benign"}]
        elif prev_cat in {"credential_access", "execution", "defense_evasion"}:
            pool = [t for t in self.ttp_vocab if ttp_category(t) in {"execution", "privilege_escalation", "persistence", "lateral_movement"}]
        else:
            pool = [t for t in self.ttp_vocab if ttp_category(t) in {"persistence", "lateral_movement", "exfiltration", "impact", "benign"}]

        if not pool:
            return self.np_random.choice(self.ttp_vocab)

        return self.np_random.choice(pool)

    def _action_fit(self, ttp: str, action: int) -> float:
        category = ttp_category(ttp)
        preferred = PREFERRED_ACTIONS.get(category, [2, 3])
        if action in preferred:
            return 1.0
        if action == 0 and category != "benign":
            return -0.6
        if action == 4 and category in {"benign", "recon", "discovery"}:
            return -0.5
        return 0.2

    def _obs(self) -> np.ndarray:
        vec = np.zeros(len(self.ttp_vocab), dtype=np.float32)
        vec[self.ttp_to_idx.get(self.current_ttp, 0)] = 1.0

        scalars = np.array(
            [
                np.clip(self.risk_score / 100.0, 0.0, 1.0),
                np.clip(self.engagement_minutes / float(self.max_episode_minutes), 0.0, 1.0),
                np.clip(self.deception_exposure, 0.0, 1.0),
                self.last_action / float(len(ACTIONS) - 1),
            ],
            dtype=np.float32,
        )
        return np.concatenate([vec, scalars], axis=0)

    def reset(self, seed=None, options=None):
        if seed is not None:
            self.np_random = np.random.default_rng(seed)

        self.current_ttp = self.np_random.choice(self.ttp_vocab)
        self.risk_score = float(self.np_random.uniform(5, 20))
        self.engagement_minutes = 0
        self.deception_exposure = 0.0
        self.last_action = 0
        self.done = False

        return self._obs(), {}

    def step(self, action: int):
        if self.done:
            return self._obs(), 0.0, True, False, {"reason": "episode_already_done"}

        action = int(action)
        fit = self._action_fit(self.current_ttp, action)

        # Detection probability: stronger/deceptive actions increase chance of discovery
        # if overused, while poor-fit actions increase risk.
        detection_prob = np.clip(
            0.04 + 0.22 * self.deception_exposure + 0.004 * self.risk_score - 0.05 * fit,
            0.01,
            0.95,
        )

        # Staying probability: suitable actions keep attacker engaged.
        stay_prob = np.clip(
            0.45 + 0.18 * max(fit, 0) - 0.003 * self.risk_score - 0.1 * self.deception_exposure,
            0.02,
            0.98,
        )

        detected = self.np_random.random() < detection_prob
        if detected:
            reward = -50.0
            self.done = True
            info = {
                "reason": "detected_honeypot",
                "ttp": self.current_ttp,
                "action": ACTIONS[action],
                "detection_prob": float(detection_prob),
                "stay_prob": float(stay_prob),
            }
            return self._obs(), reward, True, False, info

        stayed = self.np_random.random() < stay_prob
        if stayed:
            reward = 10.0
            self.engagement_minutes += 1
        else:
            reward = 0.0
            self.done = True

        # Update evolving risk/exposure state.
        self.risk_score = float(np.clip(self.risk_score + 4.0 - 5.0 * max(fit, 0), 0.0, 100.0))

        if action == 0:
            self.deception_exposure = float(np.clip(self.deception_exposure - 0.05, 0.0, 1.0))
        else:
            self.deception_exposure = float(np.clip(self.deception_exposure + 0.09, 0.0, 1.0))

        self.last_action = action

        if not self.done:
            self.current_ttp = self._sample_ttp(self.current_ttp)

        if self.engagement_minutes >= self.max_episode_minutes:
            self.done = True

        reason = "attacker_stayed" if stayed else "attacker_disconnected"
        info = {
            "reason": reason,
            "ttp": self.current_ttp,
            "action": ACTIONS[action],
            "detection_prob": float(detection_prob),
            "stay_prob": float(stay_prob),
        }

        return self._obs(), reward, self.done, False, info


@dataclass
class SessionState:
    risk_score: float = 20.0
    engagement_minutes: int = 0
    deception_exposure: float = 0.0
    last_action: int = 0


def build_obs_from_ttp(ttp: str, state: SessionState, ttp_vocab: List[str], max_minutes: int = 30) -> np.ndarray:
    ttp_to_idx = {t: i for i, t in enumerate(ttp_vocab)}
    vec = np.zeros(len(ttp_vocab), dtype=np.float32)
    vec[ttp_to_idx.get(ttp, 0)] = 1.0

    scalars = np.array(
        [
            np.clip(state.risk_score / 100.0, 0.0, 1.0),
            np.clip(state.engagement_minutes / float(max_minutes), 0.0, 1.0),
            np.clip(state.deception_exposure, 0.0, 1.0),
            state.last_action / float(len(ACTIONS) - 1),
        ],
        dtype=np.float32,
    )

    return np.concatenate([vec, scalars], axis=0)


def train_dqn(args):
    if not SB3_AVAILABLE:
        raise ImportError("stable-baselines3 is required to train DQN.")
    if not GYM_AVAILABLE:
        raise ImportError("gymnasium is required to train DQN.")
    ttp_vocab = load_ttp_vocab(args.ttp_vocab)
    env = Monitor(AdaptiveDeceptionEnv(ttp_vocab=ttp_vocab, max_episode_minutes=args.max_minutes, seed=args.seed))

    model = DQN(
        "MlpPolicy",
        env,
        learning_rate=args.learning_rate,
        buffer_size=args.buffer_size,
        learning_starts=args.learning_starts,
        batch_size=args.batch_size,
        tau=1.0,
        gamma=args.gamma,
        train_freq=4,
        target_update_interval=args.target_update_interval,
        exploration_fraction=args.exploration_fraction,
        exploration_final_eps=args.exploration_final_eps,
        policy_kwargs={"net_arch": [128, 128]},
        verbose=args.sb3_verbose,
        seed=args.seed,
    )

    model.learn(total_timesteps=args.total_timesteps, log_interval=args.log_interval)
    output = Path(args.model_out)
    output.parent.mkdir(parents=True, exist_ok=True)
    model.save(str(output))

    vocab_path = output.with_suffix(".ttp_vocab.json")
    with open(vocab_path, "w", encoding="utf-8") as fh:
        json.dump(ttp_vocab, fh, indent=2)

    print(f"[INFO] Model saved: {output}")
    print(f"[INFO] TTP vocab saved: {vocab_path}")


def evaluate_dqn(args):
    if not SB3_AVAILABLE:
        raise ImportError("stable-baselines3 is required to evaluate DQN.")
    if not GYM_AVAILABLE:
        raise ImportError("gymnasium is required to evaluate DQN.")
    model = DQN.load(args.model_path)
    vocab_path = args.ttp_vocab or f"{args.model_path}.ttp_vocab.json"
    ttp_vocab = load_ttp_vocab(vocab_path)
    env = AdaptiveDeceptionEnv(ttp_vocab=ttp_vocab, max_episode_minutes=args.max_minutes, seed=args.seed)

    episode_rewards = []
    detections = 0

    for ep in range(args.episodes):
        obs, _ = env.reset(seed=args.seed + ep)
        done = False
        total_reward = 0.0
        last_reason = ""

        while not done:
            action, _ = model.predict(obs, deterministic=True)
            obs, reward, terminated, truncated, info = env.step(int(action))
            total_reward += float(reward)
            done = bool(terminated or truncated)
            last_reason = info.get("reason", "")

        if last_reason == "detected_honeypot":
            detections += 1
        episode_rewards.append(total_reward)

    rewards = np.array(episode_rewards, dtype=np.float32)
    print("[INFO] Evaluation complete")
    print(f"[INFO] Episodes: {args.episodes}")
    print(f"[INFO] Mean reward: {rewards.mean():.2f}")
    print(f"[INFO] Median reward: {np.median(rewards):.2f}")
    print(f"[INFO] Detection rate: {(detections / max(1, args.episodes)) * 100:.2f}%")


def recommend_actions(args):
    if not SB3_AVAILABLE:
        raise ImportError("stable-baselines3 is required to recommend actions.")
    if not PANDAS_AVAILABLE:
        raise ImportError("pandas is required to recommend actions.")
    model = DQN.load(args.model_path)
    vocab_path = args.ttp_vocab or f"{args.model_path}.ttp_vocab.json"
    ttp_vocab = load_ttp_vocab(vocab_path)

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input predictions file not found: {input_path}")

    if input_path.suffix.lower() == ".csv":
        df = pd.read_csv(input_path)
    else:
        rows = []
        with open(input_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        df = pd.DataFrame(rows)

    required = {"ttp", "src_ip", "confidence"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Input file missing required columns: {sorted(missing)}")

    if "timestamp" in df.columns:
        df = df.sort_values(["src_ip", "timestamp", "rank"], na_position="last")
    elif "line" in df.columns:
        df = df.sort_values(["src_ip", "line", "rank"], na_position="last")
    else:
        df = df.sort_values(["src_ip", "rank"], na_position="last")

    sessions: Dict[str, SessionState] = {}
    outputs: List[Dict[str, object]] = []

    for _, row in df.iterrows():
        ip = str(row.get("src_ip", "unknown"))
        raw_ttp = str(row.get("ttp", "BENIGN"))
        confidence = float(row.get("confidence", 0.0))
        ttp = resolve_ttp_for_vocab(raw_ttp, ttp_vocab)

        state = sessions.setdefault(ip, SessionState())
        state.risk_score = float(np.clip(state.risk_score + 8.0 * confidence, 0.0, 100.0))

        obs = build_obs_from_ttp(ttp, state, ttp_vocab, max_minutes=args.max_minutes)
        action_idx, _ = model.predict(obs, deterministic=True)
        action_idx = int(action_idx)
        action_name = ACTIONS[action_idx]

        # Approximate state progression for next event for same attacker.
        state.engagement_minutes = min(state.engagement_minutes + 1, args.max_minutes)
        if action_idx == 0:
            state.deception_exposure = max(0.0, state.deception_exposure - 0.04)
        else:
            state.deception_exposure = min(1.0, state.deception_exposure + 0.08)
        state.last_action = action_idx

        outputs.append(
            {
                "src_ip": ip,
                "timestamp": row.get("timestamp", ""),
                "sensor": row.get("sensor", ""),
                "eventid": row.get("eventid", ""),
                "ttp": ttp,
                "confidence": confidence,
                "recommended_action": action_name,
                "action_id": action_idx,
                "risk_score": round(state.risk_score, 3),
                "engagement_minutes": state.engagement_minutes,
                "deception_exposure": round(state.deception_exposure, 3),
            }
        )

    out_df = pd.DataFrame(outputs)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if out_path.suffix.lower() == ".csv":
        out_df.to_csv(out_path, index=False)
    else:
        with open(out_path, "w", encoding="utf-8") as fh:
            for _, rec in out_df.iterrows():
                fh.write(json.dumps(rec.to_dict(), ensure_ascii=True) + "\n")

    print(f"[INFO] Wrote recommendations: {out_path.resolve()}")
    print("[INFO] Action distribution:")
    print(out_df["recommended_action"].value_counts().to_string())


def build_parser():
    parser = argparse.ArgumentParser(
        description="Adaptive deception with DQN: train, evaluate, and recommend actions from TTP logs."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    train = sub.add_parser("train", help="Train DQN policy in custom Gymnasium environment.")
    train.add_argument("--model-out", default="dqn_adaptive_deception")
    train.add_argument("--total-timesteps", type=int, default=120000)
    train.add_argument("--learning-rate", type=float, default=1e-3)
    train.add_argument("--buffer-size", type=int, default=50000)
    train.add_argument("--learning-starts", type=int, default=2000)
    train.add_argument("--batch-size", type=int, default=128)
    train.add_argument("--target-update-interval", type=int, default=1000)
    train.add_argument("--gamma", type=float, default=0.98)
    train.add_argument("--exploration-fraction", type=float, default=0.25)
    train.add_argument("--exploration-final-eps", type=float, default=0.05)
    train.add_argument("--max-minutes", type=int, default=30)
    train.add_argument("--seed", type=int, default=42)
    train.add_argument("--ttp-vocab", default="", help="Optional JSON file containing TTP label list.")
    train.add_argument("--sb3-verbose", type=int, default=0, choices=[0, 1, 2])
    train.add_argument("--log-interval", type=int, default=50)
    train.set_defaults(func=train_dqn)

    evaluate = sub.add_parser("evaluate", help="Evaluate a trained DQN policy.")
    evaluate.add_argument("--model-path", required=True)
    evaluate.add_argument("--episodes", type=int, default=200)
    evaluate.add_argument("--max-minutes", type=int, default=30)
    evaluate.add_argument("--seed", type=int, default=42)
    evaluate.add_argument("--ttp-vocab", default="", help="Optional TTP vocab JSON. Defaults to <model_path>.ttp_vocab.json")
    evaluate.set_defaults(func=evaluate_dqn)

    recommend = sub.add_parser("recommend", help="Recommend deception actions from predicted TTP logs.")
    recommend.add_argument("--model-path", required=True)
    recommend.add_argument("--input", required=True, help="Input file from TTP predictor (.csv or .jsonl).")
    recommend.add_argument("--output", default="adaptive_actions.csv")
    recommend.add_argument("--max-minutes", type=int, default=30)
    recommend.add_argument("--ttp-vocab", default="", help="Optional TTP vocab JSON. Defaults to <model_path>.ttp_vocab.json")
    recommend.set_defaults(func=recommend_actions)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
