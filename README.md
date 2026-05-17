AI-Powred Adaptive deception system for APT's
AI-Powered Adaptive Deception Network for Advanced Persistent Threat (APT) Detection &amp; Response using BiLSTM, Deep Q-Networks, and SOAR orchestration.
# AI-Powered Adaptive Deception Network

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![TensorFlow](https://img.shields.io/badge/TensorFlow-2.x-orange.svg)](https://www.tensorflow.org/)
[![DQN](https://img.shields.io/badge/RL-DQN-purple.svg)](https://stable-baselines3.readthedocs.io/)

## 📌 Overview

This project implements an **AI-driven adaptive deception network** that dynamically detects, profiles, and responds to Advanced Persistent Threats (APTs) in real-time. Unlike static honeypots that fail once discovered, our system uses **deep reinforcement learning (DQN)** combined with a **BiLSTM-based TTP classifier** to continuously adapt deception strategies based on attacker behavior.

## 🎯 Key Features

- 🔍 **Real-time TTP Classification** — BiLSTM + MultiHeadAttention model classifies attacker techniques across **25 MITRE ATT&CK categories** with **83.2% accuracy**
- 🤖 **Hybrid Decision Engine** — DQN (Deep Q-Network) reinforcement learning with rule-based fallback (SOAR v3) for adaptive defense actions
- 🐳 **Dynamic Honeypot Orchestration** — Docker-based decoy deployment that adapts to attacker skill level
- 🛡️ **Progressive Deception Layers** — Escalates from canary injection → decoy deployment → SDN throttling → containment
- 👤 **Attacker Profiling** — Risk scoring (0-500) with kill-chain sequence multipliers and persistent profiles
- 📡 **Multi-Honeypot Integration** — Ingests logs from **Cowrie** (SSH/Telnet) and **Dionaea** (SMB/HTTP/FTP)

## 🏗️ System Architecture

```
Honeypot Input (Cowrie + Dionaea)
       ↓
Phase 1: BiLSTM TTP Classifier (ML API on port 5000)
       ↓
Phase 2: Attacker Profiler (Risk Scoring + Threat Intel)
       ↓
Phase 3: Adaptive Deception SOAR (DQN + RULE hybrid)
       ↓
Defense Actions: Monitor | Canary | Decoy | Throttle | Containment
```

## 🧠 Tech Stack

| Component | Technology |
|-----------|-----------|
| **Deep Learning** | TensorFlow, BiLSTM, MultiHeadAttention, Focal Loss (γ=2.0) |
| **Reinforcement Learning** | Stable-Baselines3, DQN, Custom Gym Environment |
| **Honeypots** | Cowrie, Dionaea, Docker |
| **API Server** | FastAPI, Uvicorn (port 5000) |
| **Logging** | Elasticsearch |
| **Orchestration** | Python threading, Paramiko SSH, iptables, tc (traffic control) |
| **Data Processing** | pandas, numpy, scikit-learn |

## 📊 Performance Metrics

| Metric | Value |
|--------|-------|
| TTP Classification Accuracy | **83.2%** |
| Average Prediction Confidence | **98.7%** |
| TTP Classes Covered | **25** MITRE ATT&CK techniques |
| SOC Features Extracted | **19** |
| Defense Action Types | **5** (Monitor, Canary, Decoy, Throttle, Containment) |
| Max Risk Score | **500** |

## 📁 Project Structure

```
├── adaptive_engine.py              # Main SOAR engine (DQN + RULE hybrid)
├── api_server.py                   # FastAPI server for TTP prediction
├── train_model.py                  # BiLSTM model training pipeline
├── dqn_adaptive_deception.py       # Custom Gym environment for DQN
├── create_dqn_policy.py            # Quick DQN policy generator
├── predict_ttps_from_honeypot_logs.py  # TTP inference module
├── mitre_mapping.py                # MITRE ATT&CK enrichment
├── docker_orchestrator.py          # Docker container management
├── requirements.txt                # Python dependencies
└── README.md                       # This file
```

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Docker
- 8GB+ RAM recommended

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/ai-adaptive-deception-network.git
cd ai-adaptive-deception-network

# Install dependencies
pip install -r requirements.txt
```

### Usage

```bash
# Step 1: Train the BiLSTM model
python train_model.py

# Step 2: Generate quick DQN policy
python create_dqn_policy.py

# Step 3: Start ML API server
python api_server.py &

# Step 4: Run adaptive deception engine
python adaptive_engine.py
```

## 🔧 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `USE_DQN_POLICY` | `1` | Enable/disable DQN mode |
| `DQN_MODEL_PATH` | `dqn_adaptive_deception_quick` | Path to DQN model |
| `MOCK_SSH` | `1` | Mock SSH for testing |
| `RISK_SCORE_CAP` | `500.0` | Maximum risk score per attacker |
| `COOLDOWN_WINDOW` | `60` | Seconds between defense actions |

## 📚 Research Contributions

1. ✅ Novel integration of **BiLSTM-based TTP classification** with **reinforcement learning** for adaptive honeypot deception
2. ✅ **Hybrid DQN + Rule-based** decision engine ensuring seamless fallback
3. ✅ **Kill-chain-aware** risk scoring with sequence bonus multipliers
4. ✅ **Docker-based** dynamic decoy orchestration responding to attacker TTPs
5. ✅ Comprehensive **25-class TTP classifier** trained on synthetic + real honeypot logs

## 👨‍🔬 Authors

- **Muhammad Saqib** — Reg. No. 22147324
- **Tauseef Ahmed** — Reg. No. 22150989

**Supervisor:** Prof. Muhammad Shahzad  
**Institution:** Abdul Wali Khan University Mardan  
**Department:** Computer Science  

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- MITRE ATT&CK framework
- Cowrie & Dionaea honeypot communities
- Stable-Baselines3 contributors
- TensorFlow team

---

⭐ **If you find this project useful, please consider giving it a star!**
