# 🔥 NetGuard — Smart Firewall & Intrusion Detection System

A real-time, AI-based **Smart Firewall and Intrusion Detection System (IDS)** for data center security. The system acts as an intermediary between incoming and outgoing network traffic — capturing live packets, extracting features, and detecting cyber attacks using a **hybrid approach**: rule-based detection, **Isolation Forest** for anomaly detection, and **XGBoost** for attack classification.

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![Flask](https://img.shields.io/badge/Flask-2.3+-green)
![XGBoost](https://img.shields.io/badge/XGBoost-99.74%25_Accuracy-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Table of Contents

- [Features](#features)
- [System Architecture](#system-architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Dataset Setup](#dataset-setup)
- [Training the XGBoost Model](#training-the-xgboost-model)
- [Running the Application](#running-the-application)
- [API Endpoints](#api-endpoints)
- [Configuration](#configuration)
- [Detection Capabilities](#detection-capabilities)
- [Decision Engine](#decision-engine)
- [Telegram Alerts](#telegram-alerts)
- [Dashboard](#dashboard)
- [Troubleshooting](#troubleshooting)

---

## Features

- **🔥 Smart Firewall** — BLOCK / FLAG / ALLOW decision engine with simulated IP blocking
- **📦 Real-time Packet Capture** — Live packet sniffing using Scapy with metadata extraction
- **🧠 Hybrid Detection Engine** — Rule-based + XGBoost + Isolation Forest working in concert
- **🎯 XGBoost Classifier** — Trained on CICIDS-2017 with **99.74% accuracy** across 27 attack classes
- **🌲 Isolation Forest Fallback** — Unsupervised anomaly detection when XGBoost is unavailable
- **📏 Rule-Based Detection** — DDoS, Port Scan, SYN Flood, SQL Injection, Brute Force, DNS Tunneling, ICMP Flood, ARP Spoofing, Encrypted Anomaly
- **⚖️ Decision Engine** — Combines detection outputs into BLOCK/FLAG/ALLOW decisions
- **📱 Telegram Alerts** — Real-time notifications for HIGH/CRITICAL severity attacks
- **📊 Live Dashboard** — 6-tab web UI with Chart.js visualizations and WebSocket real-time updates
- **🔍 Explainable Alerts** — Every alert includes evidence, confidence scores, and detection method

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     NetGuard Smart Firewall & IDS                       │
│                                                                         │
│  ┌──────────────┐    ┌────────────────┐    ┌──────────────────────┐    │
│  │   Network     │    │   Feature       │    │   Hybrid Detection   │    │
│  │   Interface   │───▶│   Extraction    │───▶│   Engine             │    │
│  │   (Scapy)     │    │                │    │                      │    │
│  └──────────────┘    └────────────────┘    │  ┌──────────┐        │    │
│                                             │  │ Rule-    │        │    │
│  ┌──────────────┐                           │  │ Based    │        │    │
│  │   Flow        │◀─────────────────────────│  │ Engine   │        │    │
│  │   Analyzer    │─────────────────────────▶│  └──────────┘        │    │
│  └──────────────┘                           │  ┌──────────┐        │    │
│                                             │  │ XGBoost  │        │    │
│                                             │  │ + Isol.  │        │    │
│                                             │  │ Forest   │        │    │
│                                             │  └──────────┘        │    │
│                                             └──────────┬───────────┘    │
│                                                        ▼                │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    Decision Engine (Firewall)                     │   │
│  │                                                                   │   │
│  │   Rule + ML confirms ──▶ 🚫 BLOCK (auto-block IP for 5 min)     │   │
│  │   Anomaly only ────────▶ ⚠️  FLAG  (auto-block after 3 flags)    │   │
│  │   Neither detects ─────▶ ✅ ALLOW                                 │   │
│  └──────────┬───────────────────────────────────┬───────────────────┘   │
│             ▼                                   ▼                       │
│  ┌──────────────────┐              ┌──────────────────────────────┐    │
│  │  Telegram Alerts  │              │   Flask Dashboard + SocketIO │    │
│  │  (HIGH/CRITICAL)  │              │   (6-tab real-time UI)       │    │
│  └──────────────────┘              └──────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
4th-SEM-MAIN-EL/
├── app.py                         # Flask application entry point (dashboard.py)
├── config.py                      # Configuration: rules, thresholds, firewall, Telegram
├── requirements.txt               # Python dependencies
├── train_xgboost.py               # XGBoost model training pipeline
├── download_dataset.py            # CICIDS-2017 dataset download helper
├── test_attack.py                 # Synthetic attack simulation testing script
├── README.md                      # This file
├── REPORT.md                      # Detailed project report (Phase 2)
├── PHASE1_REPORT.md               # Phase 1 project report
│
├── engine/                        # Core engine modules
│   ├── __init__.py
│   ├── packet_capture.py          # Packet capture with Scapy (+ simulation fallback)
│   ├── feature_extraction.py      # Feature extraction from packets and flows
│   ├── flow_analyzer.py           # Bidirectional flow tracking & feature computation
│   └── decision_engine.py         # BLOCK / FLAG / ALLOW decision logic (firewall)
│
├── detection/                     # Detection engines
│   ├── __init__.py
│   ├── rule_engine.py             # Rule-based detection (DDoS, Port Scan, SQLi, etc.)
│   ├── ml_detector.py             # ML detection (XGBoost primary + Isolation Forest)
│   └── hybrid_detector.py         # Hybrid detection manager + alert correlation
│
├── alerts/                        # Alert notification modules
│   ├── __init__.py
│   └── telegram_alert.py          # Telegram Bot API notifications
│
├── dataset/                       # CICIDS-2017 CSV files (training data)
│   ├── monday.csv
│   ├── tuesday.csv
│   ├── wednesday.csv
│   ├── thursday.csv
│   └── friday.csv
│
├── models/                        # Trained ML model files
│   ├── xgboost_model.json         # Trained XGBoost model (99.74% accuracy)
│   ├── xgb_scaler.pkl             # Feature scaler
│   ├── xgb_label_encoder.pkl      # Label encoder (27 classes)
│   ├── xgb_feature_names.pkl      # Feature column names (81 features)
│   ├── xgb_metadata.pkl           # Training metadata
│   ├── isolation_forest.pkl       # Fallback IF model
│   └── scaler.pkl                 # Fallback IF scaler
│
├── templates/                     # HTML templates
│   └── index.html                 # Dashboard UI (6 tabs)
│
└── static/                        # Static assets
    ├── css/
    │   └── dashboard.css          # Premium dark theme stylesheet
    └── js/
        └── dashboard.js           # Real-time dashboard logic
```

---

## Prerequisites

- **Python 3.9** or higher
- **macOS / Linux / Windows** (packet capture requires appropriate permissions; Windows requires Npcap)
- **pip** (Python package manager)

---

## Installation

### Step 1: Clone or navigate to the project

```bash
cd /path/to/4th-SEM-MAIN-EL
```

### Step 2: Install Python dependencies

```bash
pip3 install -r requirements.txt
```

This installs:
| Package | Purpose |
|---------|---------|
| `flask` | Web framework |
| `flask-socketio` | Real-time WebSocket communication |
| `scapy` | Network packet capture |
| `scikit-learn` | ML utilities (preprocessing, metrics) |
| `xgboost` | XGBoost classifier |
| `pandas` | Data manipulation |
| `numpy` | Numerical computing |
| `joblib` | Model serialization |
| `eventlet` | Async server support |

### Step 3 (macOS): Install OpenMP runtime for XGBoost

```bash
brew install libomp
```

### Step 3 (Windows): Install Npcap

For Windows, `scapy` requires **Npcap** to capture live network packets.
1. Download Npcap from [npcap.com](https://npcap.com/#download)
2. Run the installer. Ensure you select the option **"Install Npcap in WinPcap API-compatible Mode"** during installation.

---

## Dataset Setup

The project uses the **CICIDS-2017** dataset for training the XGBoost model.

### Download the Dataset

**Option A — Automatic Download (Recommended):**

```bash
python3 download_dataset.py
```

**Option B — Manual Download from Hugging Face:**

1. Go to [huggingface.co/datasets/eugenesiow/CICIDS2017](https://huggingface.co/datasets/eugenesiow/CICIDS2017)
2. Download the CSV files
3. Place them in the `dataset/` folder

---

## Training the XGBoost Model

```bash
python3 train_xgboost.py
```

### What the training script does:

1. **Loads** all 5 CSV files (~2.8 million rows)
2. **Cleans** data — handles infinite values, NaN, removes duplicates
3. **Balances** classes — downsamples the majority class (BENIGN)
4. **Trains** an XGBoost multi-class classifier (200 trees, max depth 8)
5. **Evaluates** with accuracy, F1-score, and per-class classification report
6. **Saves** all model artifacts to `models/`

### Training hyperparameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `n_estimators` | 200 | Number of boosted trees |
| `max_depth` | 8 | Maximum tree depth |
| `learning_rate` | 0.1 | Boosting learning rate |
| `subsample` | 0.8 | Row subsampling ratio |
| `colsample_bytree` | 0.8 | Column subsampling ratio |
| `MAX_SAMPLES_PER_CLASS` | 100,000 | Max samples per class (for balancing) |

---

## Running the Application

### Start the server:

```bash
# With live packet capture (requires root):
sudo python3 app.py

# Without root (falls back to simulation mode):
python3 app.py
```

### Access the dashboard:

```
http://localhost:5050
```

### What happens on startup:

1. Flask server starts on port **5050**
2. XGBoost model loads automatically from `models/` (99.74% accuracy)
3. If no XGBoost model exists, Isolation Forest fallback is used
4. Packet capture starts automatically (or simulation mode if no root)
5. Decision engine initializes with BLOCK/FLAG/ALLOW logic
6. Telegram alerts configured (if environment variables set)
7. Real-time stats are pushed to the dashboard via WebSocket

---

## API Endpoints

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Main dashboard page |
| `GET` | `/api/status` | System status (capture, detection, uptime) |
| `GET` | `/api/packets?count=50` | Recent captured packets |
| `GET` | `/api/alerts?count=50&severity=high` | Detection alerts |
| `POST` | `/api/alerts/<id>/acknowledge` | Acknowledge an alert |
| `GET` | `/api/flows` | Active network flows |
| `GET` | `/api/stats` | Capture and detection statistics |
| `GET` | `/api/interfaces` | Available network interfaces |
| `POST` | `/api/capture/start` | Start packet capture |
| `POST` | `/api/capture/stop` | Stop packet capture |
| `GET` | `/api/ml/status` | ML detector status |
| `POST` | `/api/ml/retrain` | Force retrain ML model |

### Firewall Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/firewall/status` | Firewall status (blocked/flagged IPs, decisions) |
| `GET` | `/api/firewall/blocked` | Currently blocked IPs |
| `GET` | `/api/firewall/flagged` | Currently flagged (suspicious) IPs |
| `GET` | `/api/firewall/decisions?count=50` | Recent firewall decisions |
| `POST` | `/api/firewall/unblock/<ip>` | Manually unblock an IP |

### Example API usage:

```bash
# Check system status
curl http://localhost:5050/api/status

# Get firewall status
curl http://localhost:5050/api/firewall/status

# Get blocked IPs
curl http://localhost:5050/api/firewall/blocked

# Unblock an IP
curl -X POST http://localhost:5050/api/firewall/unblock/192.168.1.100

# Get recent alerts
curl http://localhost:5050/api/alerts?count=10&severity=critical
```

---

## Configuration

All settings are in `config.py`. Key options:

| Setting | Default | Description |
|---------|---------|-------------|
| `PORT` | 5050 | Web server port |
| `HOST` | 0.0.0.0 | Bind address |
| `DEBUG` | True | Flask debug mode |
| `CAPTURE_INTERFACE` | None (auto) | Network interface for capture |
| `PACKET_BUFFER_SIZE` | 1000 | Max packets in memory |
| `ALERT_HISTORY_SIZE` | 500 | Max alerts in memory |
| `MIN_SAMPLES_FOR_TRAINING` | 1000 | Min samples before IF auto-trains |
| `MODEL_PATH` | `./models` | Directory for saved models |

### Firewall Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `FIREWALL.block_duration` | 300 | Seconds to block an IP (5 min) |
| `FIREWALL.flag_threshold` | 3 | FLAG events before auto-BLOCK |
| `FIREWALL.min_ml_confidence` | 0.5 | Min ML confidence for decisions |

### Environment variables:

```bash
export FLASK_PORT=8080              # Change server port
export FLASK_HOST=127.0.0.1        # Bind to localhost only
export FLASK_DEBUG=False            # Disable debug mode
export CAPTURE_INTERFACE=en0        # Specify network interface
export TELEGRAM_BOT_TOKEN=xxx       # Telegram Bot token
export TELEGRAM_CHAT_ID=xxx         # Telegram chat ID
```

---

## Detection Capabilities

### Rule-Based Detection

| Attack Type | Trigger | Severity |
|-------------|---------|----------|
| **DDoS** | 200+ packets/s from same IP | Critical |
| **SYN Flood** | 100+ SYN packets/second | Critical |
| **Port Scan** | 15+ unique ports probed in 10s | High |
| **SQL Injection** | Rapid payload-bearing requests to web/DB ports | Critical |
| **Brute Force** | 10+ failed connections/min on SSH/FTP/RDP | High |
| **DNS Tunneling** | Long queries (>50 chars) or high frequency (>30/min) | High |
| **ICMP Flood** | 50+ ICMP packets/second | Medium |
| **ARP Spoofing** | Same IP with 5+ different MAC addresses | Critical |
| **Encrypted Anomaly** | Deprecated TLS versions (SSL 3.0, TLS 1.0/1.1) | Medium |

### ML-Based Detection (XGBoost)

When trained on CICIDS-2017, the model classifies traffic into **27 attack classes**:

| Category | Attack Types |
|----------|-------------|
| Benign | Normal traffic |
| DoS | DoS Hulk, DoS GoldenEye, DoS Slowloris, DoS Slowhttptest |
| DDoS | Distributed Denial of Service |
| Port Scan | Network reconnaissance |
| Brute Force | FTP-Patator, SSH-Patator |
| Web Attack | Brute Force, XSS, SQL Injection |
| Botnet | Bot traffic |
| Infiltration | Network infiltration |
| Heartbleed | OpenSSL vulnerability exploit |

---

## Decision Engine

The Decision Engine (`engine/decision_engine.py`) combines detection outputs to produce firewall actions:

| Condition | Action | Behavior |
|-----------|--------|----------|
| Rule-Based + ML both confirm attack | 🚫 **BLOCK** | IP blocked for 5 minutes |
| Rule-Based with high confidence (≥80%) | 🚫 **BLOCK** | IP blocked for 5 minutes |
| ML + Anomaly detection both flag | 🚫 **BLOCK** | IP blocked for 5 minutes |
| Any single detection engine flags | ⚠️ **FLAG** | IP marked as suspicious |
| 3+ FLAG events for same IP | 🚫 **BLOCK** | Auto-escalated to block |
| Nothing detected | ✅ **ALLOW** | Traffic passes through |

---

## Telegram Alerts

The system can send real-time notifications to Telegram for HIGH and CRITICAL severity attacks.

### Setup:

1. Create a Telegram bot via [@BotFather](https://t.me/BotFather)
2. Get the bot token and your chat ID
3. Set environment variables:

```bash
export TELEGRAM_BOT_TOKEN="your-bot-token-here"
export TELEGRAM_CHAT_ID="your-chat-id-here"
```

Alerts include: attack type, severity, source/target IPs, confidence, evidence, and timestamp.

---

## Dashboard

The web dashboard at `http://localhost:5050` provides 6 tabs:

| Tab | Description |
|-----|-------------|
| 📊 **Overview** | Stats cards, traffic timeline chart, protocol distribution |
| 📦 **Packets** | Live packet stream with search/filter |
| 🚨 **Alerts** | Alert feed with severity filters, charts, expandable evidence |
| 🔥 **Firewall** | Blocked/flagged IPs, decision log, unblock controls |
| 🔄 **Flows** | Active bidirectional network flows |
| 🧠 **Detection Engine** | ML status, training progress, active rules table |

---

## 🧪 Attacker–Victim Demo Setup

This section explains how to set up a real-world demonstration using two machines to simulate attacks and visualize real-time detection.

### 🎭 Roles

- **Victim Machine**: Runs the NetGuard IDS application (the target).
- **Attacker Machine**: Generates malicious traffic using tools like Nmap or `ping`.

### 💻 System Requirements

- **Two devices**: (Mac / Linux / Windows)
- **Network**: Both devices must be on the **same network** (e.g., same Wi-Fi network or a mobile hotspot).
- **Software (Victim)**: Python installed and NetGuard dependencies configured.
- **Software (Attacker)**: Nmap installed (for port scanning).

### 📝 Step-by-Step Instructions

#### A. Victim Setup (e.g., Windows)

1. **Navigate to the project directory**:
   ```bash
   cd path\to\4th-SEM-MAIN-EL
   ```
2. **Activate your virtual environment** (if applicable):
   ```bash
   venv\Scripts\activate
   ```
3. **Configure the interface**:
   Update `config.py` to set `CAPTURE_INTERFACE` to your active network adapter (or leave as `None` for auto-detection).
4. **Run the application**:
   ```bash
   python app.py
   ```
   *(Ensure you run as Administrator if packet capture requires it).*
5. **Open the dashboard**:
   Navigate to `http://localhost:5050` in your web browser. Note your machine's local IP address (e.g., `192.168.1.10`).

#### B. Attacker Setup (e.g., Mac / Linux)

1. **Verify connectivity**:
   Ping the victim's IP to ensure they are reachable.
   ```bash
   ping <victim_ip>
   ```
2. **Run an Nmap Port Scan**:
   Execute a stealth SYN scan targeting the first 1000 ports.
   ```bash
   nmap -Pn -sS -T4 -p 1-1000 <victim_ip>
   ```

### 🎯 Expected Results

On the Victim's NetGuard Dashboard:
- **Packets Tab**: You will see a rapid increase in captured network traffic.
- **Alerts Tab**: New alerts will appear, detecting the attack (e.g., flagged as "Port Scan").
- **Firewall Tab**: The system will log **FLAG** or **BLOCK** decisions against the attacker's IP based on the detection engine.

### 🔍 Optional Verification

- Use **Wireshark** on the Victim machine, listening on the same network interface, to confirm that the packets shown in the NetGuard dashboard match the raw traffic on the wire.

### 🛠 Troubleshooting Demo Issues

- **"Host seems down" during Nmap**: Ensure you use the `-Pn` flag in your Nmap command to skip host discovery. Check Windows Firewall on the victim to ensure it isn't completely dropping ICMP/ping.
- **No packets in Dashboard**: The two machines are not on the same network, or `CAPTURE_INTERFACE` is set to the wrong adapter.
- **Packets appear, but no alerts**: The attack traffic might not be hitting the configured detection thresholds. Review `config.py` or `rule_engine.py` settings.

### 🎬 Presentation Demo Script

Use this script for a live 5-step presentation:
1. **Show the Dashboard**: Present the empty/idle NetGuard dashboard on the Victim machine.
2. **Launch Attack**: Switch to the Attacker machine and execute the Nmap command.
3. **Show Live Traffic**: Switch back to the Victim and open the *Packets* tab to show raw traffic flowing in.
4. **Highlight Detection**: Move to the *Alerts* tab to show the "Port Scan" detection in real-time.
5. **Show Defense**: Open the *Firewall* tab to demonstrate the attacker's IP being flagged and subsequently blocked.

---

## Troubleshooting

### XGBoost import error: `libomp.dylib not found` (macOS)

```bash
brew install libomp
```

### Permission denied for packet capture

```bash
sudo python3 app.py # macOS/Linux
# On Windows, run the command prompt or terminal as Administrator
```

> Without admin/root privileges, the system automatically falls back to simulation mode.

### Windows Interface Configuration (Scapy NPF Devices)

If packet capture isn't working on Windows or you need to manually set `CAPTURE_INTERFACE` in `config.py`, note that Scapy uses device GUIDs (e.g., `\Device\NPF_{...}`) instead of friendly names like "Wi-Fi" or "Ethernet".

To find the correct interface string, open your terminal and run:
```bash
python -c "from scapy.all import show_interfaces; show_interfaces()"
```
This will display a table mapping your readable network adapters to their `\Device\NPF_{...}` names. Copy the exact NPF string for your active internet connection and set it as your `CAPTURE_INTERFACE`.

### Dataset CSV files are Git LFS pointers

```bash
python3 download_dataset.py
```

### Model not loading

```bash
ls -la models/xgboost_model.json
# Should be several MB in size. If missing:
python3 train_xgboost.py
```

### Port 5050 already in use

```bash
export FLASK_PORT=8080
python3 app.py
```

---

## Quick Start (TL;DR)

```bash
# 1. Install dependencies
pip3 install -r requirements.txt
brew install libomp    # macOS only, for XGBoost
# Windows users: Install Npcap from https://npcap.com/#download (Enable WinPcap compatible mode)

# 2. Download CICIDS-2017 dataset from Hugging Face
python3 download_dataset.py

# 3. Train the XGBoost model
python3 train_xgboost.py

# 4. (Optional) Configure Telegram alerts
export TELEGRAM_BOT_TOKEN="your-token"
export TELEGRAM_CHAT_ID="your-chat-id"

# 5. Run the application
sudo python3 app.py

# 6. Open dashboard
open http://localhost:5050
```
