# NetGuard — Smart Firewall & Intrusion Detection System
## Phase 1 Project Report

**Project Title:** NetGuard — AI-Based Smart Firewall & Intrusion Detection System for Data Center Security  
**Course:** 4th Semester — Main Experiential Learning (EL)  
**Technology Stack:** Python 3.9+, Flask, XGBoost, Scikit-learn, Scapy, WebSocket, Chart.js, Telegram Bot API  
**Dataset:** CICIDS-2017 (Canadian Institute for Cybersecurity, University of New Brunswick)  
**Date:** March 2026

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Problem Statement & Objectives](#2-problem-statement--objectives)
3. [System Architecture](#3-system-architecture)
4. [Project Structure](#4-project-structure)
5. [Technology Stack & Tools](#5-technology-stack--tools)
6. [Dataset Description — CICIDS-2017](#6-dataset-description--cicids-2017)
7. [Feature Set Used for Training (81 Features)](#7-feature-set-used-for-training-81-features)
8. [Module-wise Detailed Working](#8-module-wise-detailed-working)
9. [Machine Learning Pipeline](#9-machine-learning-pipeline)
10. [Rule-Based Detection Engine](#10-rule-based-detection-engine)
11. [Decision Engine (Firewall Logic)](#11-decision-engine-firewall-logic)
12. [Alert & Notification System](#12-alert--notification-system)
13. [Web Dashboard](#13-web-dashboard)
14. [Training Results & Model Performance](#14-training-results--model-performance)
15. [Execution Flow](#15-execution-flow)
16. [API Endpoints](#16-api-endpoints)
17. [Configuration & Thresholds](#17-configuration--thresholds)
18. [Conclusion](#18-conclusion)
19. [Future Enhancements](#19-future-enhancements)

---

## 1. Introduction

With the exponential growth of internet-connected devices and cloud-based data centers, network security has become a critical challenge. Traditional signature-based firewalls and intrusion detection systems (IDS) are limited to detecting only known attack patterns and fail to identify novel, zero-day, or evolving threats.

**NetGuard** addresses this gap by implementing a **hybrid AI-based Smart Firewall and Intrusion Detection System** that combines:
- **Rule-based detection** for fast identification of known attack signatures
- **Machine Learning (XGBoost)** for intelligent classification of network traffic into 27 attack categories
- **Anomaly detection (Isolation Forest)** for identifying unknown/zero-day threats
- **Automated firewall response** (BLOCK / FLAG / ALLOW) with real-time alerting

The system captures live network packets, analyzes them through multiple detection engines simultaneously, makes intelligent firewall decisions, and provides administrators with a real-time monitoring dashboard and Telegram notifications.

---

## 2. Problem Statement & Objectives

### 2.1 Problem Statement

Traditional network security systems rely on static rule sets and signature databases that must be manually updated. They cannot detect previously unknown attack patterns, generate excessive false positives, and lack automated response capabilities. Modern data centers need an intelligent, adaptive security system that can detect both known and unknown threats in real-time and respond autonomously.

### 2.2 Objectives

1. Capture and analyze live network packets in real-time using Scapy
2. Detect 9 known attack patterns using rule-based analysis (DDoS, SQL Injection, Port Scan, SYN Flood, Brute Force, DNS Tunneling, ICMP Flood, ARP Spoofing, Encrypted Anomaly)
3. Classify network traffic into benign or 27 specific attack types using an XGBoost ML model trained on the CICIDS-2017 dataset with 99.74% accuracy
4. Detect anomalous traffic using Isolation Forest unsupervised learning as a fallback
5. Make intelligent firewall decisions (BLOCK / FLAG / ALLOW) using a hybrid Decision Engine
6. Automatically block confirmed threats and auto-escalate suspicious activity
7. Send real-time Telegram alerts for HIGH and CRITICAL severity attacks
8. Provide a 6-tab real-time web dashboard with Chart.js visualizations and WebSocket live updates

### 2.3 Scope

| Category | Attack Types Covered |
|----------|---------------------|
| Volumetric Attacks | DDoS, SYN Flood, ICMP Flood |
| Reconnaissance | Port Scanning |
| Brute Force | SSH-Patator, FTP-Patator, Web Brute Force |
| Web Attacks | SQL Injection, XSS |
| Data Exfiltration | DNS Tunneling |
| Man-in-the-Middle | ARP Spoofing |
| Malware | Botnet Activity |
| Advanced Threats | Network Infiltration, Heartbleed Exploit |
| Encryption Issues | Deprecated TLS/SSL versions |

---

## 3. System Architecture

### 3.1 High-Level Architecture Diagram

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
│  │   Analyzer    │─────────────────────────▶│  │ (9 rules)│        │    │
│  └──────────────┘                           │  └──────────┘        │    │
│                                             │  ┌──────────┐        │    │
│                                             │  │ XGBoost  │        │    │
│                                             │  │ (99.74%) │        │    │
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

### 3.2 Data Flow Pipeline

```
Packet Captured (Scapy)
    │
    ▼
Feature Extraction (extract packet metadata)
    │
    ▼
Flow Analyzer (group into bidirectional flows, compute 27 flow features)
    │
    ├──▶ Rule-Based Engine (9 pattern detectors)
    │
    ├──▶ ML Engine (XGBoost: 81 features → 27 classes)
    │
    ▼
Decision Engine (BLOCK / FLAG / ALLOW)
    │
    ├──▶ IP Blocking (5-min block, auto-escalation after 3 flags)
    ├──▶ Telegram Alert (for HIGH/CRITICAL)
    ├──▶ WebSocket Push (real-time dashboard update)
    └──▶ Alert Log (stored for API retrieval)
```

---

## 4. Project Structure

```
4th-SEM-MAIN-EL/
├── app.py                         # Flask entry point — server, API, WebSocket
├── config.py                      # All configuration: rules, thresholds, firewall, Telegram
├── requirements.txt               # Python dependencies (10 packages)
├── train_xgboost.py               # XGBoost model training pipeline
├── download_dataset.py            # CICIDS-2017 dataset download from Hugging Face
├── README.md                      # Project documentation
├── REPORT.md                      # Detailed project report
├── PHASE1_REPORT.md               # This file
│
├── engine/                        # Core engine modules
│   ├── __init__.py
│   ├── packet_capture.py          # Scapy packet capture + simulation fallback
│   ├── feature_extraction.py      # Centralized feature extraction
│   ├── flow_analyzer.py           # Bidirectional flow tracking & feature computation
│   └── decision_engine.py         # BLOCK / FLAG / ALLOW firewall logic
│
├── detection/                     # Detection engines
│   ├── __init__.py
│   ├── rule_engine.py             # 9 rule-based detectors with evidence generation
│   ├── ml_detector.py             # XGBoost (primary) + Isolation Forest (fallback)
│   └── hybrid_detector.py         # Alert correlation + pipeline orchestration
│
├── alerts/                        # Notification modules
│   ├── __init__.py
│   └── telegram_alert.py          # Telegram Bot API notifications
│
├── dataset/                       # CICIDS-2017 CSV files (~2.8M rows)
│   ├── monday.csv                 # Benign baseline traffic
│   ├── tuesday.csv                # FTP-Patator, SSH-Patator
│   ├── wednesday.csv              # DoS GoldenEye, DoS Hulk, Slowloris, Slowhttptest, Heartbleed
│   ├── thursday.csv               # Web Attacks (Brute Force, XSS, SQLi), Infiltration
│   └── friday.csv                 # Botnet, Port Scan, DDoS
│
├── models/                        # Trained ML model artifacts
│   ├── xgboost_model.json         # Trained XGBoost classifier (5.8 MB)
│   ├── xgb_scaler.pkl             # StandardScaler for feature normalization
│   ├── xgb_label_encoder.pkl      # LabelEncoder (27 classes)
│   ├── xgb_feature_names.pkl      # Ordered list of 81 feature column names
│   ├── xgb_metadata.pkl           # Training metadata (accuracy, params, timestamp)
│   ├── isolation_forest.pkl       # Fallback Isolation Forest model
│   └── scaler.pkl                 # Fallback scaler
│
├── templates/
│   └── index.html                 # 6-tab dashboard HTML with Chart.js
│
└── static/
    ├── css/dashboard.css          # Premium dark theme stylesheet
    └── js/dashboard.js            # Real-time dashboard logic + WebSocket handlers
```

---

## 5. Technology Stack & Tools

| Technology | Version | Purpose |
|------------|---------|---------|
| **Python** | 3.9+ | Core programming language |
| **Flask** | ≥2.3.0 | Web framework for REST API and HTML serving |
| **Flask-SocketIO** | ≥5.3.0 | Real-time bidirectional WebSocket communication |
| **Scapy** | ≥2.5.0 | Raw network packet capture, dissection, and metadata extraction |
| **XGBoost** | ≥1.7.0 | Gradient boosted tree classifier — primary ML model (99.74% accuracy) |
| **Scikit-learn** | ≥1.3.0 | StandardScaler, LabelEncoder, Isolation Forest, evaluation metrics |
| **Pandas** | ≥2.0.0 | Dataset loading, cleaning, manipulation, feature engineering |
| **NumPy** | ≥1.24.0 | Numerical computations, array operations |
| **Joblib** | ≥1.3.0 | Model serialization — save/load `.pkl` files |
| **Eventlet** | ≥0.33.0 | Async server backend for Flask-SocketIO |
| **Hugging Face Hub** | ≥0.20.0 | Automated dataset download from Hugging Face |
| **Telegram Bot API** | — | Real-time push notifications via HTTP |
| **Chart.js** | 4.x | Dashboard charts — traffic timeline, protocol distribution, severity charts |
| **Socket.IO Client** | 4.7 | Client-side WebSocket for real-time dashboard updates |
| **HTML5 / CSS3 / JS** | — | 6-tab dashboard front-end with premium dark theme |

### 5.1 Why These Tools?

| Choice | Rationale |
|--------|-----------|
| **XGBoost** over Deep Learning | Faster training, interpretable feature importances, excellent accuracy on tabular data, lower resource requirements |
| **Scapy** over libpcap | Python-native, deep packet dissection, protocol-aware, simulation fallback support |
| **Flask** over Django | Lightweight, minimal overhead, ideal for real-time WebSocket + REST API |
| **Isolation Forest** as fallback | Unsupervised — no labels needed, learns "normal" from live traffic, catches zero-day attacks |
| **CICIDS-2017** dataset | Industry-standard benchmark, 2.8M labeled samples, 15+ attack categories, realistic traffic |

---

## 6. Dataset Description — CICIDS-2017

| Property | Details |
|----------|---------|
| **Full Name** | Canadian Institute for Cybersecurity Intrusion Detection Dataset 2017 |
| **Source** | University of New Brunswick (hosted on Hugging Face) |
| **Collection Period** | Monday to Friday (5 days of network traffic) |
| **Total Records** | ~2,830,743 network flow records |
| **Feature Extraction Tool** | CICFlowMeter |
| **Total Columns** | 89 (81 features + 6 identifiers + Label + Attempted Category) |
| **Benign Samples** | ~2,273,097 (80.3%) |
| **Attack Samples** | ~557,646 (19.7%) |

### 6.1 Daily Attack Schedule

| Day | Traffic Type | Attack Categories |
|-----|-------------|-------------------|
| **Monday** | Benign only | Normal activity baseline |
| **Tuesday** | Benign + Attacks | FTP-Patator, SSH-Patator (brute force) |
| **Wednesday** | Benign + Attacks | DoS GoldenEye, DoS Hulk, DoS Slowhttptest, DoS Slowloris, Heartbleed |
| **Thursday** | Benign + Attacks | Web Attack — Brute Force, Web Attack — XSS, Web Attack — SQL Injection, Infiltration |
| **Friday** | Benign + Attacks | Botnet, Port Scan, DDoS |

### 6.2 Column Categories in Dataset

| Category | Columns | Used For |
|----------|---------|----------|
| **Identifiers** (excluded) | Src IP dec, Dst IP dec, Src Port, Dst Port, Protocol, Timestamp | Not used in training — these are metadata |
| **Features** (81 columns) | Flow Duration, Packet Lengths, IAT stats, Flag counts, etc. | Input features for XGBoost model |
| **Target** (excluded) | Label, Attempted Category | Label = prediction target; Attempted Category = subcategory |

---

## 7. Feature Set Used for Training (81 Features)

The XGBoost model is trained on exactly **81 numerical features** extracted from network flows:

### 7.1 Flow-Level Basics (5 features)

| # | Feature Name | Description |
|---|-------------|-------------|
| 1 | Flow Duration | Total duration of the network flow (microseconds) |
| 2 | Total Fwd Packet | Count of packets in forward direction |
| 3 | Total Bwd packets | Count of packets in backward direction |
| 4 | Total Length of Fwd Packet | Total bytes sent in forward direction |
| 5 | Total Length of Bwd Packet | Total bytes sent in backward direction |

### 7.2 Packet Length Statistics (8 features)

| # | Feature Name | Description |
|---|-------------|-------------|
| 6 | Fwd Packet Length Max | Maximum forward packet size |
| 7 | Fwd Packet Length Min | Minimum forward packet size |
| 8 | Fwd Packet Length Mean | Average forward packet size |
| 9 | Fwd Packet Length Std | Standard deviation of forward packet sizes |
| 10 | Bwd Packet Length Max | Maximum backward packet size |
| 11 | Bwd Packet Length Min | Minimum backward packet size |
| 12 | Bwd Packet Length Mean | Average backward packet size |
| 13 | Bwd Packet Length Std | Standard deviation of backward packet sizes |

### 7.3 Flow Rate (2 features)

| # | Feature Name | Description |
|---|-------------|-------------|
| 14 | Flow Bytes/s | Bytes transferred per second |
| 15 | Flow Packets/s | Packets transferred per second |

### 7.4 Inter-Arrival Time — IAT (14 features)

| # | Feature Name | Description |
|---|-------------|-------------|
| 16–19 | Flow IAT Mean / Std / Max / Min | Time gap between consecutive packets (both directions) |
| 20–24 | Fwd IAT Total / Mean / Std / Max / Min | Forward direction inter-arrival times |
| 25–29 | Bwd IAT Total / Mean / Std / Max / Min | Backward direction inter-arrival times |

### 7.5 TCP Flag Features (14 features)

| # | Feature Name | Description |
|---|-------------|-------------|
| 30–31 | Fwd PSH Flags / Bwd PSH Flags | Push flag counts per direction |
| 32–33 | Fwd URG Flags / Bwd URG Flags | Urgent flag counts per direction |
| 34–35 | Fwd RST Flags / Bwd RST Flags | Reset flag counts per direction |
| 36–37 | Fwd Header Length / Bwd Header Length | Header sizes per direction |
| 45–52 | FIN / SYN / RST / PSH / ACK / URG / CWR / ECE Flag Count | Total TCP flag counts for the flow |

### 7.6 Packet Rate & Length Stats (7 features)

| # | Feature Name | Description |
|---|-------------|-------------|
| 38–39 | Fwd Packets/s / Bwd Packets/s | Packets per second per direction |
| 40–44 | Packet Length Min / Max / Mean / Std / Variance | Overall packet size distribution |

### 7.7 Ratios & Averages (4 features)

| # | Feature Name | Description |
|---|-------------|-------------|
| 53 | Down/Up Ratio | Download vs upload ratio |
| 54 | Average Packet Size | Mean packet size across both directions |
| 55 | Fwd Segment Size Avg | Average forward segment size |
| 56 | Bwd Segment Size Avg | Average backward segment size |

### 7.8 Bulk Transfer Features (6 features)

| # | Feature Name | Description |
|---|-------------|-------------|
| 57–59 | Fwd Bytes/Packet/Rate Bulk Avg | Forward bulk transfer averages |
| 60–62 | Bwd Bytes/Packet/Rate Bulk Avg | Backward bulk transfer averages |

### 7.9 Subflow Features (4 features)

| # | Feature Name | Description |
|---|-------------|-------------|
| 63–64 | Subflow Fwd Packets / Subflow Fwd Bytes | Forward subflow metrics |
| 65–66 | Subflow Bwd Packets / Subflow Bwd Bytes | Backward subflow metrics |

### 7.10 TCP Window, Activity & Idle (12 features)

| # | Feature Name | Description |
|---|-------------|-------------|
| 67–68 | FWD Init Win Bytes / Bwd Init Win Bytes | Initial TCP window sizes |
| 69 | Fwd Act Data Pkts | Forward packets containing actual data |
| 70 | Fwd Seg Size Min | Minimum forward segment size |
| 71–74 | Active Mean / Std / Max / Min | Time the flow was actively transmitting |
| 75–78 | Idle Mean / Std / Max / Min | Time the flow was idle |

### 7.11 Protocol-Specific (3 features)

| # | Feature Name | Description |
|---|-------------|-------------|
| 79 | ICMP Code | ICMP message code (0 for non-ICMP) |
| 80 | ICMP Type | ICMP message type (0 for non-ICMP) |
| 81 | Total TCP Flow Time | Total TCP connection duration |

### 7.12 Columns Excluded from Training

| Excluded Column | Reason |
|----------------|--------|
| Src IP dec | Source IP is an identifier, not a learnable feature |
| Dst IP dec | Destination IP is an identifier |
| Src Port | Source port is mostly ephemeral (random) |
| Dst Port | Destination port is an identifier |
| Protocol | Categorical identifier (handled implicitly by flow features) |
| Timestamp | Time metadata, not relevant for pattern detection |
| Label | This is the **target variable** — what the model predicts |
| Attempted Category | Target metadata — subcategory of attack |

---

## 8. Module-wise Detailed Working

### 8.1 Packet Capture Engine (`engine/packet_capture.py`)

**Purpose:** Entry point of the data pipeline — captures raw network packets.

**How it works:**
1. Uses **Scapy** library to sniff raw packets from the network interface
2. Runs in a dedicated background thread (`PacketCaptureThread`)
3. Extracts structured metadata into a `PacketInfo` object containing 22 fields:
   - Layer 2 (Ethernet): Source/destination MAC addresses
   - Layer 3 (IP): Source/destination IP, TTL, header length, fragment offset
   - Layer 4 (TCP/UDP): Ports, TCP flags (SYN, ACK, FIN, RST, PSH, URG), window size
   - Application: DNS queries/responses, ICMP types, ARP operations
   - Encryption: TLS version detection (SSL 3.0, TLS 1.0–1.3)
4. Maintains a circular buffer of 1,000 recent packets
5. Calculates real-time rates: packets/second, bytes/second
6. **Simulation fallback**: When root privileges are unavailable, generates realistic synthetic traffic including periodic attack patterns (port scans, SYN floods, DNS tunneling)

**Key design decision:** Metadata-only analysis — no payload inspection, preserving privacy.

### 8.2 Flow Analyzer (`engine/flow_analyzer.py`)

**Purpose:** Groups individual packets into bidirectional flows and computes flow-level features.

**How it works:**
1. Generates a bidirectional flow ID: `sorted(src_ip:port, dst_ip:port) + protocol`
2. For each flow, tracks and computes 27 features in real-time:
   - Basic: duration, packet count, total bytes
   - Directional: forward/backward packets and bytes
   - Packet size: avg, min, max
   - TCP flags: SYN, FIN, RST, ACK, PSH, URG counts
   - Ratios: forward/backward packet ratio, byte ratio
   - Timing: average and std deviation of inter-arrival times
   - Payload: average and std deviation of payload sizes
   - Other: encryption flag, unique destination ports, DNS query count
3. Expired flows (inactive >120 seconds) are archived automatically
4. Flow feature dictionaries are passed to the ML detection engine

### 8.3 Feature Extraction (`engine/feature_extraction.py`)

**Purpose:** Centralized feature computation ensuring consistency between training and inference.

- Extracts packet-level features from individual packets
- Extracts flow-level features from bidirectional flows
- Maintains per-IP packet rate tracking
- Periodic cleanup of stale entries to prevent memory leaks

### 8.4 Rule-Based Detection Engine (`detection/rule_engine.py`)

(See Section 10 for detailed rule specifications)

### 8.5 ML Detection Engine (`detection/ml_detector.py`)

(See Section 9 for detailed ML pipeline)

### 8.6 Hybrid Detector (`detection/hybrid_detector.py`)

**Purpose:** Orchestrates all detection engines and correlates alerts.

**Processing pipeline for each packet:**
1. Extract features → 2. Update flow → 3. Run rule checks → 4. Run XGBoost prediction → 5. Decision Engine → 6. Telegram alert → 7. WebSocket push

**Alert correlation logic:**
- When ML flags an IP that was also flagged by rules within 30 seconds, confidence is boosted by +15%
- Corroborated alerts are tracked separately for statistics

### 8.7 Decision Engine (`engine/decision_engine.py`)

(See Section 11 for detailed decision logic)

---

## 9. Machine Learning Pipeline

### 9.1 XGBoost Classifier (Primary Model)

**What is XGBoost?**
XGBoost (eXtreme Gradient Boosting) is an optimized implementation of gradient boosted decision trees. It builds an ensemble of weak decision trees sequentially, where each new tree corrects errors made by previous trees.

**Why XGBoost?**
- 99.74% accuracy on CICIDS-2017 dataset
- Built-in L1/L2 regularization (prevents overfitting)
- Handles missing values natively
- Parallel processing for fast training
- Provides feature importance rankings
- Excellent performance on tabular/structured data

### 9.2 Training Pipeline (`train_xgboost.py`)

```
Step 1: Load 5 CSV files from dataset/ (~2.8M rows)
Step 2: Clean data — strip whitespace, handle inf/NaN, remove duplicates
Step 3: Select exactly 81 feature columns (FEATURE_COLUMNS list)
Step 4: Balance classes — downsample BENIGN to max 100,000 samples
Step 5: Encode labels — LabelEncoder maps 27 class names to integers
Step 6: Split — 80% training, 20% testing (stratified sampling)
Step 7: Scale — StandardScaler (zero mean, unit variance)
Step 8: Train — XGBoost with 200 trees, max depth 8
Step 9: Evaluate — accuracy, F1-score, per-class classification report
Step 10: Save — model (JSON), scaler, encoder, feature names, metadata
```

### 9.3 XGBoost Hyperparameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `n_estimators` | 200 | Number of boosting rounds (trees) |
| `max_depth` | 8 | Maximum depth of each decision tree |
| `learning_rate` | 0.1 | Step size shrinkage to prevent overfitting |
| `subsample` | 0.8 | Fraction of training rows sampled per tree |
| `colsample_bytree` | 0.8 | Fraction of features sampled per tree |
| `min_child_weight` | 5 | Minimum sum of instance weights in a child node |
| `gamma` | 0.1 | Minimum loss reduction required for a split |
| `reg_alpha` | 0.1 | L1 regularization (lasso) |
| `reg_lambda` | 1.0 | L2 regularization (ridge) |
| `objective` | `multi:softprob` | Multi-class classification with probability output |
| `eval_metric` | `mlogloss` | Multi-class log loss |

### 9.4 Isolation Forest (Fallback Model)

When no XGBoost model is available:
1. Collects flow features from live traffic
2. After 1,000 samples, auto-trains an Isolation Forest (100 estimators, 5% contamination)
3. Flags flows with high anomaly scores as suspicious
4. Periodically retrains with new data (every 200 new samples)

### 9.5 Live Inference — Feature Mapping

Live flow features are mapped to the exact 81 CICIDS-2017 column names:

| Live Flow Feature | → CICIDS-2017 Column |
|-------------------|---------------------|
| `duration` | `Flow Duration` |
| `fwd_packets` | `Total Fwd Packet` |
| `bwd_packets` | `Total Bwd packets` |
| `fwd_bytes` | `Total Length of Fwd Packet` |
| `bwd_bytes` | `Total Length of Bwd Packet` |
| `avg_packet_size` | `Average Packet Size` |
| `syn_count` | `SYN Flag Count` |
| `avg_inter_arrival` | `Flow IAT Mean` |
| `packets_per_second` | `Fwd Packets/s` |
| *(and 72 more mappings)* | *(corresponding CICIDS columns)* |

Features present in CICIDS-2017 but not available from live capture are filled with zeros.

---

## 10. Rule-Based Detection Engine

The rule engine provides fast, deterministic detection of 9 known attack patterns:

| # | Attack Type | Detection Logic | Threshold | Severity | Cooldown |
|---|------------|----------------|-----------|----------|----------|
| 1 | **DDoS** | Packet rate from same source IP exceeds threshold | 200 pkts/s or 10 MB/s | Critical | 15s |
| 2 | **SYN Flood** | SYN-only packets targeting single IP | 100 SYN/s in 5s window | Critical | 15s |
| 3 | **Port Scan** | Unique destination ports probed by single source | 15 ports in 10s | High | 15s |
| 4 | **SQL Injection** | Rapid payload-bearing requests to web/DB ports | 20 requests in 60s to ports 80,443,3306,5432,8080,8443 | Critical | 15s |
| 5 | **Brute Force** | Repeated SYN/RST connections to auth services | 10 attempts/min on SSH(22), FTP(21), RDP(3389) | High | 15s |
| 6 | **DNS Tunneling** | Long DNS queries or high-frequency queries | >50 chars or >30/min to same domain | High | 15s |
| 7 | **ICMP Flood** | Volumetric ICMP traffic to single target | 50 ICMP/s in 5s window | Medium | 15s |
| 8 | **ARP Spoofing** | Same IP mapped to multiple MAC addresses | 5+ different MACs for one IP | Critical | 15s |
| 9 | **Encrypted Anomaly** | Deprecated TLS/SSL versions detected | SSL 3.0, TLS 1.0, or TLS 1.1 | Medium | 15s |

Each alert includes: type, severity, source/destination IP, human-readable description, evidence list, and confidence score (0.0–1.0).

---

## 11. Decision Engine (Firewall Logic)

### 11.1 Decision Rules

| Priority | Condition | Action | Behavior |
|----------|-----------|--------|----------|
| 1 | IP already blocked | 🚫 BLOCK | Traffic denied (existing block) |
| 2 | Rule-Based + ML both confirm attack | 🚫 BLOCK | IP blocked for 5 minutes, confidence boosted +15% |
| 3 | Rule-Based with ≥80% confidence | 🚫 BLOCK | IP blocked for 5 minutes |
| 4 | ML + Anomaly detection both flag | 🚫 BLOCK | IP blocked for 5 minutes |
| 5 | Any single engine flags | ⚠️ FLAG | IP marked as suspicious |
| 6 | Same IP flagged 3+ times | 🚫 BLOCK | Auto-escalated from FLAG to BLOCK |
| 7 | Nothing detected | ✅ ALLOW | Traffic passes normally |

### 11.2 IP Management

| Feature | Default | Description |
|---------|---------|-------------|
| Block Duration | 300 seconds (5 min) | How long a blocked IP stays blocked |
| Flag Threshold | 3 | Number of FLAG events before auto-BLOCK |
| Min ML Confidence | 0.5 | Minimum ML confidence to consider a detection |
| Block Expiry | Automatic | Blocked IPs auto-expire after duration |
| Manual Unblock | Via API/Dashboard | Administrators can unblock IPs manually |

---

## 12. Alert & Notification System

### 12.1 Telegram Alerts

- Monitors all alerts for HIGH and CRITICAL severity
- Formats HTML messages with: attack type, severity, source/target IPs, detection method, confidence, evidence, timestamp
- Rate limited: max 20 alerts/minute, per-type cooldown of 60 seconds
- Special notifications for firewall BLOCK actions

### 12.2 Severity Classification

| Severity | Criteria |
|----------|----------|
| **Critical** | DDoS, DoS variants, Heartbleed with confidence >70% |
| **High** | Brute Force, Botnet, Infiltration, Web Attacks, or any with confidence >80% |
| **Medium** | Attacks with 50–80% confidence |
| **Low** | Attacks with <50% confidence |

---

## 13. Web Dashboard

The dashboard at `http://localhost:5050` provides 6 tabs:

| Tab | Content |
|-----|---------|
| 📊 **Overview** | 8 stats cards, traffic timeline chart, protocol distribution doughnut chart |
| 📦 **Packets** | Live packet stream with search/filter — Time, Src/Dst IP, Port, Protocol, Length, Flags |
| 🚨 **Alerts** | Alert cards with severity badges, expandable evidence, acknowledge button, severity chart |
| 🔥 **Firewall** | Blocked/flagged IP lists, decision log, manual unblock controls |
| 🔄 **Flows** | Active bidirectional flow table — Source, Destination, Packets, Bytes, Duration |
| 🧠 **Detection** | ML model status, training progress, anomalies count, active rules table |

**Real-time updates via 3 channels:**
1. WebSocket push — packets, alerts, firewall decisions (instant)
2. Periodic stats broadcast — every 2 seconds to all clients
3. REST API polling — firewall status every 3 seconds

---

## 14. Training Results & Model Performance

### 14.1 Overall Metrics

| Metric | Value |
|--------|-------|
| **Accuracy** | 99.74% |
| **F1 Score (Weighted)** | 0.9973 |
| **F1 Score (Macro)** | 0.8930 |
| **Training Time** | 176.2 seconds |
| **Total Pipeline Time** | 192.6 seconds |
| **Training Samples** | ~332,930 (after balancing) |
| **Test Samples** | ~66,586 |
| **Number of Classes** | 27 |
| **Number of Features** | 81 |
| **Model File Size** | 5.8 MB |

### 14.2 Per-Class Performance (Selected)

| Class | Precision | Recall | F1-Score | Support |
|-------|-----------|--------|----------|---------|
| BENIGN | 0.9993 | 0.9991 | 0.9992 | 20,000 |
| DDoS | 1.0000 | 1.0000 | 1.0000 | 19,029 |
| DoS Hulk | 1.0000 | 1.0000 | 1.0000 | 20,000 |
| DoS GoldenEye | 1.0000 | 0.9980 | 0.9990 | 1,513 |
| DoS Slowloris | 0.9987 | 1.0000 | 0.9994 | 772 |
| FTP-Patator | 1.0000 | 1.0000 | 1.0000 | 794 |
| SSH-Patator | 1.0000 | 0.9983 | 0.9992 | 592 |
| Portscan | 0.9912 | 1.0000 | 0.9956 | 337 |
| Botnet | 1.0000 | 1.0000 | 1.0000 | 147 |
| Heartbleed | 1.0000 | 1.0000 | 1.0000 | 2 |

### 14.3 Top 15 Most Important Features

| Rank | Feature | Importance |
|------|---------|------------|
| 1 | Fwd Segment Size Avg | 0.4074 |
| 2 | Bwd Packet Length Std | 0.1098 |
| 3 | Bwd Segment Size Avg | 0.1082 |
| 4 | Fwd Packet Length Mean | 0.0599 |
| 5 | Packet Length Std | 0.0505 |
| 6 | Fwd Packet Length Max | 0.0415 |
| 7 | Packet Length Variance | 0.0275 |
| 8 | Fwd PSH Flags | 0.0163 |
| 9 | Total Length of Fwd Packet | 0.0162 |
| 10 | Fwd RST Flags | 0.0134 |
| 11 | Total Length of Bwd Packet | 0.0129 |
| 12 | Down/Up Ratio | 0.0126 |
| 13 | Bwd RST Flags | 0.0111 |
| 14 | Bwd IAT Std | 0.0109 |
| 15 | Bwd Packet Length Mean | 0.0091 |

### 14.4 Model Artifacts Saved

| File | Size | Contents |
|------|------|----------|
| `xgboost_model.json` | 5.8 MB | Trained XGBoost classifier (200 trees, 27 classes) |
| `xgb_scaler.pkl` | 4.2 KB | StandardScaler fitted on training features |
| `xgb_label_encoder.pkl` | 1.0 KB | LabelEncoder mapping 27 class names ↔ integers |
| `xgb_feature_names.pkl` | 1.5 KB | Ordered list of 81 feature column names |
| `xgb_metadata.pkl` | 1.1 KB | Training metadata (accuracy, F1, params, timestamp) |

---

## 15. Execution Flow

### 15.1 Training Phase

```bash
# Step 1: Install dependencies
pip3 install -r requirements.txt
brew install libomp    # macOS only, for XGBoost

# Step 2: Download CICIDS-2017 dataset from Hugging Face
python3 download_dataset.py

# Step 3: Train the XGBoost model (81 features, 27 classes)
python3 train_xgboost.py
# Output: 99.74% accuracy, model saved to models/
```

### 15.2 Detection Phase

```bash
# Step 1: Start the application
sudo python3 app.py     # With live capture (needs root)
python3 app.py           # Without root (simulation mode)

# Step 2: System initializes:
#   → Load XGBoost model (99.74% accuracy)
#   → Initialize Decision Engine + Telegram Alerter
#   → Start packet capture
#   → Start Flask server on port 5050

# Step 3: Open dashboard
open http://localhost:5050
```

---

## 16. API Endpoints

### Core Endpoints (12)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Main dashboard page |
| GET | `/api/status` | System status (capture, detection, uptime) |
| GET | `/api/packets?count=50` | Recent captured packets |
| GET | `/api/alerts?count=50&severity=high` | Detection alerts |
| POST | `/api/alerts/<id>/acknowledge` | Acknowledge an alert |
| GET | `/api/flows` | Active network flows |
| GET | `/api/stats` | Capture and detection statistics |
| GET | `/api/interfaces` | Available network interfaces |
| POST | `/api/capture/start` | Start packet capture |
| POST | `/api/capture/stop` | Stop packet capture |
| GET | `/api/ml/status` | ML detector status |
| POST | `/api/ml/retrain` | Force retrain ML model |

### Firewall Endpoints (5)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/firewall/status` | Firewall status (blocked/flagged IPs, decisions) |
| GET | `/api/firewall/blocked` | Currently blocked IPs |
| GET | `/api/firewall/flagged` | Currently flagged (suspicious) IPs |
| GET | `/api/firewall/decisions?count=50` | Recent firewall decisions |
| POST | `/api/firewall/unblock/<ip>` | Manually unblock an IP |

---

## 17. Configuration & Thresholds

All settings are in `config.py`:

### Server Settings

| Setting | Default | Description |
|---------|---------|-------------|
| PORT | 5050 | Web server port |
| HOST | 0.0.0.0 | Bind address |
| DEBUG | True | Flask debug mode |

### Detection Settings

| Setting | Default | Description |
|---------|---------|-------------|
| PACKET_BUFFER_SIZE | 1,000 | Max packets in memory |
| ALERT_HISTORY_SIZE | 500 | Max alerts in memory |
| MIN_SAMPLES_FOR_TRAINING | 1,000 | Min samples before Isolation Forest trains |
| FLOW_TIMEOUT | 120s | Inactive flow expiry |

### Firewall Settings

| Setting | Default | Description |
|---------|---------|-------------|
| block_duration | 300s (5 min) | How long to block an IP |
| flag_threshold | 3 | FLAGS before auto-BLOCK |
| min_ml_confidence | 0.5 | Minimum ML confidence for decisions |

---

## 18. Conclusion

NetGuard demonstrates a practical, production-oriented approach to data center network security by combining:

1. **Rule-based detection** — Fast, deterministic identification of 9 known attack signatures with configurable thresholds and evidence generation
2. **XGBoost machine learning** — Classification of network traffic into 27 attack classes with 99.74% accuracy, trained on 81 features from the CICIDS-2017 benchmark dataset
3. **Isolation Forest anomaly detection** — Fallback unsupervised model for zero-day threat detection
4. **Smart Firewall Decision Engine** — Autonomous BLOCK/FLAG/ALLOW decisions with hybrid confidence boosting, auto-escalation, and timed IP blocking
5. **Real-time alerting** — Telegram push notifications for critical threats with rate limiting
6. **Alert correlation** — Cross-engine validation (Rule + ML) to reduce false positives by +15% confidence boost on corroborated detections
7. **Live monitoring dashboard** — 6-tab web UI with WebSocket real-time updates, Chart.js visualizations, and manual IP management

The hybrid architecture ensures detection of both known patterns (via rules) and complex multi-feature attack signatures (via ML) that would be difficult to express as simple rules. The Decision Engine adds active response capability, transforming the IDS into a full IDS/IPS (Intrusion Prevention System).

---

## 19. Future Enhancements

1. **OS-Level Blocking** — `iptables`/`nftables` integration for kernel-level packet filtering
2. **Deep Learning Models** — LSTM/Transformer for temporal pattern detection
3. **Online Learning** — Continuously update XGBoost with labeled live traffic
4. **PCAP Replay** — Import and analyze PCAP capture files
5. **Multi-Interface Capture** — Monitor multiple network interfaces simultaneously
6. **SIEM Integration** — Export alerts to Splunk/ELK Stack via syslog
7. **User Authentication** — Login and role-based access control for dashboard
8. **Geo-IP Mapping** — Visualize attack origins on a world map
9. **Threat Intelligence Feeds** — Integrate with known-bad-IP databases

---

*Report generated: March 2026*  
*NetGuard v2.0 — Smart Firewall & Intrusion Detection System*
