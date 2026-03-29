# 🔥 NetGuard – Project Report
## Smart Firewall & Intrusion Detection System for Data Center Security

**Project Name:** NetGuard – Smart Firewall & Intrusion Detection System  
**Technology Stack:** Python, Flask, XGBoost, Scikit-learn, Scapy, WebSocket, Telegram Bot API  
**Dataset:** CICIDS-2017 (Canadian Institute for Cybersecurity)  
**Date:** March 2026

---

## 1. Introduction

### 1.1 Problem Statement

With the rapid growth of internet-connected devices and cloud-based data centers, network security has become a critical concern. Traditional signature-based intrusion detection systems (IDS) are limited to detecting only known attack patterns and fail to identify novel or evolving threats. Modern data centers require an intelligent system that not only detects threats but actively responds to them — blocking malicious traffic, flagging suspicious behavior, and alerting administrators in real-time.

### 1.2 Objective

The objective of this project is to design and implement **NetGuard**, a hybrid **Smart Firewall and Intrusion Detection System (IDS)** that:

1. Captures and analyzes live network packets in real-time
2. Detects known attack patterns using rule-based analysis (DDoS, SQL Injection, Port Scan, Brute Force, etc.)
3. Classifies network traffic into benign or specific attack types using an **XGBoost** machine learning model trained on the **CICIDS-2017** dataset (99.7% accuracy)
4. Detects anomalous traffic using **Isolation Forest** unsupervised learning
5. Makes intelligent firewall decisions (**BLOCK / FLAG / ALLOW**) using a hybrid Decision Engine
6. Automatically blocks confirmed threats and escalates suspicious activity
7. Sends real-time **Telegram alerts** for HIGH and CRITICAL severity attacks
8. Provides a real-time web dashboard with 6 tabs for comprehensive monitoring

### 1.3 Scope

The system covers detection and response for the following attack categories:

- **Volumetric Attacks:** DDoS, SYN Flood, ICMP Flood
- **Reconnaissance:** Port Scanning
- **Brute Force Attacks:** SSH-Patator, FTP-Patator
- **Web Attacks:** SQL Injection, XSS, Web Brute Force
- **Data Exfiltration:** DNS Tunneling
- **Man-in-the-Middle:** ARP Spoofing
- **Botnet Activity**
- **Network Infiltration**
- **Heartbleed Exploit**
- **Encrypted Traffic Anomalies**

---

## 2. System Architecture

### 2.1 High-Level Architecture

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
│                                             │  │ (99.7%)  │        │    │
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

### 2.2 Module Breakdown

The project is organized into the following modules:

| Module | File(s) | Responsibility |
|--------|---------|----------------|
| **Packet Capture Engine** | `engine/packet_capture.py` | Captures live network packets using Scapy, extracts metadata |
| **Feature Extraction** | `engine/feature_extraction.py` | Centralized feature extraction from packets and flows for ML pipeline |
| **Flow Analyzer** | `engine/flow_analyzer.py` | Groups packets into bidirectional flows, computes flow-level features |
| **Decision Engine** | `engine/decision_engine.py` | BLOCK/FLAG/ALLOW firewall logic, IP blocking, auto-escalation |
| **Rule-Based Detector** | `detection/rule_engine.py` | Detects known attack patterns: DDoS, SQL Injection, Port Scan, etc. |
| **ML Detector** | `detection/ml_detector.py` | Classifies traffic using XGBoost (primary) and Isolation Forest (fallback) |
| **Hybrid Detector** | `detection/hybrid_detector.py` | Combines all detection engines, correlates alerts, triggers decisions |
| **Telegram Alerter** | `alerts/telegram_alert.py` | Sends real-time Telegram notifications for critical threats |
| **XGBoost Training** | `train_xgboost.py` | Trains XGBoost model on CICIDS-2017 dataset |
| **Web Application** | `app.py` | Flask server with REST API, WebSocket, and firewall endpoints |
| **Dashboard** | `templates/index.html`, `static/` | 6-tab real-time web UI with Chart.js visualizations |
| **Configuration** | `config.py` | Settings for rules, thresholds, firewall, Telegram, ML |

---

## 3. Detailed Working

### 3.1 Packet Capture Engine (`engine/packet_capture.py`)

The packet capture engine is the entry point of the data pipeline.

**How it works:**

1. Uses the **Scapy** library to sniff raw network packets from a specified network interface
2. Runs in a dedicated background thread to avoid blocking the main application
3. For each captured packet, extracts structured metadata into a `PacketInfo` object:
   - **Layer 2 (Ethernet):** Source/destination MAC addresses
   - **Layer 3 (IP):** Source/destination IP, TTL, header length, fragment offset
   - **Layer 4 (TCP/UDP):** Ports, TCP flags (SYN, ACK, FIN, RST, PSH, URG), window size
   - **Application layer:** DNS queries/responses, ICMP types, ARP operations
   - **Encryption metadata:** TLS version detection (without payload inspection)
4. Maintains a circular buffer of recent packets (default: 1000)
5. Calculates real-time statistics: packets/second, bytes/second, protocol distribution
6. Includes a **simulation mode** that generates realistic synthetic traffic (including attack patterns) when Scapy is unavailable or root privileges are not granted

**Key Design Decision:** The engine performs metadata-only analysis—it never inspects payload content, preserving privacy while still enabling effective detection.

### 3.2 Feature Extraction (`engine/feature_extraction.py`)

The Feature Extractor centralizes all feature computation to ensure consistency between the ML training pipeline and real-time inference.

**How it works:**

1. Extracts **packet-level features** from individual packets: protocol, ports, flags, TTL, payload size
2. Extracts **flow-level features** from bidirectional flows: duration, packet counts, byte counts, inter-arrival times
3. Maintains per-IP packet rate tracking for volumetric detection
4. Periodically cleans up stale tracking entries to prevent memory leaks

### 3.3 Flow Analyzer (`engine/flow_analyzer.py`)

Network flows provide a higher-level view of communication patterns compared to individual packets.

**How it works:**

1. Groups individual packets into **bidirectional flows** using a composite key: `(src_ip, src_port, dst_ip, dst_port, protocol)`
2. The flow ID is sorted so that packets in either direction belong to the same flow
3. For each flow, computes 27 features in real-time:

| Feature Category | Features Computed |
|-----------------|-------------------|
| **Basic** | Duration, packet count, total bytes |
| **Directional** | Forward/backward packets and bytes |
| **Packet size** | Average, min, max packet size |
| **TCP flags** | SYN, FIN, RST, ACK, PSH, URG counts |
| **Ratios** | Forward/backward packet ratio, byte ratio |
| **Timing** | Average and standard deviation of inter-arrival times |
| **Payload** | Average and standard deviation of payload sizes |
| **Other** | Encryption flag, unique destination ports, DNS query count |

4. Expired flows (inactive for >120 seconds) are automatically cleaned up and archived
5. The computed feature dictionaries are passed directly to the ML detection engine

### 3.4 Rule-Based Detection Engine (`detection/rule_engine.py`)

The rule engine provides fast, deterministic detection of known attack patterns.

**Implemented Rules:**

| Rule | Detection Logic | Threshold | Severity |
|------|----------------|-----------|----------|
| **DDoS** | Tracks packet rate from same source IP. Triggers on volumetric flood. | 200 pkts/s | Critical |
| **Port Scan** | Tracks unique destination ports per source IP within a time window. | 15 ports / 10s | High |
| **SYN Flood** | Monitors SYN-only packets targeting a single IP. | 100 SYN/s | Critical |
| **SQL Injection** | Detects rapid payload-bearing requests to web/database ports (80, 443, 3306, 5432, 8080, 8443) with suspicious patterns. Uses 20+ heuristic patterns: `SELECT`, `UNION`, `DROP TABLE`, `' OR '1'='1`, `--`, `/**/`, etc. | Port + rate | Critical |
| **DNS Tunneling** | Detects two patterns: (a) abnormally long DNS queries (>50 chars), and (b) high-frequency queries to same domain (>30/min). | 50 chars or 30/min | High |
| **ICMP Flood** | Counts ICMP packets per target IP. | 50 ICMP/s | Medium |
| **ARP Spoofing** | Maintains ARP table mapping IP→MAC addresses. Triggers on 5+ different MACs per IP. | 5 MACs/IP | Critical |
| **Brute Force** | Monitors connection attempts to auth services (SSH:22, FTP:21, RDP:3389). | 10 attempts/min | High |
| **Encrypted Anomaly** | Detects deprecated TLS/SSL versions (SSL 3.0, TLS 1.0, TLS 1.1). | N/A | Medium |

**Alert Generation:**
- Each alert includes: type, severity, source/destination IP, human-readable description, list of evidence items, and confidence score (0.0–1.0)
- A cooldown mechanism (15 seconds per alert type per source IP) prevents alert flooding

### 3.5 Machine Learning Detection Engine (`detection/ml_detector.py`)

This is the core ML component that uses **XGBoost** for network intrusion classification.

#### 3.5.1 XGBoost Classifier (Primary)

**What is XGBoost?**

XGBoost (eXtreme Gradient Boosting) is an optimized implementation of gradient boosted decision trees. It is widely used due to its:
- High prediction accuracy (99.7% on CICIDS-2017)
- Built-in regularization (prevents overfitting)
- Efficient handling of missing values
- Parallel processing capability
- Feature importance ranking

**How it integrates into NetGuard:**

1. **Pre-trained model:** The training script (`train_xgboost.py`) trains the model offline on CICIDS-2017
2. **Model loading:** On startup, the ML detector loads:
   - `xgboost_model.json` — trained XGBoost classifier (27 classes)
   - `xgb_scaler.pkl` — StandardScaler for feature normalization
   - `xgb_label_encoder.pkl` — maps numeric predictions to attack names
   - `xgb_feature_names.pkl` — ordered list of 85 feature columns
3. **Feature mapping:** Live flow features are mapped to the CICIDS-2017 feature space. Missing features are filled with zero
4. **Prediction:** For each network flow:
   - Features are extracted and scaled
   - XGBoost outputs class probabilities for all 27 attack types
   - The class with highest probability is selected
   - If the predicted class is not BENIGN and confidence >50%, an alert is generated
5. **Explainable output:** Each alert includes top predicted classes with probabilities

#### 3.5.2 Isolation Forest (Fallback)

When no XGBoost model is available, the system uses **Isolation Forest** for unsupervised anomaly detection:

1. Collects flow feature samples from live traffic
2. After accumulating 1000 samples, automatically trains an Isolation Forest model
3. Flags flows with anomaly scores above threshold as suspicious
4. Periodically retrains as new samples are collected

#### 3.5.3 Severity Classification

| Severity | Criteria |
|----------|----------|
| **Critical** | DDoS, DoS variants, Heartbleed (with confidence >70%) |
| **High** | Brute Force, Botnet, Infiltration, Web Attacks, or any attack with confidence >80% |
| **Medium** | Attacks with confidence 50–80% |
| **Low** | Attacks with confidence <50% |

### 3.6 Decision Engine (`engine/decision_engine.py`)

The Decision Engine is the **central brain** of the Smart Firewall. It processes outputs from both the Rule Engine and ML Detector to determine the appropriate response action.

**Decision Logic:**

```
                    ┌─────────────────────────┐
                    │   Incoming Detection     │
                    │   (Rule + ML results)    │
                    └───────────┬──────────────┘
                                │
                    ┌───────────▼──────────────┐
                    │  Both Rule + ML confirm? │
                    └───────┬──────────┬───────┘
                      Yes   │          │  No
                    ┌───────▼──┐  ┌────▼──────────────────┐
                    │  BLOCK   │  │ Rule-Based high conf?  │
                    │  (5 min) │  │ (≥80% confidence)      │
                    └──────────┘  └───┬──────────┬─────────┘
                                 Yes  │          │  No
                              ┌───────▼──┐  ┌───▼──────────────┐
                              │  BLOCK   │  │ ML + Anomaly?    │
                              │  (5 min) │  │                  │
                              └──────────┘  └──┬──────────┬────┘
                                           Yes │          │ No
                                       ┌───────▼──┐  ┌───▼────┐
                                       │  BLOCK   │  │  FLAG  │
                                       │  (5 min) │  │        │
                                       └──────────┘  └────────┘
```

**IP Management:**

| Feature | Description |
|---------|-------------|
| **Blocked IPs** | Dictionary of currently blocked IPs with reason, timestamp, and expiry |
| **Flagged IPs** | Counter-based tracking of suspicious source IPs |
| **Auto-Escalation** | After `flag_threshold` (default: 3) FLAG events, IP is auto-promoted to BLOCK |
| **Block Expiry** | Blocked IPs are automatically unblocked after `block_duration` (default: 300 seconds) |
| **Manual Unblock** | Administrators can manually unblock IPs via the dashboard or API |
| **Decision History** | All decisions are logged with timestamp, action, source/target IP, confidence, attack type |

**Hybrid Confidence Boosting:**

When both rule-based and ML engines independently flag the same source IP within a 30-second window, the ML confidence score is boosted by +15%. This reduces false positives by requiring agreement from independent detection methods.

### 3.7 Telegram Alerter (`alerts/telegram_alert.py`)

The Telegram Alert module sends real-time notifications for severe threats.

**How it works:**

1. Monitors all generated alerts for HIGH and CRITICAL severity
2. When a qualifying alert fires, formats an HTML message with:
   - Attack type and severity
   - Source and target IP addresses
   - Detection method (Rule-Based, ML, or Hybrid)
   - Confidence score
   - Evidence items
   - Timestamp
3. Sends the message asynchronously via the Telegram Bot API
4. Rate limits to prevent flooding: maximum 20 alerts/minute, with per-type cooldowns
5. Also sends special notifications when the firewall blocks an IP

**Configuration:**

```bash
export TELEGRAM_BOT_TOKEN="123456:ABCdefGHIjklMNOpqrsTUVwxyz"
export TELEGRAM_CHAT_ID="-1001234567890"
```

### 3.8 Hybrid Detection Manager (`detection/hybrid_detector.py`)

The hybrid detector orchestrates all components in the detection pipeline.

**Processing Pipeline:**

```
Packet Captured
    ├──▶ Feature Extractor (extract packet/flow features)
    ├──▶ Flow Analyzer (update bidirectional flow)
    ├──▶ Rule Engine (check all 9 rule detectors)
    ├──▶ ML Detector (XGBoost prediction + anomaly check)
    ├──▶ Decision Engine (BLOCK / FLAG / ALLOW decision)
    ├──▶ Telegram Alerter (notify if HIGH/CRITICAL)
    ├──▶ WebSocket (push to dashboard, throttled)
    └──▶ Alert Callbacks (store for API retrieval)
```

**Alert Correlation Logic:**

1. When an ML-based alert is generated, the system checks if a rule-based alert exists for the same source IP within the last 30 seconds
2. If a corroborating rule-based alert is found:
   - The ML alert's confidence is boosted by +15%
   - Evidence is appended noting the corroboration
   - The alert is tracked as a "correlated alert"
3. This dual-validation approach significantly reduces false positives

### 3.9 XGBoost Training Pipeline (`train_xgboost.py`)

**Dataset: CICIDS-2017**

The CICIDS-2017 dataset was created by the Canadian Institute for Cybersecurity at the University of New Brunswick. It is hosted on **Hugging Face** and contains:
- ~2.8 million labeled network flow records
- 78 numerical features extracted using CICFlowMeter
- Traffic from 5 days (Monday through Friday)
- Both benign and attack traffic covering 15+ attack categories

**Training Pipeline Steps:**

```
CSV Files → Data Loading → Cleaning → Feature Selection → Class Balancing
                                                              │
              Model Saved ← Evaluation ← XGBoost Training ←──┘
```

| Step | Description |
|------|-------------|
| **1. Data Loading** | Reads all 5 CSV files, detects encoding, concatenates into single DataFrame |
| **2. Data Cleaning** | Strips whitespace from column names, replaces infinite values with NaN, fills NaN with 0, removes duplicate rows, drops zero-variance columns |
| **3. Feature Selection** | Removes non-numeric columns (Flow ID, IPs, timestamps), keeps 76 numeric features |
| **4. Class Balancing** | Downsamples the majority class (BENIGN) to max 100,000 samples to prevent bias |
| **5. Label Encoding** | Converts string labels to integer classes using LabelEncoder |
| **6. Train/Test Split** | 80% training, 20% testing with stratified sampling |
| **7. Feature Scaling** | StandardScaler normalization (zero mean, unit variance) |
| **8. Model Training** | XGBoost with 200 trees, max depth 8, learning rate 0.1, multi-class softmax |
| **9. Evaluation** | Accuracy, macro/weighted F1, per-class precision/recall/F1, feature importance |
| **10. Artifact Saving** | Model (JSON), scaler, encoder, feature names, metadata saved to `models/` |

**XGBoost Hyperparameters:**

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `n_estimators` | 200 | Number of boosting rounds |
| `max_depth` | 8 | Maximum depth of each tree |
| `learning_rate` | 0.1 | Step size shrinkage to prevent overfitting |
| `subsample` | 0.8 | Fraction of rows sampled per tree |
| `colsample_bytree` | 0.8 | Fraction of features sampled per tree |
| `min_child_weight` | 5 | Minimum sum of instance weights in a child node |
| `gamma` | 0.1 | Minimum loss reduction for a split |
| `reg_alpha` | 0.1 | L1 regularization |
| `reg_lambda` | 1.0 | L2 regularization |
| `objective` | `multi:softprob` | Multi-class classification with probability output |

### 3.10 Web Application (`app.py`)

The Flask application serves as the interface layer.

**Components:**

1. **REST API** — 17 endpoints for programmatic access (packets, alerts, stats, firewall control)
2. **WebSocket (SocketIO)** — Real-time push of packets, alerts, decisions, and statistics
3. **Firewall Endpoints** — 5 endpoints for blocked/flagged IPs, decisions, and manual unblock
4. **Background Stats Thread** — Sends updated statistics to all connected clients every 2 seconds
5. **Throttled Packet Feed** — Sends every 3rd packet via WebSocket to reduce bandwidth

---

## 4. Technology Stack

| Technology | Version | Usage |
|------------|---------|-------|
| **Python** | 3.9+ | Core programming language |
| **Flask** | 2.3+ | Web framework for REST API and HTML serving |
| **Flask-SocketIO** | 5.3+ | Real-time bidirectional WebSocket communication |
| **Scapy** | 2.5+ | Raw network packet capture and parsing |
| **XGBoost** | 1.7+ | Gradient boosted tree classifier (27 classes, 99.7% accuracy) |
| **Scikit-learn** | 1.3+ | Data preprocessing (StandardScaler, LabelEncoder), evaluation metrics |
| **Pandas** | 2.0+ | Dataset loading, manipulation, and feature engineering |
| **NumPy** | 1.24+ | Numerical computations and array operations |
| **Joblib** | 1.3+ | Model serialization (save/load trained models) |
| **Telegram Bot API** | — | Real-time alert notifications via HTTP |
| **Chart.js** | 4.x | Dashboard charts (traffic timeline, protocol distribution) |
| **Socket.IO** | 4.7 | Client-side WebSocket for real-time dashboard updates |
| **HTML/CSS/JS** | — | 6-tab dashboard front-end with premium dark theme |

---

## 5. Dataset Description

### CICIDS-2017

| Property | Details |
|----------|---------|
| **Source** | Canadian Institute for Cybersecurity, UNB (hosted on Hugging Face) |
| **Collection Period** | 5 days (Monday–Friday) |
| **Total Records** | ~2.83 million network flows |
| **Features** | 78 numeric features + 1 label column |
| **Feature Extraction Tool** | CICFlowMeter |
| **Benign Samples** | ~2.27 million (80.3%) |
| **Attack Samples** | ~0.56 million (19.7%) |

**Attack Types in Dataset:**

| Day | Attack Types |
|-----|-------------|
| Monday | Benign (normal activity baseline) |
| Tuesday | FTP-Patator, SSH-Patator (brute force) |
| Wednesday | DoS GoldenEye, DoS Hulk, DoS Slowhttptest, DoS Slowloris, Heartbleed |
| Thursday | Web Attack – Brute Force, Web Attack – XSS, Web Attack – SQL Injection, Infiltration |
| Friday | Botnet, Port Scan, DDoS |

---

## 6. Execution Flow

### 6.1 Training Phase

```
Step 1: Download CICIDS-2017 dataset from Hugging Face
        $ python3 download_dataset.py

Step 2: Run training
        $ python3 train_xgboost.py

Step 3: Training pipeline executes:
        Load CSVs → Clean Data → Balance Classes → Train XGBoost → Evaluate → Save Model

Step 4: Model artifacts saved to models/ folder
        (xgboost_model.json, xgb_scaler.pkl, xgb_label_encoder.pkl, etc.)
```

### 6.2 Detection Phase

```
Step 1: Start the application
        $ sudo python3 app.py

Step 2: System initializes:
        Load XGBoost model → Init Decision Engine → Init Telegram Alerter
        → Start packet capture → Start web server on port 5050

Step 3: For each captured packet:
        Extract metadata → Update flow → Extract features
        → Run rule checks → Run XGBoost prediction

Step 4: Decision Engine processes results:
        Both Rule + ML confirm → BLOCK IP (5 minutes)
        Single detection → FLAG IP (auto-block after 3 flags)
        No detection → ALLOW

Step 5: If threat is HIGH/CRITICAL:
        Send Telegram notification → Push to dashboard → Log decision

Step 6: User monitors via dashboard:
        Open http://localhost:5050
        → Overview tab: Stats, traffic charts, protocol distribution
        → Packets tab: Live packet stream with search
        → Alerts tab: Alert feed with severity filters and evidence
        → Firewall tab: Blocked/flagged IPs, decision log, unblock controls
        → Flows tab: Active bidirectional flows
        → Detection Engine tab: ML status, training progress, active rules
```

---

## 7. Key Integrations

### 7.1 XGBoost Integration with Live Traffic

The primary integration challenge was mapping live network flow features to the CICIDS-2017 feature space. The solution:

| Live Flow Feature | Mapped to CICIDS-2017 Column |
|-------------------|------------------------------|
| `duration` | `Flow Duration` |
| `fwd_packets` | `Total Fwd Packets` |
| `bwd_packets` | `Total Backward Packets` |
| `fwd_bytes` | `Total Length of Fwd Packets` |
| `bwd_bytes` | `Total Length of Bwd Packets` |
| `avg_packet_size` | `Average Packet Size` |
| `syn_count` | `SYN Flag Count` |
| `fin_count` | `FIN Flag Count` |
| `avg_inter_arrival` | `Flow IAT Mean` |
| `packets_per_second` | `Fwd Packets/s` |
| *(and 17 more)* | *(corresponding CICIDS columns)* |

Features present in CICIDS-2017 but not available from live capture are filled with zero values.

### 7.2 Decision Engine Integration

The Decision Engine correlates outputs from independent detection engines:

```python
# If Rule-Based AND ML both confirm an attack → BLOCK
if rule_alert and ml_alert:
    action = 'BLOCK'
    block_ip(source_ip, duration=300)
    send_telegram_alert(alert)

# If either engine flags → FLAG (tracked for auto-escalation)
elif rule_alert or ml_alert or anomaly_detected:
    action = 'FLAG'
    increment_flag_count(source_ip)
    if flag_count >= threshold:
        action = 'BLOCK'  # Auto-escalation

# If nothing detected → ALLOW
else:
    action = 'ALLOW'
```

### 7.3 Telegram Integration

The Telegram Alerter hooks into the detection pipeline:

```
Alert Generated (HIGH/CRITICAL)
    → Format HTML message with attack details
    → POST to Telegram Bot API (async)
    → Rate limit: max 20 alerts/minute
    → Per-type cooldown: 60 seconds

Firewall Block Event
    → Send special "🔥 IP BLOCKED" notification
    → Include IP, reason, and expiry time
```

### 7.4 Real-Time Dashboard Integration

The dashboard receives data through three channels:
1. **WebSocket push** — New packets, alerts, and firewall decisions pushed immediately
2. **Periodic stats** — System statistics broadcast to all connected clients every 2 seconds
3. **REST API poll** — Dashboard polls `/api/firewall/status` every 3 seconds for blocked/flagged IP lists

---

## 8. Dashboard Tabs

| Tab | Content |
|-----|---------|
| **📊 Overview** | 8 stats cards (Packets, Data, Encrypted, Alerts, Blocked IPs, Flows, Uptime, Decisions), Traffic Timeline chart, Protocol Distribution doughnut chart |
| **📦 Packets** | Live scrolling packet table with search/filter: Time, Src IP, Src Port, Dst IP, Dst Port, Protocol, Length, Flags, Encrypted |
| **🚨 Alerts** | Alert cards with severity badges, expandable evidence, acknowledge button. Filter by: All, Critical, High, Medium, Low. Severity bar chart, Attack type polar chart |
| **🔥 Firewall** | 4 summary cards (Blocked, Flagged, Allowed, Active Blocks). Blocked IPs panel with Unblock buttons. Flagged IPs panel with suspicion counts. Decision log table: Time, Action, Source, Target, Type, Severity, Confidence, Rule Match, ML Match |
| **🔄 Flows** | Active bidirectional flow table: Source, Destination, Protocol, Packets, Bytes, Duration, PPS, Encrypted |
| **🧠 Detection Engine** | ML status (XGBoost Active / Training / Learning), Training samples progress bar, Anomalies detected, Model quality. Active rules table (11 rules). System architecture description |

---

## 9. File Reference

| File | Description |
|------|-------------|
| `app.py` | Flask application with 17 REST API + 5 firewall endpoints, WebSocket, and background stats |
| `config.py` | Configuration: ports, thresholds, rule parameters, firewall settings, Telegram config, attack classes |
| `train_xgboost.py` | XGBoost training pipeline for CICIDS-2017 dataset |
| `download_dataset.py` | Dataset validation and download helper |
| `engine/packet_capture.py` | Scapy-based packet capture with simulation fallback |
| `engine/feature_extraction.py` | Centralized feature extraction from packets and flows |
| `engine/flow_analyzer.py` | Bidirectional flow tracking and feature computation |
| `engine/decision_engine.py` | BLOCK/FLAG/ALLOW decision logic with IP management |
| `detection/rule_engine.py` | 9 rule-based detectors (DDoS, SQLi, Port Scan, etc.) with evidence generation |
| `detection/ml_detector.py` | XGBoost (99.7%) + Isolation Forest ML detection engine |
| `detection/hybrid_detector.py` | Alert correlation and hybrid pipeline management |
| `alerts/telegram_alert.py` | Telegram Bot API alert notifications with rate limiting |
| `templates/index.html` | 6-tab dashboard HTML with Chart.js canvas elements |
| `static/css/dashboard.css` | Premium dark theme with firewall action badges and glassmorphism |
| `static/js/dashboard.js` | Dashboard logic: charts, tables, firewall rendering, WebSocket handlers |
| `requirements.txt` | Python package dependencies |

---

## 10. Conclusion

NetGuard demonstrates a practical, production-ready approach to data center network security by combining:

1. **Rule-based detection** for fast, deterministic identification of known attack signatures (DDoS, SQL Injection, Port Scan, Brute Force, SYN Flood, DNS Tunneling, ICMP Flood, ARP Spoofing) with zero training required
2. **XGBoost machine learning** trained on the CICIDS-2017 benchmark dataset for classification of 27 attack categories with 99.7% accuracy
3. **Isolation Forest anomaly detection** for identifying novel or zero-day threats not covered by rules or classification
4. **Smart Firewall Decision Engine** that autonomously blocks confirmed threats, flags suspicious activity, and auto-escalates repeated offenders
5. **Telegram alert integration** for real-time notification of security administrators about HIGH and CRITICAL severity events
6. **Alert correlation** between independent detection engines to reduce false positives and boost confidence
7. **Real-time monitoring** via a premium 6-tab web dashboard with WebSocket-powered live updates, Chart.js visualizations, and manual IP management controls

The hybrid architecture ensures that the system can detect both known patterns (via rules) and complex, multi-feature attack signatures (via ML) that would be difficult to express as simple rules. The Decision Engine adds an active response capability, transforming the IDS into a full IDS/IPS (Intrusion Prevention System) that can autonomously mitigate threats in real-time.

---

## 11. Future Enhancements

1. **OS-Level Blocking** — Enable `iptables`/`nftables` integration for actual kernel-level packet filtering on Linux
2. **Deep Learning Models** — Integrate LSTM/Transformer-based sequence models for temporal pattern detection
3. **Online Learning** — Continuously update the XGBoost model with labeled live traffic
4. **PCAP Replay** — Support importing and analyzing PCAP capture files
5. **Multi-Interface Capture** — Monitor multiple network interfaces simultaneously
6. **Alert Export** — Export alerts to SIEM systems (Splunk, ELK Stack) via syslog
7. **User Authentication** — Add login and role-based access to the dashboard
8. **Geo-IP Mapping** — Visualize attack origins on a world map
9. **Threat Intelligence Feeds** — Integrate with known-bad-IP databases for enhanced detection
