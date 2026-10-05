<div align="center">

# 🛡️ Real-Time Machine Learning Network Intrusion Detection System (NIDS)

**An offline-first, low-latency NIDS leveraging unsupervised Isolation Forests, FastAPI WebSockets, and real-time telemetry visualizers.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

</div>

---

## 📌 Executive Overview

This repository contains a **Computer Science Capstone Project** centered on low-overhead security monitoring, zero-day threat resilience, and zero cloud-API cost dependencies. 

The system intercepts live network packets at Layer 2/3, aggregates time-series telemetry into **5-second sliding windows**, standardizes metrics via `StandardScaler`, and performs real-time unsupervised anomaly detection using an **Isolation Forest** model. Detected security anomalies are persisted to an SQLite database and broadcast asynchronously over WebSockets to a live HTML5/Tailwind/Chart.js dashboard.

---

## 📐 System Architecture

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                          LIVE NETWORK INTERFACE                         │
│                           (Wi-Fi / Ethernet)                            │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       RAW PACKET CAPTURE (SCAPY)                        │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    SLIDING-WINDOW FEATURE EXTRACTOR                     │
│                      (5-Second Aggregation Engine)                      │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    MACHINE LEARNING INFERENCE ENGINE                    │
│                  (Isolation Forest + StandardScaler)                    │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
           ┌─────────────────────────┴─────────────────────────┐
           ▼                                                   ▼
┌─────────────────────┐                             ┌─────────────────────┐
│ SQLite Persistence  │                             │  FastAPI WebSocket  │
│ Database (ids_db)   │                             │  Streaming Server   │
└─────────────────────┘                             └──────────┬──────────┘
                                                               │
                                                               ▼
                                                    ┌─────────────────────┐
                                                    │ Interactive Web     │
                                                    │ Dashboard (Chart.js)│
                                                    └─────────────────────┘

```
---

## 🌟 Key Features

* **⚡ Real-Time Packet Dissection:** Direct interface sniffing using Scapy and low-level raw sockets without payload retention overhead.
* **📊 8-Dimensional Feature Vectorization:** Extracts packet rates, byte throughput, average packet sizes, TCP/UDP counts, SYN flag ratios, and target IP/port dispersion every 5 seconds.
* **🧠 Unsupervised Threat Detection:** Uses an Isolation Forest algorithm to detect zero-day DoS attacks (SYN floods) and port scans without static rule signature dependencies.
* **🔄 Asynchronous WebSocket Telemetry:** Broadcasts detection vectors and anomaly scores with **sub-5ms pipeline overhead**.
* **💾 Persistent SQLite Audit Logs:** Stores all event streams in `ids_alerts.db` with an exposed REST API (`/api/logs`) for security auditing.
* **🚨 Built-in Attack Simulator:** Features an interactive traffic simulator (`attack_simulator.py`) to execute controlled SYN floods and port probes.
* **📈 Empirical Evaluation Suite:** Includes `evaluate_model.py` to benchmark Precision, Recall, F1-Score, Confusion Matrices, and ROC-AUC curves.

---

## 📊 Empirical Performance Benchmarks

Benchmark evaluation executed across **1,000 traffic samples** (800 normal, 200 attack anomalies):

| Evaluation Metric | System Benchmark Score |
| :--- | :--- |
| **Classification Accuracy** | **97.0%** |
| **Attack Recall (Sensitivity)** | **96.0%** |
| **Attack Precision** | **90.5%** |
| **F1-Score** | **0.93** |
| **ROC-AUC Score** | **0.984** |
| **Mean Pipeline Processing Overhead** | **~4.92 ms / window** |

---

## 🛠️ Tech Stack & Dependencies

* **Language:** Python 3.10+
* **Packet Dissection:** Scapy, Npcap (WinPcap API Mode)
* **Machine Learning:** `scikit-learn` (IsolationForest, StandardScaler), `pandas`, `numpy`, `joblib`
* **Backend Server:** FastAPI, Uvicorn, WebSockets
* **Database:** SQLite3
* **Visualization:** Matplotlib, Seaborn (Model Metrics)
* **Frontend Web Dashboard:** HTML5, Tailwind CSS, Chart.js

---

## 🚀 Installation & Quick Start

### 1. Prerequisites
* **Python 3.10+**
* **Npcap (Windows users):** Download and install from [npcap.com](https://npcap.com/#download). Ensure **"Install Npcap in WinPcap API-compatible Mode"** is checked during setup.

### 2. Clone the Repository
```powershell
git clone https://github.com/shekinahomollo/network-ids-capstone.git
cd network-ids-capstone
```
### 3. Set Up Virtual Environment & Dependencies
```powershell
# Create virtual environment
python -m venv .venv

# Activate environment (PowerShell)
.\.venv\Scripts\Activate.ps1

# Install core dependencies
pip install scapy scikit-learn pandas numpy fastapi "uvicorn[standard]" websockets joblib matplotlib seaborn
```
## ⚙️ Usage Workflow

1. **Train Baseline ML Model:**
   ```powershell
   python train_model.py
   ```
## ⚙️ Usage Guide
### Step 1: Train the Baseline ML Model
Train the Isolation Forest model on normal network behavior metrics:

   ```powershell
python train_model.py
   ```
Outputs: ids_isolation_forest.joblib and ids_scaler.joblib

### Step 2: Initialize Database
Set up the local SQLite database table:

   ```powershell
python database.py
   ```
Outputs: ids_alerts.db

### Step 3: Launch the Streaming Server
Start the FastAPI server with elevated Administrator privileges (required for raw packet socket access):

   ```powershell
python server.py
   ```
Server runs at http://127.0.0.1:8000 with WebSocket endpoint at ws://127.0.0.1:8000/ws/alerts and logs API at http://127.0.0.1:8000/api/logs.

### Step 4: Open the Live Dashboard
Double-click index.html or open it directly in any browser (Chrome, Edge, Firefox). Ensure the top-right status badge displays "● WebSocket Connected".

### Step 5: Simulate Attack Traffic (Validation)
Open a second PowerShell terminal, activate .venv, and run the attack simulator:

   ```powershell
python attack_simulator.py
   ```
Select Option 1 (SYN Flood) or Option 2 (Port Scan) to observe real-time anomaly spikes and alert notifications stream on the web dashboard.

### Step 6: Run Empirical Model Evaluation
To generate precision, recall, confusion matrix, and ROC curve plots for academic documentation:

   ```powershell
python evaluate_model.py
   ```
Outputs: High-resolution plot saved as model_evaluation_metrics.png.

## 📂 Project Structure

```text
network-ids-capstone/
│
├── sniffer.py           # Standalone low-level packet capture prototype
├── feature_extractor.py # 5-second sliding window feature engineering engine
├── train_model.py       # Isolation Forest ML training & model exporter
├── ids_engine.py        # Integrated real-time CLI detection engine
├── server.py           # Asynchronous FastAPI & WebSocket streaming server
├── database.py         # SQLite persistence and REST query handler
├── attack_simulator.py # Controlled SYN flood & port scan attack simulator
├── evaluate_model.py   # Model evaluation benchmark (Confusion matrix & ROC)
├── index.html          # Interactive Chart.js & Tailwind web dashboard
├── .gitignore          # Git exclusion rules
└── README.md           # Project documentation

```

## 🎓 Academic Evaluation & Future Work

* **Multi-Model Benchmark:** Extending evaluation to compare Isolation Forest performance against One-Class SVM and Autoencoders.
* **Dynamic Adaptive Windowing:** Replacing static 5-second windowing with event-driven sliding intervals to capture sub-second micro-bursts.
* **Automated Mitigation (IPS):** Integrating active firewall rule insertion (Windows Filtering Platform / `iptables`) upon high-confidence anomaly triggers.
* **Standard Dataset Testing:** Running accuracy benchmarks against public intrusion datasets (e.g., CICIDS2017).

  
## 📜 License
Distributed under the MIT License. See LICENSE for details.
