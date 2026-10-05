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


🌟 Key Features⚡ Real-Time Packet Dissection: Direct interface sniffing using Scapy and low-level raw sockets without payload retention overhead.📊 8-Dimensional Feature Vectorization: Extracts packet rates, byte throughput, average packet sizes, TCP/UDP counts, SYN flag ratios, and target IP/port dispersion every 5 seconds.🧠 Unsupervised Threat Detection: Uses an Isolation Forest algorithm to detect zero-day DoS attacks (SYN floods) and port scans without static rule signature dependencies.🔄 Asynchronous WebSocket Telemetry: Broadcasts detection vectors and anomaly scores with sub-5ms pipeline overhead.💾 Persistent SQLite Audit Logs: Stores all event streams in ids_alerts.db with an exposed REST API (/api/logs) for security auditing.🚨 Built-in Attack Simulator: Features an interactive traffic simulator (attack_simulator.py) to execute controlled SYN floods and port probes.📈 Empirical Evaluation Suite: Includes evaluate_model.py to benchmark Precision, Recall, F1-Score, Confusion Matrices, and ROC-AUC curves.📊 Empirical Performance BenchmarksBenchmark evaluation executed across 1,000 traffic samples (800 normal, 200 attack anomalies):Evaluation MetricSystem Benchmark ScoreClassification Accuracy97.0%Attack Recall (Sensitivity)96.0%Attack Precision90.5%F1-Score0.93ROC-AUC Score0.984Mean Pipeline Processing Overhead~4.92 ms / window🛠️ Tech Stack & DependenciesLanguage: Python 3.10+Packet Dissection: Scapy, Npcap (WinPcap API Mode)Machine Learning: scikit-learn (IsolationForest, StandardScaler), pandas, numpy, joblibBackend Server: FastAPI, Uvicorn, WebSocketsDatabase: SQLite3Visualization: Matplotlib, Seaborn (Model Metrics)Frontend Web Dashboard: HTML5, Tailwind CSS, Chart.js🚀 Installation & Quick Start1. PrerequisitesPython 3.10+Npcap (Windows users): Download and install from npcap.com. Ensure "Install Npcap in WinPcap API-compatible Mode" is checked during setup.2. Clone the RepositoryPowerShellgit clone [https://github.com/shekinahomollo/network-ids-capstone.git](https://github.com/shekinahomollo/network-ids-capstone.git)
cd network-ids-capstone
3. Set Up Virtual Environment & DependenciesPowerShell# Create virtual environment
python -m venv .venv

# Activate environment (PowerShell)
.\.venv\Scripts\Activate.ps1

# Install core dependencies
pip install scapy scikit-learn pandas numpy fastapi "uvicorn[standard]" websockets joblib matplotlib seaborn
⚙️ Usage WorkflowTrain Baseline ML Model:PowerShellpython train_model.py
Initialize SQLite Database:PowerShellpython database.py
Launch Streaming Server (Run as Administrator):PowerShellpython server.py
Runs at http://127.0.0.1:8000 (WebSocket endpoint: ws://127.0.0.1:8000/ws/alerts).Launch Live Dashboard:Open index.html in Chrome/Edge. Verify the connection badge shows "● WebSocket Connected".Simulate Attack Traffic:In a second terminal, execute:PowerShellpython attack_simulator.py
Select Option 1 (SYN Flood) or 2 (Port Scan) to observe live telemetry spikes.Generate Benchmark Metrics:PowerShellpython evaluate_model.py
Outputs high-resolution plot model_evaluation_metrics.png.📂 Repository StructurePlaintextnetwork-ids-capstone/
├── sniffer.py           # Standalone packet capture module
├── feature_extractor.py # 5-second sliding window aggregator
├── train_model.py       # Isolation Forest trainer & exporter
├── ids_engine.py        # Integrated real-time CLI detector
├── server.py           # Asynchronous FastAPI & WebSocket server
├── database.py         # SQLite persistence & REST query engine
├── attack_simulator.py # Controlled SYN flood & port scan suite
├── evaluate_model.py   # Benchmark metrics & ROC curve generator
├── index.html          # Interactive Chart.js & Tailwind web dashboard
└── README.md           # Documentation
📜 LicenseDistributed under the MIT License. See LICENSE for details.