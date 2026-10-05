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
