# 🛡️ Real-Time Unsupervised Machine Learning Network Intrusion Detection System (NIDS)

An offline-first, low-latency Network Intrusion Detection System (NIDS) built for high-throughput packet processing, sliding-window feature engineering, unsupervised anomaly detection using **Isolation Forests**, and real-time alert streaming via **WebSockets** and **FastAPI**.

Designed as a 7-month Computer Science Capstone Project focusing on low-overhead security monitoring, resilience against zero-day network threats, and zero cloud-API cost dependencies.

---

## 📐 System Architecture
                   +-----------------------------------+
                   |      Live Network Interface       |
                   |       (Wi-Fi / Ethernet)          |
                   +-----------------+-----------------+
                                     |
                                     v
                   +-----------------+-----------------+
                   |    Raw Packet Capture (Scapy)     |
                   +-----------------+-----------------+
                                     |
                                     v
                   +-----------------+-----------------+
                   | Sliding-Window Feature Extractor  |
                   |   (5-Second Aggregation Engine)   |
                   +-----------------+-----------------+
                                     |
                                     v
                   +-----------------+-----------------+
                   | Machine Learning Inference Engine |
                   | (Isolation Forest + StandardScaler)|
                   +--------+----------------+--------+
                            |                |
                            v                v
        +-------------------+---+        +---+-------------------+
        | SQLite Persistence    |        | FastAPI WebSocket     |
        | Database (ids_alerts) |        | Streaming Server      |
        +-----------------------+        +---+-------------------+
                                             |
                                             v
                                 +-----------+-----------+
                                 | Interactive Dashboard |
                                 | (Chart.js & Tailwind) |
                                 +-----------------------+

---

## 🌟 Key Features

* **Real-Time Packet Dissection:** Leverages Scapy and low-level sockets to sniff network traffic directly from active network interfaces.
* **Sliding-Window Feature Extraction:** Aggregates packet streams into time-series feature vectors every 5 seconds (measuring packet rates, bandwidth throughput, TCP flag distributions, and IP/port dispersion).
* **Unsupervised Anomaly Detection:** Utilizes an **Isolation Forest** model to establish baseline normal behavior and detect statistical anomalies (e.g., TCP SYN Floods, port scanning) without requiring labeled attack signatures.
* **Zero Cloud Dependencies:** Operates entirely locally with zero external API calls or subscription costs.
* **WebSocket Telemetry:** Broadcasts detection events asynchronously to an interactive HTML5/Tailwind/Chart.js dashboard.
* **Persistent Logging:** Stores historical threat records locally in an SQLite database for auditing and offline research.
* **Integrated Attack Simulator:** Includes a built-in test suite to generate controlled SYN floods and port scan anomalies for empirical validation.

---

## 🛠️ Tech Stack & Dependencies

* **Language:** Python 3.10+
* **Packet Capture:** Scapy, Npcap (WinPcap API Mode)
* **Machine Learning:** `scikit-learn` (IsolationForest, StandardScaler), `pandas`, `numpy`, `joblib`
* **Backend API:** FastAPI, Uvicorn, WebSockets
* **Data Persistence:** SQLite3
* **Frontend Dashboard:** HTML5, Tailwind CSS, Chart.js

---

## 🚀 Installation & Quick Start

### 1. Prerequisites
* **Python 3.10+**
* **Npcap (Windows users):** Download and install from [npcap.com](https://npcap.com/#download). Ensure **"Install Npcap in WinPcap API-compatible Mode"** is checked during installation.

### 2. Clone the Repository
```powershell
git clone [https://github.com/shekinahomollo/network-ids-capstone.git](https://github.com/shekinahomollo/network-ids-capstone.git)
cd network-ids-capstone

⚙️ Usage Guide
Step 1: Train the Baseline ML Model
Train the Isolation Forest model on normal network behavior metrics:

PowerShell
python train_model.py
Outputs: ids_isolation_forest.joblib and ids_scaler.joblib

Step 2: Initialize Database
Set up the local SQLite database table:

PowerShell
python database.py
Outputs: ids_alerts.db

Step 3: Launch the Streaming Server
Start the FastAPI server with elevated Administrator privileges (required for raw packet socket access):

PowerShell
python server.py
Server runs at http://127.0.0.1:8000 with WebSocket endpoint at ws://127.0.0.1:8000/ws/alerts.

Step 4: Open the Live Dashboard
Double-click index.html or open it directly in any browser (Chrome, Edge, Firefox). Ensure the status badge displays "● WebSocket Connected".

Step 5: Simulate Attack Traffic (Validation)
Open a second PowerShell terminal, activate .venv, and run the attack simulator:

PowerShell
python attack_simulator.py
Select Option 1 (SYN Flood) or Option 2 (Port Scan) to observe real-time anomaly spikes and alert notifications on the web dashboard.

📂 Project Structure
Plaintext
network-ids-capstone/
│
├── sniffer.py           # Standalone low-level packet capture prototype
├── feature_extractor.py # 5-second sliding window feature engineering script
├── train_model.py       # Isolation Forest ML training & model exporter
├── ids_engine.py        # Integrated real-time CLI detection engine
├── server.py           # Asynchronous FastAPI & WebSocket server
├── database.py         # SQLite persistence and query handler
├── attack_simulator.py # Controlled SYN flood & port scan attack suite
├── index.html          # Interactive Chart.js & Tailwind web dashboard
├── .gitignore          # Git exclusion rules
└── README.md           # Project documentation
🎓 Academic Evaluation & Future Enhancements
Multi-Model Benchmark: Extending evaluation to compare Isolation Forest performance against One-Class SVM and Autoencoders.

Standard Dataset Testing: Running accuracy benchmarks against public intrusion datasets (e.g., CICIDS2017).

Automated Mitigation: Implementing dynamic firewall rule insertion (Windows Filtering Platform / iptables) upon high-confidence anomaly triggers.


---
   ```powershell
   notepad README.md
