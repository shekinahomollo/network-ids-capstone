import sys
import time
import os
import asyncio
import joblib
import pandas as pd
from typing import List
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import sniff, IP, TCP, UDP, get_working_if, IFACES

# Import database module
from database import init_db, log_alert, get_recent_alerts

MODEL_FILE = "ids_isolation_forest.joblib"
SCALER_FILE = "ids_scaler.joblib"
WINDOW_SIZE_SECONDS = 5

model = None
scaler = None

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"[*] WebSocket Client Connected. Active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            print(f"[*] WebSocket Client Disconnected. Active connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)
        for connection in disconnected:
            self.disconnect(connection)

manager = ConnectionManager()

def load_ml_artifacts():
    global model, scaler
    if not os.path.exists(MODEL_FILE) or not os.path.exists(SCALER_FILE):
        print(f"[!] Error: Model files ('{MODEL_FILE}', '{SCALER_FILE}') not found.")
        print("[!] Run 'python train_model.py' first.")
        sys.exit(1)
    model = joblib.load(MODEL_FILE)
    scaler = joblib.load(SCALER_FILE)
    print("[✓] Model & Scaler successfully loaded into FastAPI server.")

class AsyncIDSEngine:
    def __init__(self, loop, window_size=5):
        self.loop = loop
        self.window_size = window_size
        self.reset_window()

    def reset_window(self):
        self.start_time = time.time()
        self.packet_count = 0
        self.total_bytes = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.syn_count = 0
        self.dest_ips = set()
        self.dest_ports = set()

    def process_packet(self, packet):
        current_time = time.time()

        if packet.haslayer(IP):
            self.packet_count += 1
            self.total_bytes += len(packet)
            self.dest_ips.add(packet[IP].dst)

            if packet.haslayer(TCP):
                self.tcp_count += 1
                self.dest_ports.add(packet[TCP].dport)
                if 'S' in str(packet[TCP].flags):
                    self.syn_count += 1
            elif packet.haslayer(UDP):
                self.udp_count += 1
                self.dest_ports.add(packet[UDP].dport)

        if current_time - self.start_time >= self.window_size:
            self.evaluate_and_broadcast()
            self.reset_window()

    def evaluate_and_broadcast(self):
        elapsed = time.time() - self.start_time
        pkt_rate = round(self.packet_count / elapsed, 2)
        byte_rate = round(self.total_bytes / elapsed, 2)
        avg_pkt_size = round(self.total_bytes / max(1, self.packet_count), 2)
        syn_ratio = round(self.syn_count / max(1, self.tcp_count), 2)
        unique_dst_ips = len(self.dest_ips)
        unique_dst_ports = len(self.dest_ports)

        feature_names = [
            "pkt_rate", "byte_rate", "avg_pkt_size", "tcp_count",
            "udp_count", "syn_ratio", "unique_dst_ips", "unique_dst_ports"
        ]
        
        raw_features = pd.DataFrame([[
            pkt_rate, byte_rate, avg_pkt_size, self.tcp_count,
            self.udp_count, syn_ratio, unique_dst_ips, unique_dst_ports
        ]], columns=feature_names)

        scaled_features = scaler.transform(raw_features)
        prediction = model.predict(scaled_features)[0]
        anomaly_score = float(model.decision_function(scaled_features)[0])
        status = "ANOMALY" if prediction == -1 else "NORMAL"

        # 1. Log alert into SQLite database
        try:
            log_alert(status, anomaly_score, pkt_rate, byte_rate, syn_ratio, unique_dst_ips)
        except Exception as e:
            print(f"[!] Database logging error: {e}")

        # 2. Prepare WebSocket payload
        payload = {
            "timestamp": time.strftime("%H:%M:%S"),
            "status": status,
            "anomaly_score": round(anomaly_score, 4),
            "metrics": {
                "pkt_rate": pkt_rate,
                "byte_rate": byte_rate,
                "avg_pkt_size": avg_pkt_size,
                "tcp_count": self.tcp_count,
                "udp_count": self.udp_count,
                "syn_ratio": syn_ratio,
                "unique_dst_ips": unique_dst_ips,
                "unique_dst_ports": unique_dst_ports
            }
        }

        # 3. Broadcast to all active dashboard connections
        asyncio.run_coroutine_threadsafe(manager.broadcast(payload), self.loop)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite table on startup
    init_db()
    load_ml_artifacts()
    loop = asyncio.get_running_loop()

    active_iface = None
    for iface in IFACES.values():
        name_lower = iface.name.lower()
        if "wi-fi" in name_lower or "wifi" in name_lower or "wireless" in name_lower:
            active_iface = iface
            break
    if not active_iface:
        active_iface = get_working_if()

    engine = AsyncIDSEngine(loop=loop, window_size=WINDOW_SIZE_SECONDS)
    loop.run_in_executor(None, lambda: sniff(iface=active_iface, prn=engine.process_packet, store=False))
    print(f"[*] Background packet sniffer started on: {active_iface.name}")
    yield
    print("[*] Server shutting down.")

app = FastAPI(title="Network IDS Streaming API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def health_check():
    return {"status": "online", "service": "Capstone IDS Streaming Server"}

@app.get("/api/logs")
def fetch_logs(limit: int = 50):
    """REST API endpoint to retrieve historical alert logs from SQLite."""
    logs = get_recent_alerts(limit=limit)
    return {"count": len(logs), "logs": logs}

@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)