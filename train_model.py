import os
import sys
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MODEL_FILE = "ids_isolation_forest.joblib"
SCALER_FILE = "ids_scaler.joblib"

def generate_synthetic_normal_traffic(samples=1000):
    """
    Generates synthetic feature vectors representing baseline normal network activity.
    In later phases, this can be replaced by saving real captured window logs.
    
    Features:
    [pkt_rate, byte_rate, avg_pkt_size, tcp_count, udp_count, syn_ratio, unique_dst_ips, unique_dst_ports]
    """
    np.random.seed(42)
    
    # Baseline normal web browsing distributions
    pkt_rate = np.random.normal(loc=25.0, scale=10.0, size=samples)
    byte_rate = np.random.normal(loc=15000.0, scale=5000.0, size=samples)
    avg_pkt_size = np.random.normal(loc=500.0, scale=150.0, size=samples)
    tcp_count = np.random.normal(loc=20.0, scale=8.0, size=samples)
    udp_count = np.random.normal(loc=5.0, scale=3.0, size=samples)
    syn_ratio = np.random.beta(a=0.5, b=5.0, size=samples)  # Low SYN ratio normally
    unique_dst_ips = np.random.poisson(lam=3.0, size=samples) + 1
    unique_dst_ports = np.random.poisson(lam=2.0, size=samples) + 1

    data = np.column_stack([
        np.maximum(1.0, pkt_rate),
        np.maximum(100.0, byte_rate),
        np.maximum(64.0, avg_pkt_size),
        np.maximum(0, tcp_count),
        np.maximum(0, udp_count),
        np.clip(syn_ratio, 0.0, 1.0),
        np.maximum(1, unique_dst_ips),
        np.maximum(1, unique_dst_ports)
    ])
    
    feature_names = [
        "pkt_rate", "byte_rate", "avg_pkt_size", "tcp_count", 
        "udp_count", "syn_ratio", "unique_dst_ips", "unique_dst_ports"
    ]
    return pd.DataFrame(data, columns=feature_names)

def train_and_save_model():
    print("=" * 60)
    print("      Capstone IDS — Anomaly Detection Model Trainer       ")
    print("=" * 60)

    print("[*] Generating baseline normal network traffic dataset...")
    df = generate_synthetic_normal_traffic(samples=1200)

    print("[*] Scaling feature distributions...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df)

    print("[*] Training Isolation Forest model...")
    # contamination=0.03 means we expect ~3% extreme outliers in wild traffic
    model = IsolationForest(n_estimators=100, contamination=0.03, random_state=42)
    model.fit(X_scaled)

    print(f"[*] Saving trained model to '{MODEL_FILE}'...")
    joblib.dump(model, MODEL_FILE)
    
    print(f"[*] Saving feature scaler to '{SCALER_FILE}'...")
    joblib.dump(scaler, SCALER_FILE)

    print("\n[✓] Model training successfully completed!")

if __name__ == "__main__":
    train_and_save_model()