import os
import sys
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_curve,
    auc,
    precision_recall_fscore_support
)

MODEL_FILE = "ids_isolation_forest.joblib"
SCALER_FILE = "ids_scaler.joblib"

def generate_evaluation_dataset(n_normal=800, n_attack=200):
    """
    Generates a synthetic ground-truth test dataset containing both normal 
    network browsing and attack traffic patterns (SYN floods & port scans).
    
    Labels: 0 = Normal, 1 = Anomaly / Attack
    """
    np.random.seed(101)
    
    # 1. Normal Traffic Distribution
    norm_pkt = np.random.normal(loc=25.0, scale=10.0, size=n_normal)
    norm_byte = np.random.normal(loc=15000.0, scale=5000.0, size=n_normal)
    norm_size = np.random.normal(loc=500.0, scale=150.0, size=n_normal)
    norm_tcp = np.random.normal(loc=20.0, scale=8.0, size=n_normal)
    norm_udp = np.random.normal(loc=5.0, scale=3.0, size=n_normal)
    norm_syn = np.random.beta(a=0.5, b=5.0, size=n_normal)
    norm_ips = np.random.poisson(lam=3.0, size=n_normal) + 1
    norm_ports = np.random.poisson(lam=2.0, size=n_normal) + 1

    normal_data = np.column_stack([
        np.maximum(1.0, norm_pkt), np.maximum(100.0, norm_byte),
        np.maximum(64.0, norm_size), np.maximum(0, norm_tcp),
        np.maximum(0, norm_udp), np.clip(norm_syn, 0.0, 1.0),
        np.maximum(1, norm_ips), np.maximum(1, norm_ports)
    ])
    normal_labels = np.zeros(n_normal, dtype=int)

    # 2. Attack Traffic Distribution (SYN Floods & Scans)
    atk_pkt = np.random.normal(loc=180.0, scale=50.0, size=n_attack)
    atk_byte = np.random.normal(loc=85000.0, scale=20000.0, size=n_attack)
    atk_size = np.random.normal(loc=120.0, scale=30.0, size=n_attack)
    atk_tcp = np.random.normal(loc=170.0, scale=45.0, size=n_attack)
    atk_udp = np.random.normal(loc=2.0, scale=1.5, size=n_attack)
    atk_syn = np.random.beta(a=8.0, b=1.5, size=n_attack)  # High SYN Ratio
    atk_ips = np.random.poisson(lam=12.0, size=n_attack) + 1
    atk_ports = np.random.poisson(lam=35.0, size=n_attack) + 1

    attack_data = np.column_stack([
        np.maximum(1.0, atk_pkt), np.maximum(100.0, atk_byte),
        np.maximum(64.0, atk_size), np.maximum(0, atk_tcp),
        np.maximum(0, atk_udp), np.clip(atk_syn, 0.0, 1.0),
        np.maximum(1, atk_ips), np.maximum(1, atk_ports)
    ])
    attack_labels = np.ones(n_attack, dtype=int)

    X = np.vstack([normal_data, attack_data])
    y = np.hstack([normal_labels, attack_labels])

    feature_names = [
        "pkt_rate", "byte_rate", "avg_pkt_size", "tcp_count",
        "udp_count", "syn_ratio", "unique_dst_ips", "unique_dst_ports"
    ]
    return pd.DataFrame(X, columns=feature_names), y

def evaluate():
    print("=" * 65)
    print("      Capstone IDS — Model Benchmark & Empirical Evaluation     ")
    print("=" * 65)

    if not os.path.exists(MODEL_FILE) or not os.path.exists(SCALER_FILE):
        print(f"[!] Error: Trained artifacts ('{MODEL_FILE}', '{SCALER_FILE}') not found.")
        print("[!] Run 'python train_model.py' first.")
        sys.exit(1)

    print("[*] Loading model weights and feature scaler...")
    model = joblib.load(MODEL_FILE)
    scaler = joblib.load(SCALER_FILE)

    print("[*] Generating ground-truth test evaluation dataset (1000 samples)...")
    X_test, y_true = generate_evaluation_dataset(n_normal=800, n_attack=200)

    # Scale features
    X_test_scaled = scaler.transform(X_test)

    # Predictions (IsolationForest output: 1 for normal, -1 for anomaly)
    raw_preds = model.predict(X_test_scaled)
    y_pred = np.where(raw_preds == -1, 1, 0)  # Map to 0 = Normal, 1 = Anomaly

    # Decision scores for ROC (higher anomaly score -> negative decision_function output)
    anomaly_scores = -model.decision_function(X_test_scaled)

    # Compute Classification Metrics
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary')
    
    print("\n" + "=" * 50)
    print("           CLASSIFICATION REPORT SUMMARY           ")
    print("=" * 50)
    print(classification_report(y_true, y_pred, target_names=["Normal Traffic", "Anomaly / Attack"]))
    
    print(f"  Accuracy / F1-Score Summary:")
    print(f"   - Precision : {precision:.4f}")
    print(f"   - Recall    : {recall:.4f}")
    print(f"   - F1-Score  : {f1:.4f}")
    print("=" * 50)

    # Plot Confusion Matrix and ROC Curve
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    # 1. Confusion Matrix
    cm = confusion_matrix(y_true, y_pred)
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", ax=axes[0],
                xticklabels=["Normal", "Attack"], yticklabels=["Normal", "Attack"])
    axes[0].set_title("IDS Confusion Matrix", fontsize=12, fontweight="bold")
    axes[0].set_xlabel("Predicted Label")
    axes[0].set_ylabel("True Ground-Truth Label")

    # 2. ROC Curve
    fpr, tpr, _ = roc_curve(y_true, anomaly_scores)
    roc_auc = auc(fpr, tpr)

    axes[1].plot(fpr, tpr, color="darkorange", lw=2, label=f"ROC Curve (AUC = {roc_auc:.4f})")
    axes[1].plot([0, 1], [0, 1], color="navy", lw=2, linestyle="--", label="Random Baseline")
    axes[1].set_xlim([0.0, 1.0])
    axes[1].set_ylim([0.0, 1.05])
    axes[1].set_xlabel("False Positive Rate (FPR)")
    axes[1].set_ylabel("True Positive Rate (TPR)")
    axes[1].set_title("Receiver Operating Characteristic (ROC)", fontsize=12, fontweight="bold")
    axes[1].legend(loc="lower right")
    axes[1].grid(alpha=0.3)

    plt.tight_layout()
    output_fig = "model_evaluation_metrics.png"
    plt.savefig(output_fig, dpi=300)
    print(f"\n[✓] Evaluation plots saved to '{output_fig}' for academic report insertion!")
    
    # Render plot window
    plt.show()

if __name__ == "__main__":
    evaluate()