from scapy.all import sniff, IP
from joblib import load
import numpy as np
from util import extract_features
import os
import time

# Constants for anomaly detection
ANOMALY_LABEL = "ANOMALY"
STATUS_UPDATE_INTERVAL = 100  # Print status every this many packets
WARNING_ICON = "⚠️"
NORMAL_ICON = "✅"

def monitor_traffic(interface, model_path, scaler_path):
    """
    Monitor network traffic in real-time and detect anomalies.

    Args:
        model_path (str): Path to the trained model file
        interface (str): Network interface to monitor
        scaler_path (str): Path to the scaler file, required for accurate predictions

    Returns:
        bool: True if monitoring completed successfully
    """
    # Check if model file exists
    if not os.path.exists(model_path):
        print(f"Error: Model file '{model_path}' not found.")
        return False

    # Check if scaler file exists
    if not os.path.exists(scaler_path):
        print(f"Error: Scaler file '{scaler_path}' not found. The model requires scaled features.")
        print("Please ensure you have trained the model properly.")
        return False

    try:
        # Load the model
        model = load(model_path)
        print(f"Model loaded from {model_path}")

        # Load the scaler - required for accurate predictions
        scaler = load(scaler_path)
        print("Feature scaler loaded from", scaler_path)

        # Statistics
        total_packets = 0
        anomalies = 0
        start_time = time.time()

        print(f"Monitoring traffic on interface {interface}...")
        print("Press Ctrl+C to stop monitoring")

        def packet_handler(pkt):
            nonlocal total_packets, anomalies

            if IP in pkt:
                total_packets += 1
                features = extract_features(pkt)

                if features:
                    x = np.array(features).reshape(1, -1)

                    # Apply scaling - required for accurate prediction
                    x = scaler.transform(x)

                    # Predict whether the packet is normal or anomalous
                    prediction = model.predict(x)[0]
                    score = model.decision_function(x)[0]

                    elapsed_time = time.time() - start_time
                    rate = total_packets / elapsed_time if elapsed_time > 0 else 0

                    if prediction == -1:  # Anomaly detected
                        anomalies += 1
                        anomaly_rate = (anomalies / total_packets) * 100
                        status_icon = WARNING_ICON if anomaly_rate >= 50 else NORMAL_ICON
                        status_text = "ALERT" if anomaly_rate >= 50 else "NORMAL"
                        print(f"[{ANOMALY_LABEL}] {pkt[IP].src} → {pkt[IP].dst}, size={features[0]}, proto={features[1]}, score={score:.4f}")
                        print(f"{status_icon} {status_text} - Stats: {total_packets} packets, {anomalies} anomalies ({anomaly_rate:.2f}%), {rate:.1f} pps")
                    elif total_packets % STATUS_UPDATE_INTERVAL == 0:  # Print status periodically
                        anomaly_rate = (anomalies / total_packets) * 100
                        status_icon = WARNING_ICON if anomaly_rate >= 50 else NORMAL_ICON
                        status_text = "ALERT" if anomaly_rate >= 50 else "NORMAL"
                        print(f"{status_icon} {status_text} - Stats: {total_packets} packets, {anomalies} anomalies ({anomaly_rate:.2f}%), {rate:.1f} pps")

        # Start sniffing packets
        sniff(iface=interface, prn=packet_handler, store=0)
        return True

    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
        if total_packets > 0:
            anomaly_rate = (anomalies / total_packets) * 100
            status_icon = WARNING_ICON if anomaly_rate >= 50 else NORMAL_ICON
            status_text = "ALERT" if anomaly_rate >= 50 else "NORMAL"
            print(f"{status_icon} {status_text} - Summary: {total_packets} packets processed, {anomalies} anomalies detected ({anomaly_rate:.2f}%)")
        return True
    except Exception as e:
        print(f"Error during monitoring: {str(e)}")
        return False
