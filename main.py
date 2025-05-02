# source .venv/bin/activate
# uv pip install <package_name>

import argparse
from capture import capture_packets, preprocess_pcap
from train import train_model
from monitor import monitor_traffic
import os

MODEL_PATH = "model.joblib"
SCALER_PATH = "scaler.joblib"
PCAP_PATH = "traffic.pcap"
CSV_PATH = "traffic.csv"
INTERFACE = "eth1"

def main():
    parser = argparse.ArgumentParser(description="Traffic Anomaly Detection")
    parser.add_argument('action', choices=['capture', 'train', 'monitor'], help="Action to perform: capture, train, or monitor")
    parser.add_argument('--interface', '-i', help="Network interface to use (default: %(default)s)", default=INTERFACE)
    parser.add_argument('--count', '-c', type=int, help="Number of packets to capture (default: %(default)s, 0 for unlimited)", default = 0)
    parser.add_argument('--model', '-m', help="Path to model file (default: %(default)s)", default=MODEL_PATH)
    parser.add_argument('--scaler', '-s', help="Path to scaler file (default: %(default)s)", default=SCALER_PATH)
    parser.add_argument('--pcap', '-p', help="Path to PCAP file (default: %(default)s)", default=PCAP_PATH)
    parser.add_argument('--csv', help="Path to CSV file (default: %(default)s)", default=CSV_PATH)
    args = parser.parse_args()

    try:
        if args.action == 'capture':
            if args.count == 0:
                print("Starting unlimited packet capture on interface {}. Press Ctrl+C to stop.".format(args.interface))
            else:
                print(f"Capturing {args.count} packets on interface {args.interface}...")

            if capture_packets(args.interface, args.count, args.pcap):
                preprocess_pcap(args.pcap, args.csv)

        elif args.action == 'train':
            if not os.path.exists(args.csv):
                print(f"Error: CSV file '{args.csv}' not found. Capture packets first.")
                return

            train_model(args.csv, args.model, args.scaler)

        elif args.action == 'monitor':
            if not os.path.exists(args.model):
                print(f"Error: Model file '{args.model}' not found. Train the model first.")
                return

            if not os.path.exists(args.scaler):
                print(f"Error: Scaler file '{args.scaler}' not found. The model requires scaled features.")
                print("Please ensure you have trained the model properly.")
                return

            monitor_traffic(args.interface, args.model, args.scaler)

    except KeyboardInterrupt:
        print("\nProgram terminated by user.")
    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == "__main__":
    main()
