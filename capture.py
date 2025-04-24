from scapy.all import sniff, wrpcap, rdpcap, IP
import pandas as pd
from util import extract_features
import os
import sys

def capture_packets(interface, count, output_file):
    """
    Capture network packets from specified interface and save to PCAP file.

    Args:
        interface (str): Network interface to capture from
        count (int, optional): Number of packets to capture. If None, capture until interrupted.
        output_file (str): Output PCAP file path

    Returns:
        bool: True if capture was successful
    """
    captured_packets = []

    try:
        def packet_handler(pkt):
            captured_packets.append(pkt)
            if count:
                sys.stdout.write(f"\rCaptured {len(captured_packets)}/{count} packets")
            else:
                sys.stdout.write(f"\rCaptured {len(captured_packets)} packets")
            sys.stdout.flush()

        sniff(
            iface=interface,
            prn=packet_handler,
            store=0,
            count=count  # When None, Scapy will capture indefinitely
        )

        print(f"\nCapture complete. Saving {len(captured_packets)} packets to {output_file}")
        wrpcap(output_file, captured_packets)
        print(f"Packets saved to {output_file}")
        return True

    except OSError as e:
        print(f"Error: Could not capture on interface '{interface}'. {str(e)}")
        return False
    except KeyboardInterrupt:
        print("\nCapture interrupted. Saving packets captured so far...")
        if captured_packets:
            wrpcap(output_file, captured_packets)
            print(f"Packets saved to {output_file}")
            return len(captured_packets) > 0
        return False
    except Exception as e:
        print(f"Unexpected error during capture: {str(e)}")
        return False


def preprocess_pcap(pcap_file, csv_file):
    """
    Process a PCAP file to extract features for anomaly detection.

    Args:
        pcap_file (str): Input PCAP file path
        csv_file (str): Output CSV file path

    Returns:
        bool: True if preprocessing was successful
    """
    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file '{pcap_file}' not found.")
        return False

    try:
        # Read packets from the provided PCAP file
        print(f"Reading packets from {pcap_file}...")
        pkts = rdpcap(pcap_file)
        features_data = []
        ip_packet_count = 0
        total_packets = len(pkts)

        if total_packets == 0:
            print("Error: PCAP file contains no packets.")
            return False

        # Extract features from each packet
        for i, pkt in enumerate(pkts):
            if i % 100 == 0:
                sys.stdout.write(f"\rProcessing packets: {i}/{total_packets}")
                sys.stdout.flush()

            features = extract_features(pkt)
            if features:
                features_data.append({
                    "src": pkt[IP].src,
                    "dst": pkt[IP].dst,
                    "size": features[0],
                    "proto": features[1],
                    "time": features[2]
                })
                ip_packet_count += 1

        # Convert the features list to a DataFrame
        print(f"\nExtracted features from {ip_packet_count} IP packets (out of {total_packets} total packets)")
        if not features_data:
            print("No IP packets found in the capture.")
            return False

        df = pd.DataFrame(features_data)
        df.to_csv(csv_file, index=False)
        print(f"Preprocessing complete and saved to '{csv_file}'.")
        return True

    except Exception as e:
        print(f"Error processing PCAP file: {str(e)}")
        return False
