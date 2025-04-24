from scapy.all import IP, TCP, UDP, ICMP

def extract_features(pkt):
    """
    Extract basic features from a packet for anomaly detection.

    Args:
        pkt: A scapy packet

    Returns:
        List of extracted features [size, proto, timestamp] or None if not an IP packet
    """
    if IP in pkt:
        # Basic packet features
        size = len(pkt)
        proto = pkt[IP].proto  # The protocol number (e.g., TCP = 6, UDP = 17)

        # Get timestamp and normalize it to second within a minute (0-59)
        timestamp = pkt.time % 60

        # Return only the 3 essential features
        features = [
            size,      # Total packet size
            proto,     # Protocol number
            timestamp  # Timestamp mod 60
        ]

        return features
    return None