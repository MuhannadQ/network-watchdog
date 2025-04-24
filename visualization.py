import matplotlib.pyplot as plt
import numpy as np

# Map common protocol numbers to names
PROTO_MAP = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    47: 'GRE',
    50: 'ESP',
    58: 'ICMPv6',
    89: 'OSPF',
    132: 'SCTP'
    # Add more protocols as needed
}

def plot_anomaly_scores(scores, output_file='anomaly_scores.png'):
    """
    Generate a histogram of anomaly scores from the model.

    Args:
        scores (array): Array of anomaly scores from model.decision_function()
        output_file (str): Path to save the plot image

    Returns:
        bool: True if plot was successfully created and saved
    """
    try:
        # Generate histogram of anomaly scores
        plt.figure(figsize=(10, 6))
        plt.hist(scores, bins=50, alpha=0.8)
        plt.axvline(x=0, color='r', linestyle='--', label='Decision Boundary')
        plt.xlabel('Anomaly Score')
        plt.ylabel('Count')
        plt.title('Distribution of Anomaly Scores')
        plt.legend()
        plt.savefig(output_file)
        plt.close()  # Close the figure to free memory
        return True
    except Exception as e:
        print(f"Could not generate plot: {str(e)}")
        return False

def plot_packet_features(df, output_file='packet_features.png'):
    """
    Generate plots visualizing the distribution of packet features.

    Args:
        df (DataFrame): DataFrame containing packet features
        output_file (str): Path to save the plot image

    Returns:
        bool: True if plot was successfully created and saved
    """
    try:
        feature_cols = ['size', 'proto', 'time']
        if not all(col in df.columns for col in feature_cols):
            print("Error: DataFrame missing required feature columns")
            return False

        fig, axs = plt.subplots(1, 3, figsize=(15, 5))

        # Plot size distribution
        axs[0].hist(df['size'], bins=30, color='skyblue', edgecolor='black')
        axs[0].set_title('Packet Size Distribution')
        axs[0].set_xlabel('Packet Size (bytes)')
        axs[0].set_ylabel('Count')
        axs[0].grid(True, linestyle='--', alpha=0.7)

        # Plot protocol distribution with proper labels
        proto_counts = df['proto'].value_counts().sort_index()
        labels = [PROTO_MAP.get(p, str(p)) for p in proto_counts.index]

        axs[1].bar(range(len(labels)), proto_counts.values, color='lightgreen')
        axs[1].set_xticks(range(len(labels)))
        axs[1].set_xticklabels(labels, rotation=45)
        axs[1].set_title('Protocol Distribution')
        axs[1].set_xlabel('Protocol')
        axs[1].set_ylabel('Count')
        axs[1].grid(True, axis='y', linestyle='--', alpha=0.7)

        # Plot time distribution
        axs[2].hist(df['time'], bins=60, color='salmon', edgecolor='black')
        axs[2].set_title('Packet Timing Distribution')
        axs[2].set_xlabel('Time (seconds in minute)')
        axs[2].set_ylabel('Count')
        axs[2].grid(True, linestyle='--', alpha=0.7)

        plt.tight_layout()
        plt.savefig(output_file, dpi=300)  # Higher resolution
        plt.close()
        return True
    except Exception as e:
        print(f"Could not generate feature plots: {str(e)}")
        print(f"DataFrame shape: {df.shape}, columns: {df.columns}")
        if 'proto' in df.columns:
            print(f"Protocol values: {df['proto'].unique()}")
        return False