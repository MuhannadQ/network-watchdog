from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from joblib import dump
import os
from visualization import plot_anomaly_scores, plot_packet_features

# Define required feature columns for the model
FEATURE_COLS = ['size', 'proto', 'time']
# Default parameters
DEFAULT_CONTAMINATION = 0.1
DEFAULT_TEST_SIZE = 0.2
DEFAULT_RANDOM_STATE = 42

def train_model(data_file, model_path, scaler_path, contamination=DEFAULT_CONTAMINATION,
               test_size=DEFAULT_TEST_SIZE, plot=True):
    """
    Train the Isolation Forest model with preprocessed data.

    Args:
        data_file (str): Path to CSV file with preprocessed packet data
        model_path (str): Path to save the trained model
        scaler_path (str): Path to save the feature scaler
        contamination (float): Expected proportion of anomalies (0.0-0.5)
        test_size (float): Proportion of data to use for testing
        plot (bool): Whether to generate evaluation plots

    Returns:
        bool: True if training was successful
    """
    try:
        print(f"Loading data from {data_file}...")
        df = pd.read_csv(data_file)

        # Check if we have the expected features
        if set(FEATURE_COLS).issubset(df.columns):
            # We only have the basic features
            print("Warning: Using limited feature set. Consider recapturing with updated code.")
        else:
            # Doesn't match expected format
            print("Error: CSV file does not have the expected columns.")
            return False

        # Extract features
        X = df[FEATURE_COLS].values

        # Simple scaling approach for our 3 features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # Split into train and test sets
        X_train, X_test = train_test_split(X_scaled, test_size=test_size, random_state=DEFAULT_RANDOM_STATE)

        print(f"Training Isolation Forest model with {X_train.shape[0]} samples...")
        # Initialize and train the model
        model = IsolationForest(contamination=contamination, random_state=DEFAULT_RANDOM_STATE)
        model.fit(X_train)

        # Evaluate on test data
        test_predictions = model.predict(X_test)
        test_scores = model.decision_function(X_test)

        # Count anomalies in test set
        anomaly_count = np.sum(test_predictions == -1)
        normal_count = np.sum(test_predictions == 1)
        print(f"Model evaluation on test set: {anomaly_count} anomalies detected ({anomaly_count/len(test_predictions):.2%})")
        print(f"                             {normal_count} normal packets ({normal_count/len(test_predictions):.2%})")

        if plot:
            # Generate histogram of anomaly scores
            if plot_anomaly_scores(test_scores):
                print("Saved anomaly score distribution to 'anomaly_scores.png'")

            # Generate feature distribution plots
            if plot_packet_features(df):
                print("Saved packet feature distributions to 'packet_features.png'")

        # Save both the model and the scaler
        dump(model, model_path)
        dump(scaler, scaler_path)
        print(f"Model training complete and saved as '{model_path}'")
        print(f"Scaler saved as '{scaler_path}'")

        return True

    except Exception as e:
        print(f"Error during model training: {str(e)}")
        return False
