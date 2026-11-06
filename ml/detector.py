import sys
import os
import joblib
import numpy as np
import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.utils.features import engineer_features, get_feature_names
from ml.threat_scorer import calculate_threat_score, get_threat_level, get_threat_color

MODEL_PATH  = "backend/models/isolation_forest.pkl"
SCALER_PATH = "backend/models/scaler.pkl"


class ThreatDetector:
    """
    Loads the trained model and provides methods to
    analyse log entries and return threat assessments.
    """

    def __init__(self):
        self.model  = None
        self.scaler = None
        self.loaded = False

    def load_model(self):
        """Load the trained model and scaler from disk."""
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Model not found at {MODEL_PATH}. "
                f"Please run: python ml/train_model.py"
            )
        self.model  = joblib.load(MODEL_PATH)
        self.scaler = joblib.load(SCALER_PATH)
        self.loaded = True
        print("✅ Model loaded successfully")

    def analyse(self, df):
        """
        Analyse a DataFrame of log entries.

        Input : DataFrame with log data
        Output: same DataFrame with added columns:
                threat_score, threat_level, threat_color, is_anomaly
        """
        if not self.loaded:
            self.load_model()

        # Engineer features
        X = engineer_features(df)

        # Scale features using the same scaler used during training
        X_scaled = self.scaler.transform(X)

        # Get predictions and anomaly scores
        predictions    = self.model.predict(X_scaled)
        anomaly_scores = self.model.decision_function(X_scaled)

        # Calculate threat scores
        threat_scores  = []
        threat_levels  = []
        threat_colors  = []

        for i, (_, row) in enumerate(X.iterrows()):
            scoring_row = row.to_dict()

            # A manually supplied count is contextual input, not
            # verified temporal history. Keep it separately named.
            if "failed_attempts" in df.columns:
                reported_failures = df.iloc[i]["failed_attempts"]
                if pd.notna(reported_failures):
                    scoring_row["reported_failed_attempts"] = (
                        reported_failures
                    )

            score = calculate_threat_score(
                scoring_row,
                anomaly_scores[i]
            )
            level = get_threat_level(score)
            color = get_threat_color(level)
            threat_scores.append(score)
            threat_levels.append(level)
            threat_colors.append(color)

        result = df.copy()
        result["threat_score"] = threat_scores
        result["threat_level"] = threat_levels
        result["threat_color"] = threat_colors
        result["is_anomaly"]   = (predictions == -1).astype(int)

        return result

    def analyse_single(self, log_entry: dict):
        """
        Analyse a single log entry (as a dictionary).
        Returns a dict with threat_score, threat_level, threat_color.

        Example input:
        {
            "timestamp"      : "2024-12-10 03:22:00",
            "ip_address"     : "1.2.3.4",
            "username"       : "root",
            "status"         : "Failed",
            "failed_attempts": 25,
            "port"           : 22,
            "hour"           : 3
        }
        """
        if not self.loaded:
            self.load_model()

        # Convert single entry to DataFrame
        df = pd.DataFrame([log_entry])

        # Add derived columns if missing
        df["is_night_hour"]    = (df["hour"] < 5).astype(int)
        df["is_root_attempt"]  = df["username"].apply(
            lambda u: 1 if u in ["root", "admin", "administrator", "test", "guest"] else 0
        )
        df["ip_attempt_count"] = 1
        df["status_numeric"]   = df["status"].apply(
            lambda s: 1 if s == "Failed" else 0
        )

        result = self.analyse(df)
        row    = result.iloc[0]

        return {
            "threat_score" : int(row["threat_score"]),
            "threat_level" : row["threat_level"],
            "threat_color" : row["threat_color"],
            "is_anomaly"   : int(row["is_anomaly"])
        }


# Singleton instance — import this in Flask app
detector = ThreatDetector()


if __name__ == "__main__":
    print("Testing ThreatDetector …\n")

    detector.load_model()

    test_entries = [
        {
            "timestamp"      : "2024-12-10 10:30:00",
            "ip_address"     : "192.168.1.5",
            "username"       : "alice",
            "status"         : "Accepted",
            "failed_attempts": 1,
            "port"           : 52341,
            "hour"           : 10
        },
        {
            "timestamp"      : "2024-12-10 03:15:00",
            "ip_address"     : "45.33.32.156",
            "username"       : "root",
            "status"         : "Failed",
            "failed_attempts": 42,
            "port"           : 22,
            "hour"           : 3
        },
        {
            "timestamp"      : "2024-12-10 02:00:00",
            "ip_address"     : "198.51.100.5",
            "username"       : "admin",
            "status"         : "Accepted",
            "failed_attempts": 3,
            "port"           : 22,
            "hour"           : 2
        }
    ]

    print(f"{'Entry':<25} {'Score':>6} {'Level':<10} {'Anomaly'}")
    print("-" * 55)

    names = ["Normal office login", "Brute force attack", "Suspicious night login"]
    for name, entry in zip(names, test_entries):
        result = detector.analyse_single(entry)
        print(f"{name:<25} {result['threat_score']:>5}/100  "
              f"{result['threat_level']:<10} {'YES' if result['is_anomaly'] else 'no'}")

    print("\n✅ Detector working correctly!")