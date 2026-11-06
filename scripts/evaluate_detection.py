from pathlib import Path
import sys

# Ensure the project root is available for backend/ml imports.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    precision_recall_curve,
)

from backend.utils.features import engineer_features
from backend.utils.rule_engine import evaluate_rules


TRAIN_DATA = ROOT / "data" / "sample_logs.csv"
INDEPENDENT_DATA = (
    ROOT / "data" / "evaluation" / "independent_test.csv"
)

CUTOFF = pd.Timestamp("2026-10-06 00:00:00")

FEATURE_INPUTS = [
    "timestamp",
    "ip_address",
    "username",
    "status",
]


def load_dataset(path):
    df = pd.read_csv(path)

    required = set(
        FEATURE_INPUTS + [
            "is_suspicious",
            "attack_type",
            "scenario_id",
        ]
    )

    missing = required.difference(df.columns)

    if missing:
        raise ValueError(
            f"{path.name}: missing columns {sorted(missing)}"
        )

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="raise",
    )

    df = df.sort_values(
        "timestamp",
        kind="stable",
    ).reset_index(drop=True)

    df["is_suspicious"] = (
        df["is_suspicious"].astype(int)
    )

    return df


def calculate_metrics(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1],
    ).ravel()

    precision = precision_score(
        y_true,
        y_pred,
        zero_division=0,
    )

    recall = recall_score(
        y_true,
        y_pred,
        zero_division=0,
    )

    f1 = f1_score(
        y_true,
        y_pred,
        zero_division=0,
    )

    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "TP": int(tp),
        "FP": int(fp),
        "FN": int(fn),
        "TN": int(tn),
        "Precision": precision,
        "Recall": recall,
        "F1": f1,
        "FPR": fpr,
    }


def print_metrics(name, y_true, y_pred):
    result = calculate_metrics(y_true, y_pred)

    print(f"\n{name}")
    print("-" * len(name))

    print(
        f"TP={result['TP']}  "
        f"FP={result['FP']}  "
        f"FN={result['FN']}  "
        f"TN={result['TN']}"
    )

    print(f"Precision: {result['Precision']:.4f}")
    print(f"Recall:    {result['Recall']:.4f}")
    print(f"F1:        {result['F1']:.4f}")
    print(f"FPR:       {result['FPR']:.4f}")

    return result


def select_validation_threshold(y_true, anomaly_strength):
    precision, recall, thresholds = precision_recall_curve(
        y_true,
        anomaly_strength,
    )

    if len(thresholds) == 0:
        raise RuntimeError(
            "Could not calculate a validation threshold."
        )

    f1_values = (
        2 * precision[:-1] * recall[:-1]
        / np.maximum(
            precision[:-1] + recall[:-1],
            1e-12,
        )
    )

    best_index = int(np.argmax(f1_values))

    return float(thresholds[best_index]), float(
        f1_values[best_index]
    )


def scenario_metrics(df, predictions):
    work = df.copy()
    work["prediction"] = predictions

    attacks = work[
        (work["is_suspicious"] == 1)
        & work["scenario_id"].notna()
    ]

    if attacks.empty:
        print("No labelled attack scenarios available.")
        return

    grouped = attacks.groupby("scenario_id")["prediction"]

    detected = int(grouped.max().sum())
    fully_detected = int(grouped.min().sum())
    total = int(grouped.ngroups)

    print(
        f"Scenarios detected at least once: "
        f"{detected}/{total} ({detected / total:.2%})"
    )

    print(
        f"Scenarios with every attack event detected: "
        f"{fully_detected}/{total} "
        f"({fully_detected / total:.2%})"
    )


def attack_type_recall(df, predictions):
    work = df.copy()
    work["prediction"] = predictions

    print("\nRecall by attack type:")

    attacks = work[work["is_suspicious"] == 1]

    for attack_type, group in attacks.groupby("attack_type"):
        detected = int(group["prediction"].sum())
        total = len(group)

        print(
            f"{attack_type:<22} "
            f"{detected:>4}/{total:<4} "
            f"recall={detected / total:.4f}"
        )


def prepare_features(df):
    # Only these four operational fields enter feature engineering.
    # Ground-truth labels and scenario identifiers are excluded.
    return engineer_features(df[FEATURE_INPUTS].copy())


def main():
    print("=" * 65)
    print("THREAT DETECTION — CHRONOLOGICAL EVALUATION")
    print("=" * 65)

    original = load_dataset(TRAIN_DATA)
    independent = load_dataset(INDEPENDENT_DATA)

    train_mask = original["timestamp"] < CUTOFF
    validation_mask = ~train_mask

    train_df = original.loc[train_mask].copy()
    validation_df = original.loc[validation_mask].copy()

    if train_df.empty or validation_df.empty:
        raise RuntimeError("Chronological split is empty.")

    print("\nDataset sizes")
    print("-------------")
    print("Training:", len(train_df))
    print("Validation:", len(validation_df))
    print("Independent test:", len(independent))

    print("\nTraining dates:")
    print(train_df["timestamp"].min(), "to",
          train_df["timestamp"].max())

    print("\nValidation dates:")
    print(validation_df["timestamp"].min(), "to",
          validation_df["timestamp"].max())

    # Causal features are computed in timestamp order.
    # Earlier events may inform later events; future events cannot.
    X_original = prepare_features(original)
    X_independent = prepare_features(independent)

    X_train = X_original.loc[train_mask]
    X_validation = X_original.loc[validation_mask]

    y_train = train_df["is_suspicious"].to_numpy()
    y_validation = validation_df["is_suspicious"].to_numpy()
    y_independent = independent["is_suspicious"].to_numpy()

    scaler = StandardScaler()

    X_train_scaled = scaler.fit_transform(X_train)
    X_validation_scaled = scaler.transform(X_validation)
    X_independent_scaled = scaler.transform(X_independent)

    model = IsolationForest(
        n_estimators=200,
        contamination=0.25,
        random_state=42,
        n_jobs=-1,
    )

    # Fit only on the chronological training partition.
    model.fit(X_train_scaled)

    # Higher values mean more anomalous.
    validation_strength = -model.decision_function(
        X_validation_scaled
    )

    independent_strength = -model.decision_function(
        X_independent_scaled
    )

    threshold, validation_best_f1 = (
        select_validation_threshold(
            y_validation,
            validation_strength,
        )
    )

    print("\nML threshold selection")
    print("----------------------")
    print(f"Selected on validation: {threshold:.8f}")
    print(f"Best validation F1: {validation_best_f1:.4f}")
    print("Independent test was not used for threshold selection.")

    ml_validation = (
        validation_strength >= threshold
    ).astype(int)

    ml_independent = (
        independent_strength >= threshold
    ).astype(int)

    # Rule engine evaluates the complete chronological stream.
    # Only validation-period predictions are measured.
    original_rules = evaluate_rules(
        original[FEATURE_INPUTS].copy()
    )

    validation_rules = original_rules.loc[
        validation_mask
    ]

    rule_validation = (
        validation_rules["is_rule_alert"]
        .astype(int)
        .to_numpy()
    )

    independent_rules = evaluate_rules(
        independent[FEATURE_INPUTS].copy()
    )

    rule_independent = (
        independent_rules["is_rule_alert"]
        .astype(int)
        .to_numpy()
    )

    # Combined policy: alert if either independent detector alerts.
    combined_validation = np.logical_or(
        ml_validation,
        rule_validation,
    ).astype(int)

    combined_independent = np.logical_or(
        ml_independent,
        rule_independent,
    ).astype(int)

    print("\n" + "=" * 65)
    print("VALIDATION RESULTS — ORIGINAL DATASET")
    print("=" * 65)

    print_metrics(
        "ML only",
        y_validation,
        ml_validation,
    )

    print_metrics(
        "Rules only",
        y_validation,
        rule_validation,
    )

    print_metrics(
        "Combined",
        y_validation,
        combined_validation,
    )

    print("\n" + "=" * 65)
    print("INDEPENDENT SYNTHETIC TEST RESULTS — SEED 2026")
    print("=" * 65)

    print_metrics(
        "ML only",
        y_independent,
        ml_independent,
    )

    print_metrics(
        "Rules only",
        y_independent,
        rule_independent,
    )

    print_metrics(
        "Combined",
        y_independent,
        combined_independent,
    )

    print("\nIndependent ML attack-type results")
    attack_type_recall(
        independent,
        ml_independent,
    )

    print("\nIndependent rule attack-type results")
    attack_type_recall(
        independent,
        rule_independent,
    )

    print("\nIndependent combined attack-type results")
    attack_type_recall(
        independent,
        combined_independent,
    )

    print("\nIndependent scenario coverage")

    print("\nML:")
    scenario_metrics(independent, ml_independent)

    print("\nRules:")
    scenario_metrics(independent, rule_independent)

    print("\nCombined:")
    scenario_metrics(independent, combined_independent)

    print("\n" + "=" * 65)
    print("EVALUATION COMPLETE")
    print("=" * 65)

    print(
        "\nLimitations: the independent dataset uses the same "
        "synthetic generator assumptions. These measurements "
        "do not establish real-world detection performance."
    )


if __name__ == "__main__":
    main()
