"""
Tests E — ML Compatibility
Feature engineering, model/scaler artifacts, batch vs single-event
consistency, and raw decision score preservation.

No model retraining occurs. All tests are read-only with respect
to production model artifacts.
"""

import sys
import os
import pickle
import tempfile
import shutil
import pytest
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.utils.features import engineer_features, get_feature_names, FEATURE_COLUMNS


# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────
MODEL_PATH  = "backend/models/isolation_forest.pkl"
SCALER_PATH = "backend/models/scaler.pkl"
EXPECTED_FEATURE_COUNT = 11


# ─────────────────────────────────────────────────────────────
# Minimal valid log row for feature engineering
# ─────────────────────────────────────────────────────────────
def _make_df(rows=None):
    """Return a minimal DataFrame suitable for engineer_features()."""
    if rows is None:
        rows = [
            {
                "timestamp": "2026-10-01 10:00:00",
                "ip_address": "192.168.1.1",
                "username": "alice",
                "status": "Accepted",
            }
        ]
    return pd.DataFrame(rows)


# ════════════════════════════════════════════════════════════
# ML-01 — FEATURE_COLUMNS has exactly 11 entries
# ════════════════════════════════════════════════════════════
def test_ml01_feature_column_count():
    """FEATURE_COLUMNS constant must list exactly 11 feature names."""
    assert len(FEATURE_COLUMNS) == EXPECTED_FEATURE_COUNT, (
        f"Expected {EXPECTED_FEATURE_COUNT} features, "
        f"got {len(FEATURE_COLUMNS)}: {FEATURE_COLUMNS}"
    )


# ════════════════════════════════════════════════════════════
# ML-02 — Feature column order matches FEATURE_COLUMNS constant
# ════════════════════════════════════════════════════════════
def test_ml02_feature_column_order():
    """
    engineer_features() must return columns in exactly the order
    defined by FEATURE_COLUMNS — model expects a fixed column order.
    """
    df = _make_df()
    result = engineer_features(df)
    assert list(result.columns) == FEATURE_COLUMNS, (
        f"Column order mismatch.\n"
        f"Expected: {FEATURE_COLUMNS}\n"
        f"Got:      {list(result.columns)}"
    )


# ════════════════════════════════════════════════════════════
# ML-03 — Scaler feature-name compatibility
# ════════════════════════════════════════════════════════════
def test_ml03_scaler_feature_name_compatibility():
    """
    If the scaler exposes feature_names_in_, it must match FEATURE_COLUMNS.
    This guards against silent column-order/name drift.
    """
    import joblib
    if not os.path.exists(SCALER_PATH):
        pytest.skip("Scaler artifact not present — skipping compatibility check.")

    scaler = joblib.load(SCALER_PATH)
    if not hasattr(scaler, "feature_names_in_"):
        pytest.skip(
            "Scaler does not expose feature_names_in_ "
            "(fitted without DataFrame — cannot check names)."
        )

    scaler_names = list(scaler.feature_names_in_)
    assert scaler_names == FEATURE_COLUMNS, (
        f"Scaler feature names do not match FEATURE_COLUMNS.\n"
        f"Scaler : {scaler_names}\n"
        f"Expected: {FEATURE_COLUMNS}"
    )


# ════════════════════════════════════════════════════════════
# ML-04 — Model artifact present and loadable
# ════════════════════════════════════════════════════════════
def test_ml04_model_artifact_loadable():
    """Model and scaler files must be present and loadable without error."""
    import joblib
    assert os.path.exists(MODEL_PATH), f"Model not found at {MODEL_PATH}"
    assert os.path.exists(SCALER_PATH), f"Scaler not found at {SCALER_PATH}"

    model  = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    assert hasattr(model, "predict"),           "Model has no predict() method."
    assert hasattr(model, "decision_function"), "Model has no decision_function()."
    assert hasattr(scaler, "transform"),        "Scaler has no transform() method."


# ════════════════════════════════════════════════════════════
# ML-05 — Missing model file raises FileNotFoundError
# ════════════════════════════════════════════════════════════
def test_ml05_missing_model_raises_file_not_found(tmp_path, monkeypatch):
    """
    ThreatDetector.load_model() must raise FileNotFoundError when
    the model artifact is absent.
    """
    from ml.detector import ThreatDetector

    # Point model path to a non-existent file
    fake_path = str(tmp_path / "nonexistent_model.pkl")
    monkeypatch.setattr("ml.detector.MODEL_PATH", fake_path)

    det = ThreatDetector()
    with pytest.raises(FileNotFoundError):
        det.load_model()


# ════════════════════════════════════════════════════════════
# ML-06 — Corrupt model file raises appropriate error
# ════════════════════════════════════════════════════════════
def test_ml06_corrupt_model_raises_error(tmp_path, monkeypatch):
    """
    A corrupt (non-pickle) model file must raise an error —
    not silently succeed or return None.
    """
    corrupt_path = tmp_path / "corrupt_model.pkl"
    corrupt_path.write_bytes(b"THIS IS NOT A VALID PICKLE FILE")

    monkeypatch.setattr("ml.detector.MODEL_PATH", str(corrupt_path))

    from ml.detector import ThreatDetector
    det = ThreatDetector()
    with pytest.raises(Exception):  # joblib/pickle will raise
        det.load_model()


# ════════════════════════════════════════════════════════════
# ML-07 — Batch vs single-event feature consistency
# ════════════════════════════════════════════════════════════
def test_ml07_batch_vs_single_event_consistency():
    """
    When a single event has no prior history, engineer_features()
    must produce the same feature values regardless of whether it
    is passed alone or as the last row of a batch with an entirely
    different IP/user (which cannot contribute to its history).
    """
    target_event = {
        "timestamp": "2026-10-01 10:30:00",
        "ip_address": "172.16.0.1",
        "username":   "targetuser",
        "status":     "Failed",
    }
    unrelated_events = [
        {
            "timestamp": "2026-10-01 10:00:00",
            "ip_address": "10.99.99.99",
            "username":   "other_user",
            "status":     "Failed",
        },
        {
            "timestamp": "2026-10-01 10:10:00",
            "ip_address": "10.99.99.99",
            "username":   "other_user2",
            "status":     "Accepted",
        },
    ]

    # Single-event result
    single_df = _make_df([target_event])
    single_features = engineer_features(single_df)

    # Batch result — unrelated events before the target
    batch_df = _make_df(unrelated_events + [target_event])
    batch_features = engineer_features(batch_df)
    # Take the last row (the target event)
    batch_last = batch_features.iloc[[-1]].reset_index(drop=True)
    single_reset = single_features.reset_index(drop=True)

    pd.testing.assert_frame_equal(
        single_reset,
        batch_last,
        check_names=True,
        atol=1e-9,
        rtol=0,
        obj="Batch vs single feature consistency",
    )


# ════════════════════════════════════════════════════════════
# ML-08 — Raw decision score is a float preserved in result
# ════════════════════════════════════════════════════════════
def test_ml08_raw_decision_score_is_float():
    """
    ThreatDetector.analyse() must expose a numeric decision_score
    via the ML pipeline. We verify that decision_function() on
    the loaded model returns floats for a simple feature matrix.
    """
    import joblib
    if not (os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH)):
        pytest.skip("Model artifacts not available.")

    model  = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    df = _make_df()
    features = engineer_features(df)
    X_scaled = scaler.transform(features)

    scores = model.decision_function(X_scaled)
    assert len(scores) == 1
    assert isinstance(float(scores[0]), float)
    # Isolation Forest scores are typically in (-0.5, 0.5)
    assert -2.0 < scores[0] < 2.0, (
        f"Decision score {scores[0]} is outside the expected range."
    )


# ════════════════════════════════════════════════════════════
# ML-09 — engineer_features returns exactly FEATURE_COLUMNS columns
# ════════════════════════════════════════════════════════════
def test_ml09_engineer_features_returns_correct_columns():
    """engineer_features() output must contain exactly the FEATURE_COLUMNS."""
    df = _make_df()
    result = engineer_features(df)
    assert set(result.columns) == set(FEATURE_COLUMNS)
    assert len(result.columns) == EXPECTED_FEATURE_COUNT


# ════════════════════════════════════════════════════════════
# ML-10 — engineer_features rejects missing required column
# ════════════════════════════════════════════════════════════
@pytest.mark.parametrize("drop_col", ["timestamp", "ip_address", "username", "status"])
def test_ml10_engineer_features_rejects_missing_column(drop_col):
    """Missing any required column must raise ValueError."""
    df = _make_df()
    df = df.drop(columns=[drop_col])
    with pytest.raises(ValueError, match="Missing required columns"):
        engineer_features(df)


# ════════════════════════════════════════════════════════════
# ML-11 — engineer_features on empty DataFrame returns correct schema
# ════════════════════════════════════════════════════════════
def test_ml11_engineer_features_empty_dataframe():
    """
    An empty DataFrame with the correct columns must return
    an empty result with FEATURE_COLUMNS as columns and float dtype.
    """
    empty_df = pd.DataFrame(
        columns=["timestamp", "ip_address", "username", "status"]
    )
    result = engineer_features(empty_df)
    assert list(result.columns) == FEATURE_COLUMNS
    assert len(result) == 0
    assert result.dtypes.apply(lambda d: d == float).all(), (
        "All feature columns in empty result must be float dtype."
    )


# ════════════════════════════════════════════════════════════
# ML-12 — get_feature_names() returns a copy, not the original list
# ════════════════════════════════════════════════════════════
def test_ml12_get_feature_names_returns_copy():
    """
    Modifying the returned list must not alter FEATURE_COLUMNS.
    """
    names = get_feature_names()
    names.append("INJECTED_COLUMN")
    assert "INJECTED_COLUMN" not in FEATURE_COLUMNS

