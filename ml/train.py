import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import json
import time
import os

# This list MUST exactly match the C++ Feature enum order from feature_manager.hpp.
# It is the contract between the C++ feature extractor and the Python model.
FEATURE_NAMES = [
    "REQUEST_TIME_S",
    "BYTES_SENT",
    "HTTP_STATUS_4XX",
    "HTTP_STATUS_5XX",
    "IS_UA_MISSING",
    "IS_UA_HEADLESS",
    "IS_UA_KNOWN_BAD",
    "IS_UA_CYCLING",
    "IS_PATH_NEW_FOR_IP",
    "IP_REQ_TIME_ZSCORE",
    "IP_BYTES_SENT_ZSCORE",
    "IP_ERROR_EVENT_ZSCORE",
    "IP_REQ_VOL_ZSCORE",
    "PATH_REQ_TIME_ZSCORE",
    "PATH_BYTES_SENT_ZSCORE",
    "PATH_ERROR_EVENT_ZSCORE",
    "SESSION_DURATION_S",
    "SESSION_REQ_COUNT",
    "SESSION_UNIQUE_PATH_COUNT",
    "SESSION_ERROR_4XX_COUNT",
    "SESSION_ERROR_5XX_COUNT",
    "SESSION_FAILED_LOGIN_COUNT",
    "SESSION_AVG_TIME_BETWEEN_REQS_S",
    "SESSION_POST_TO_GET_RATIO",
    "SESSION_UA_CHANGE_COUNT",
    "SESSION_BYTES_SENT_MEAN",
    "SESSION_REQ_TIME_MEAN",
]


def train_model(data_path, model_output_path, metadata_output_path):
    """
    Loads feature data, cleans it, trains an Isolation Forest model, evaluates it,
    and saves the model and its metadata.
    """
    print("--- ML Training Pipeline Started ---")
    print(f"Loading feature data from: {data_path}")
    if not os.path.exists(data_path):
        print(f"\nFATAL ERROR: Data file not found at '{data_path}'.")
        print(
            "Please run the C++ application with 'ml_data_collection_enabled = true' to generate it first."
        )
        return

    df = pd.read_csv(data_path, header=None)
    if df.shape[1] != len(FEATURE_NAMES):
        print("\nFATAL ERROR: Mismatch in feature count!")
        print(
            f"  Expected {len(FEATURE_NAMES)} features based on script, but found {df.shape[1]} in CSV."
        )
        print("  Check if C++ Feature enum and Python FEATURE_NAMES list are in sync.")
        return
    df.columns = FEATURE_NAMES

    print(f"Loaded {len(df)} raw samples.")

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    print(f"Using {len(df)} samples after cleaning NaN/inf values.")

    if len(df) < 200:
        print("Warning: Dataset is very small. Model quality may be poor.")

    X_train, X_test = train_test_split(df, test_size=0.3, random_state=42)

    print(f"Training IsolationForest model on {len(X_train)} samples...")
    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        max_features=1.0,
        bootstrap=False,
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_train)

    print("Evaluating model performance...")
    scores_test = model.score_samples(X_test)
    avg_score = np.mean(scores_test)

    print(f"  - Average Anomaly Score (on test set): {avg_score:.4f}")

    print("Converting model to ONNX format...")
    num_features = len(FEATURE_NAMES)
    initial_type = [("float_input", FloatTensorType([None, num_features]))]
    onnx_model = convert_sklearn(model, initial_types=initial_type, target_opset=13)

    with open(model_output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    print(f"  -> ONNX model saved to: {model_output_path}")

    metadata = {
        "model_type": "IsolationForest",
        "training_timestamp_utc": int(time.time()),
        "training_data_path": data_path,
        "training_samples": len(X_train),
        "num_features": num_features,
        "feature_names_ordered": FEATURE_NAMES,
        "evaluation_metrics": {"average_anomaly_score_test": avg_score},
    }

    with open(metadata_output_path, "w") as f:
        json.dump(metadata, f, indent=4)
    print(f"  -> Model metadata saved to: {metadata_output_path}")
    print("--- ML Training Pipeline Finished ---")


if __name__ == "__main__":
    # These paths assume the script is run from the project's root directory
    DATA_PATH = "data/training_features.csv"
    MODEL_PATH = "src/models/isolation_forest.onnx"
    METADATA_PATH = "src/models/isolation_forest.json"
    train_model(DATA_PATH, MODEL_PATH, METADATA_PATH)
