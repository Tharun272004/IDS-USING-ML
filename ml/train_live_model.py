import pandas as pd
import joblib
import os
import json

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score
)
from sklearn.model_selection import train_test_split


# ============================================================
# CONFIGURATION
# ============================================================

TRAIN_FILE = "data/KDDTrain+.txt"
TEST_FILE = "data/KDDTest+.txt"

MODEL_DIR = "models"

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "live_ids_model.pkl"
)

ENCODER_PATH = os.path.join(
    MODEL_DIR,
    "protocol_encoder.pkl"
)

THRESHOLD_PATH = os.path.join(
    MODEL_DIR,
    "attack_threshold.pkl"
)

METRICS_PATH = os.path.join(
    MODEL_DIR,
    "model_metrics.json"
)


# ============================================================
# LOAD NSL-KDD
# ============================================================

print("====================================")
print("       LIVE IDS MODEL TRAINING")
print("====================================")

print("\nLoading NSL-KDD dataset...")

train = pd.read_csv(
    TRAIN_FILE,
    header=None,
    sep=r"\s+"
)

test = pd.read_csv(
    TEST_FILE,
    header=None,
    sep=r"\s+"
)

print(
    "Original training dataset:",
    train.shape
)

print(
    "Original testing dataset:",
    test.shape
)


# ============================================================
# SELECT LIVE-COMPATIBLE FEATURES
# ============================================================

train = train.iloc[
    :,
    [0, 1, 4, 5, 22, 41]
]

test = test.iloc[
    :,
    [0, 1, 4, 5, 22, 41]
]

columns = [
    "duration",
    "protocol_type",
    "src_bytes",
    "dst_bytes",
    "count",
    "label"
]

train.columns = columns
test.columns = columns


# ============================================================
# CONVERT LABELS
#
# Normal = 0
# Attack = 1
# ============================================================

train["label"] = train["label"].apply(
    lambda x:
        0
        if str(x).lower() == "normal"
        else 1
)

test["label"] = test["label"].apply(
    lambda x:
        0
        if str(x).lower() == "normal"
        else 1
)


# ============================================================
# ENCODE PROTOCOL
# ============================================================

encoder = LabelEncoder()

# Fit using the complete set of protocol values appearing
# in the supplied training and testing datasets.
encoder.fit(
    pd.concat(
        [
            train["protocol_type"],
            test["protocol_type"]
        ]
    ).unique()
)

train["protocol_type"] = encoder.transform(
    train["protocol_type"]
)

test["protocol_type"] = encoder.transform(
    test["protocol_type"]
)


# ============================================================
# FEATURES
# ============================================================

features = [
    "duration",
    "protocol_type",
    "src_bytes",
    "dst_bytes",
    "count"
]

X = train[features]
y = train["label"]

X_test = test[features]
y_test = test["label"]


print("\nLive model features:")
for feature in features:
    print(" -", feature)


# ============================================================
# TRAIN / VALIDATION SPLIT
# ============================================================

X_train, X_validation, y_train, y_validation = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print("\n====================================")
print("        DATASET SPLIT")
print("====================================")

print(
    "Training samples:",
    X_train.shape
)

print(
    "Validation samples:",
    X_validation.shape
)

print(
    "Testing samples:",
    X_test.shape
)


# ============================================================
# TRAIN RANDOM FOREST
# ============================================================

model = RandomForestClassifier(
    n_estimators=300,
    class_weight="balanced",
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)

print("\nTraining Random Forest...")

model.fit(
    X_train,
    y_train
)

print("Training completed!")


# ============================================================
# VALIDATION PROBABILITIES
# ============================================================

validation_probabilities = (
    model.predict_proba(
        X_validation
    )[:, 1]
)


# ============================================================
# FIND BEST THRESHOLD USING VALIDATION DATA
# ============================================================

thresholds = [
    0.30,
    0.35,
    0.40,
    0.45,
    0.50,
    0.55,
    0.60
]

best_threshold = 0.50
best_f1 = -1

threshold_results = []

print("\n====================================")
print("     VALIDATION THRESHOLD TEST")
print("====================================\n")


for threshold in thresholds:

    validation_predictions = (
        validation_probabilities
        >= threshold
    ).astype(int)

    precision = precision_score(
        y_validation,
        validation_predictions,
        zero_division=0
    )

    recall = recall_score(
        y_validation,
        validation_predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_validation,
        validation_predictions,
        zero_division=0
    )

    threshold_results.append(
        {
            "threshold": threshold,
            "precision": round(
                float(precision),
                4
            ),
            "recall": round(
                float(recall),
                4
            ),
            "f1_score": round(
                float(f1),
                4
            )
        }
    )

    print(
        f"Threshold: {threshold:.2f} | "
        f"Precision: {precision:.3f} | "
        f"Recall: {recall:.3f} | "
        f"F1: {f1:.3f}"
    )

    if f1 > best_f1:

        best_f1 = f1
        best_threshold = threshold


# ============================================================
# FINAL TEST PREDICTION
#
# IMPORTANT:
# The test set was NOT used to select the threshold.
# ============================================================

test_probabilities = (
    model.predict_proba(
        X_test
    )[:, 1]
)

y_pred = (
    test_probabilities
    >= best_threshold
).astype(int)


# ============================================================
# FINAL TEST EVALUATION
# ============================================================

accuracy = accuracy_score(
    y_test,
    y_pred
)

precision = precision_score(
    y_test,
    y_pred,
    zero_division=0
)

recall = recall_score(
    y_test,
    y_pred,
    zero_division=0
)

f1 = f1_score(
    y_test,
    y_pred,
    zero_division=0
)

cm = confusion_matrix(
    y_test,
    y_pred
)


# ============================================================
# DISPLAY RESULTS
# ============================================================

print("\n====================================")
print("        FINAL MODEL RESULTS")
print("====================================")

print(
    "Best validation threshold:",
    best_threshold
)

print(
    "Test Accuracy:",
    round(
        accuracy * 100,
        2
    ),
    "%"
)

print(
    "Test Precision:",
    round(
        precision * 100,
        2
    ),
    "%"
)

print(
    "Test Recall:",
    round(
        recall * 100,
        2
    ),
    "%"
)

print(
    "Test F1 Score:",
    round(
        f1 * 100,
        2
    ),
    "%"
)


print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "Normal",
            "Attack"
        ],
        zero_division=0
    )
)


print("Confusion Matrix:")

print(cm)


# ============================================================
# CREATE MODEL DIRECTORY
# ============================================================

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)


# ============================================================
# SAVE MODEL
# ============================================================

joblib.dump(
    model,
    MODEL_PATH
)

joblib.dump(
    encoder,
    ENCODER_PATH
)

joblib.dump(
    best_threshold,
    THRESHOLD_PATH
)


# ============================================================
# MODEL METADATA
# ============================================================

metrics_data = {

    "algorithm":
        "Random Forest Classifier",

    "dataset":
        "NSL-KDD",

    "training_samples":
        int(len(X_train)),

    "validation_samples":
        int(len(X_validation)),

    "testing_samples":
        int(len(X_test)),

    "features":
        features,

    "n_estimators":
        300,

    "class_weight":
        "balanced",

    "min_samples_leaf":
        2,

    "accuracy":
        round(
            float(accuracy),
            4
        ),

    "precision":
        round(
            float(precision),
            4
        ),

    "recall":
        round(
            float(recall),
            4
        ),

    "f1_score":
        round(
            float(f1),
            4
        ),

    "threshold":
        float(best_threshold),

    "validation_threshold_results":
        threshold_results,

    "confusion_matrix":
        cm.tolist(),

    "protocol_classes":
        encoder.classes_.tolist()
}


# ============================================================
# SAVE MODEL METRICS
# ============================================================

with open(
    METRICS_PATH,
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        metrics_data,
        file,
        indent=4
    )


# ============================================================
# FINAL OUTPUT
# ============================================================

print("\n====================================")
print("        FILES SAVED")
print("====================================")

print(
    MODEL_PATH
)

print(
    ENCODER_PATH
)

print(
    THRESHOLD_PATH
)

print(
    METRICS_PATH
)

print("\n====================================")
print("        TRAINING COMPLETE")
print("====================================")
