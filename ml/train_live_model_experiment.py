import pandas as pd
import joblib
import os
import json

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
from sklearn.model_selection import train_test_split


# ============================================================
# EXPERIMENTAL LIVE IDS MODEL
#
# IMPORTANT:
# This file NEVER overwrites the current production model.
#
# Production files:
#   live_ids_model.pkl
#   protocol_encoder.pkl
#   attack_threshold.pkl
#   model_metrics.json
#
# Experimental files:
#   experimental_live_ids_model.pkl
#   experimental_protocol_encoder.pkl
#   experimental_attack_threshold.pkl
#   experimental_model_metrics.json
# ============================================================


# ============================================================
# CONFIGURATION
# ============================================================

TRAIN_FILE = "data/KDDTrain+.txt"
TEST_FILE = "data/KDDTest+.txt"

MODEL_DIR = "models"

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "experimental_live_ids_model.pkl"
)

ENCODER_PATH = os.path.join(
    MODEL_DIR,
    "experimental_protocol_encoder.pkl"
)

THRESHOLD_PATH = os.path.join(
    MODEL_DIR,
    "experimental_attack_threshold.pkl"
)

METRICS_PATH = os.path.join(
    MODEL_DIR,
    "experimental_model_metrics.json"
)


# ============================================================
# LOAD DATA
# ============================================================

print("==============================================")
print("      EXPERIMENTAL LIVE IDS MODEL")
print("==============================================")

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
# NORMAL = 0
# ATTACK = 1
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
# PROTOCOL ENCODING
#
# IMPORTANT:
# Encoder is fitted ONLY on training data.
# This avoids using test data during preprocessing.
# ============================================================

encoder = LabelEncoder()


encoder.fit(
    train["protocol_type"]
)


train["protocol_type"] = encoder.transform(
    train["protocol_type"]
)


test_protocols = set(
    test["protocol_type"].unique()
)

known_protocols = set(
    encoder.classes_
)


unknown_protocols = (
    test_protocols -
    known_protocols
)


if unknown_protocols:

    raise ValueError(
        "Test dataset contains protocol values "
        "not present in training data: "
        + str(unknown_protocols)
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

    print(
        " -",
        feature
    )


# ============================================================
# TRAIN / VALIDATION SPLIT
# ============================================================

(
    X_train,
    X_validation,
    y_train,
    y_validation
) = train_test_split(

    X,
    y,

    test_size=0.20,

    random_state=42,

    stratify=y
)


print("\n==============================================")
print("             DATASET SPLIT")
print("==============================================")

print(
    "Training samples:",
    len(X_train)
)

print(
    "Validation samples:",
    len(X_validation)
)

print(
    "Final testing samples:",
    len(X_test)
)


# ============================================================
# EXPERIMENTAL MODEL CONFIGURATIONS
#
# We keep the same five live features.
#
# We test different class weights and leaf sizes
# to improve attack recall without changing the
# live packet feature pipeline.
# ============================================================

candidates = [

    {
        "name": "baseline_balanced_leaf2",
        "n_estimators": 300,
        "class_weight": "balanced",
        "min_samples_leaf": 2
    },

    {
        "name": "attack_weight_2_leaf2",
        "n_estimators": 300,
        "class_weight": {
            0: 1,
            1: 2
        },
        "min_samples_leaf": 2
    },

    {
        "name": "attack_weight_3_leaf2",
        "n_estimators": 300,
        "class_weight": {
            0: 1,
            1: 3
        },
        "min_samples_leaf": 2
    },

    {
        "name": "attack_weight_2_leaf1",
        "n_estimators": 300,
        "class_weight": {
            0: 1,
            1: 2
        },
        "min_samples_leaf": 1
    },

    {
        "name": "attack_weight_2_leaf4",
        "n_estimators": 300,
        "class_weight": {
            0: 1,
            1: 2
        },
        "min_samples_leaf": 4
    }

]


# ============================================================
# THRESHOLDS
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


# ============================================================
# EXPERIMENT
# ============================================================

experiment_results = []

best_candidate = None
best_threshold = 0.50
best_validation_f1 = -1


print("\n==============================================")
print("        MODEL CONFIGURATION EXPERIMENT")
print("==============================================")


for config in candidates:

    print("\n----------------------------------------------")

    print(
        "Testing:",
        config["name"]
    )

    print(
        "Trees:",
        config["n_estimators"]
    )

    print(
        "Class weight:",
        config["class_weight"]
    )

    print(
        "Minimum leaf:",
        config["min_samples_leaf"]
    )


    model = RandomForestClassifier(

        n_estimators=
            config["n_estimators"],

        class_weight=
            config["class_weight"],

        min_samples_leaf=
            config["min_samples_leaf"],

        random_state=42,

        n_jobs=-1

    )


    print(
        "Training..."
    )


    model.fit(
        X_train,
        y_train
    )


    validation_probabilities = (
        model.predict_proba(
            X_validation
        )[:, 1]
    )


    local_best_threshold = 0.50
    local_best_f1 = -1

    local_best_precision = 0
    local_best_recall = 0


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


        if f1 > local_best_f1:

            local_best_f1 = f1

            local_best_threshold = (
                threshold
            )

            local_best_precision = (
                precision
            )

            local_best_recall = (
                recall
            )


    result = {

        "name":
            config["name"],

        "n_estimators":
            config["n_estimators"],

        "class_weight":
            str(
                config["class_weight"]
            ),

        "min_samples_leaf":
            config["min_samples_leaf"],

        "validation_threshold":
            local_best_threshold,

        "validation_precision":
            round(
                local_best_precision,
                4
            ),

        "validation_recall":
            round(
                local_best_recall,
                4
            ),

        "validation_f1":
            round(
                local_best_f1,
                4
            )

    }


    experiment_results.append(
        result
    )


    print(
        "Best validation threshold:",
        local_best_threshold
    )

    print(
        "Validation precision:",
        round(
            local_best_precision * 100,
            2
        ),
        "%"
    )

    print(
        "Validation recall:",
        round(
            local_best_recall * 100,
            2
        ),
        "%"
    )

    print(
        "Validation F1:",
        round(
            local_best_f1 * 100,
            2
        ),
        "%"
    )


    if local_best_f1 > best_validation_f1:

        best_validation_f1 = (
            local_best_f1
        )

        best_candidate = config

        best_threshold = (
            local_best_threshold
        )


# ============================================================
# SHOW EXPERIMENT RESULTS
# ============================================================

print("\n==============================================")
print("          EXPERIMENT COMPARISON")
print("==============================================")


for result in experiment_results:

    print(
        "\n",
        result["name"]
    )

    print(
        "  Threshold:",
        result["validation_threshold"]
    )

    print(
        "  Precision:",
        round(
            result["validation_precision"] * 100,
            2
        ),
        "%"
    )

    print(
        "  Recall:",
        round(
            result["validation_recall"] * 100,
            2
        ),
        "%"
    )

    print(
        "  F1:",
        round(
            result["validation_f1"] * 100,
            2
        ),
        "%"
    )


# ============================================================
# RETRAIN BEST MODEL ON ALL KDDTRAIN+
# ============================================================

print("\n==============================================")
print("          BEST MODEL SELECTED")
print("==============================================")


print(
    "Configuration:",
    best_candidate["name"]
)

print(
    "Threshold:",
    best_threshold
)


print(
    "\nRetraining best configuration "
    "using all KDDTrain+ data..."
)


final_model = RandomForestClassifier(

    n_estimators=
        best_candidate["n_estimators"],

    class_weight=
        best_candidate["class_weight"],

    min_samples_leaf=
        best_candidate["min_samples_leaf"],

    random_state=42,

    n_jobs=-1

)


final_model.fit(
    X,
    y
)


print(
    "Final training completed!"
)


# ============================================================
# FINAL TEST
#
# KDDTest+ is used only here for final evaluation.
# ============================================================

test_probabilities = (
    final_model.predict_proba(
        X_test
    )[:, 1]
)


y_pred = (
    test_probabilities
    >= best_threshold
).astype(int)


# ============================================================
# FINAL METRICS
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
# FINAL RESULTS
# ============================================================

print("\n==============================================")
print("       EXPERIMENTAL FINAL RESULTS")
print("==============================================")


print(
    "Accuracy:",
    round(
        accuracy * 100,
        2
    ),
    "%"
)


print(
    "Precision:",
    round(
        precision * 100,
        2
    ),
    "%"
)


print(
    "Recall:",
    round(
        recall * 100,
        2
    ),
    "%"
)


print(
    "F1 Score:",
    round(
        f1 * 100,
        2
    ),
    "%"
)


print(
    "\nClassification Report:"
)


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


print(
    "Confusion Matrix:"
)


print(
    cm
)


# ============================================================
# SAVE EXPERIMENTAL MODEL
# ============================================================

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)


joblib.dump(
    final_model,
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
# SAVE EXPERIMENTAL METADATA
# ============================================================

metrics_data = {

    "model_type":
        "Experimental Live IDS Model",

    "algorithm":
        "Random Forest Classifier",

    "dataset":
        "NSL-KDD",

    "training_samples":
        int(len(X)),

    "validation_samples":
        int(len(X_validation)),

    "testing_samples":
        int(len(X_test)),

    "features":
        features,

    "selected_configuration":
        best_candidate,

    "threshold":
        float(best_threshold),

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

    "confusion_matrix":
        cm.tolist(),

    "protocol_classes":
        encoder.classes_.tolist(),

    "experiment_results":
        experiment_results

}


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
# FINAL MESSAGE
# ============================================================

print("\n==============================================")
print("       EXPERIMENT FILES SAVED")
print("==============================================")


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


print("\n==============================================")
print("      CURRENT PRODUCTION MODEL UNTOUCHED")
print("==============================================")