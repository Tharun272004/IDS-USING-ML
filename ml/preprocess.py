import pandas as pd
import os

columns = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "label",
    "difficulty"
]

# Load datasets
train_df = pd.read_csv(
    "data/KDDTrain+.txt",
    header=None,
    sep=r"\s+"
)

test_df = pd.read_csv(
    "data/KDDTest+.txt",
    header=None,
    sep=r"\s+"
)

print("Original training data:", train_df.shape)
print("Original testing data:", test_df.shape)

# Training dataset has 43 columns
train_df.columns = columns

# Test dataset has 42 columns
# It contains no difficulty column
test_df.columns = columns[:-1]

# Convert labels to binary classification
# Normal = 0
# Attack = 1

train_df["label"] = train_df["label"].apply(
    lambda x: 0 if str(x).lower() == "normal" else 1
)

test_df["label"] = test_df["label"].apply(
    lambda x: 0 if str(x).lower() == "normal" else 1
)

# Remove difficulty column from training data
train_df.drop("difficulty", axis=1, inplace=True)

print("\nTraining labels:")
print(train_df["label"].value_counts())

print("\nTesting labels:")
print(test_df["label"].value_counts())

# Categorical columns
categorical_columns = [
    "protocol_type",
    "service",
    "flag"
]

# Combine datasets so both receive identical one-hot encoded columns
combined = pd.concat(
    [train_df, test_df],
    axis=0,
    ignore_index=True
)

combined = pd.get_dummies(
    combined,
    columns=categorical_columns,
    dtype=int
)

# Split back into training and testing
train_processed = combined.iloc[:len(train_df)].copy()
test_processed = combined.iloc[len(train_df):].copy()

# Create processed-data directory
os.makedirs("data/processed", exist_ok=True)

# Save processed files
train_processed.to_csv(
    "data/processed/train_processed.csv",
    index=False
)

test_processed.to_csv(
    "data/processed/test_processed.csv",
    index=False
)

print("\nPreprocessing completed successfully!")

print(
    "Processed training data:",
    train_processed.shape
)

print(
    "Processed testing data:",
    test_processed.shape
)

print("\nFiles created:")
print("data/processed/train_processed.csv")
print("data/processed/test_processed.csv")