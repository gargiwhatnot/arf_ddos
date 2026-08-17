import os
import time
import pickle
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# CONFIGURATION
# ============================================================

TRAIN_FOLDER = "../train_data"
TEST_FOLDER = "../test_data"

# Previous checkpoint
INPUT_CHECKPOINT = (
    "../results/checkpoints/"
    "arf_after_01_DNS.pkl"
)

# New checkpoint
OUTPUT_CHECKPOINT = (
    "../results/checkpoints/"
    "arf_after_02_LDAP.pkl"
)

# Training file
TRAIN_FILE = "DrDoS_LDAP_train.csv"

# Test files
TEST_FILES = [
    "DrDoS_DNS_test.csv",
    "DrDoS_LDAP_test.csv"
]

CHUNK_SIZE = 10_000


# ============================================================
# SETUP
# ============================================================

print("=" * 70)
print("ARF CHECKPOINT 02 - LDAP TRAINING + DNS/LDAP TESTING")
print("=" * 70)

print("\nPrevious checkpoint:")
print(f"  {INPUT_CHECKPOINT}")

print("\nTraining file:")
print(f"  {TRAIN_FILE}")

print("\nTesting files:")
for file in TEST_FILES:
    print(f"  - {file}")

print("\nNew checkpoint:")
print(f"  {OUTPUT_CHECKPOINT}")

print("\nIMPORTANT:")
print("The DNS checkpoint will be loaded.")
print("LDAP training will continue from that checkpoint.")
print("Test data will ONLY be used for prediction.")


# ============================================================
# CHECK FILES
# ============================================================

if not os.path.exists(INPUT_CHECKPOINT):
    raise FileNotFoundError(
        f"\nPrevious checkpoint not found:\n"
        f"{INPUT_CHECKPOINT}"
    )

train_path = os.path.join(
    TRAIN_FOLDER,
    TRAIN_FILE
)

if not os.path.exists(train_path):
    raise FileNotFoundError(
        f"\nLDAP training file not found:\n"
        f"{train_path}"
    )

for test_file in TEST_FILES:

    test_path = os.path.join(
        TEST_FOLDER,
        test_file
    )

    if not os.path.exists(test_path):
        raise FileNotFoundError(
            f"\nTest file not found:\n"
            f"{test_path}"
        )


# ============================================================
# LOAD DNS CHECKPOINT
# ============================================================

print("\n" + "=" * 70)
print("LOADING CHECKPOINT 01")
print("=" * 70)

with open(
    INPUT_CHECKPOINT,
    "rb"
) as f:

    model = pickle.load(f)

print("\nCheckpoint 1 loaded successfully.")
print("The existing ARF will now continue learning LDAP.")


# ============================================================
# LDAP TRAINING
# ============================================================

print("\n" + "=" * 70)
print("STARTING LDAP TRAINING")
print("=" * 70)

rows_trained = 0

start_time = time.time()


for chunk in pd.read_csv(
    train_path,
    chunksize=CHUNK_SIZE,
    low_memory=False
):

    # --------------------------------------------------------
    # CLEAN COLUMN NAMES
    # --------------------------------------------------------

    chunk.columns = chunk.columns.str.strip()

    # --------------------------------------------------------
    # CHECK LABEL
    # --------------------------------------------------------

    if "Label" not in chunk.columns:
        raise ValueError(
            "'Label' column not found in LDAP dataset."
        )

    # --------------------------------------------------------
    # CLEAN LABEL
    # --------------------------------------------------------

    y = (
        chunk["Label"]
        .astype(str)
        .str.strip()
    )

    # --------------------------------------------------------
    # REMOVE NON-ML COLUMNS
    # --------------------------------------------------------

    drop_columns = [
        "Unnamed: 0",
        "Flow ID",
        "Source IP",
        "Destination IP",
        "Timestamp",
        "SimillarHTTP",
        "Label"
    ]

    existing_columns = [
        column
        for column in drop_columns
        if column in chunk.columns
    ]

    X = chunk.drop(
        columns=existing_columns
    )

    # --------------------------------------------------------
    # CLEAN FEATURES
    # --------------------------------------------------------

    X = X.replace(
        [float("inf"), float("-inf")],
        0
    )

    for column in X.columns:

        X[column] = pd.to_numeric(
            X[column],
            errors="coerce"
        )

    X = X.fillna(0)

    # --------------------------------------------------------
    # CONTINUE ONLINE TRAINING
    # --------------------------------------------------------

    for i in range(len(X)):

        features = X.iloc[i].to_dict()

        label = y.iloc[i]

        # IMPORTANT:
        # This continues training Checkpoint 1.
        model.learn_one(
            features,
            label
        )

        rows_trained += 1

        if rows_trained % 100_000 == 0:

            elapsed = time.time() - start_time

            print(
                f"LDAP rows trained: "
                f"{rows_trained:,} | "
                f"Time: "
                f"{elapsed / 60:.2f} min"
            )


# ============================================================
# TRAINING COMPLETE
# ============================================================

training_time = time.time() - start_time

print("\n" + "=" * 70)
print("LDAP TRAINING COMPLETE")
print("=" * 70)

print(
    f"\nLDAP rows trained : "
    f"{rows_trained:,}"
)

print(
    f"Training time     : "
    f"{training_time / 60:.2f} minutes"
)


# ============================================================
# SAVE CHECKPOINT 02
# ============================================================

print("\n" + "=" * 70)
print("SAVING CHECKPOINT 02")
print("=" * 70)

with open(
    OUTPUT_CHECKPOINT,
    "wb"
) as f:

    pickle.dump(
        model,
        f,
        protocol=pickle.HIGHEST_PROTOCOL
    )

print(
    "\nCheckpoint 2 saved successfully:"
)

print(
    OUTPUT_CHECKPOINT
)


# ============================================================
# TESTING FUNCTION
# ============================================================

def test_model(test_file, model):

    test_path = os.path.join(
        TEST_FOLDER,
        test_file
    )

    print("\n" + "=" * 70)
    print(f"TESTING: {test_file}")
    print("=" * 70)

    y_actual = []
    y_predicted = []

    rows_tested = 0

    start_time = time.time()

    for chunk in pd.read_csv(
        test_path,
        chunksize=CHUNK_SIZE,
        low_memory=False
    ):

        # ----------------------------------------------------
        # CLEAN COLUMN NAMES
        # ----------------------------------------------------

        chunk.columns = chunk.columns.str.strip()

        if "Label" not in chunk.columns:
            raise ValueError(
                f"'Label' column not found in {test_file}"
            )

        # ----------------------------------------------------
        # CLEAN LABELS
        # ----------------------------------------------------

        y = (
            chunk["Label"]
            .astype(str)
            .str.strip()
        )

        # ----------------------------------------------------
        # REMOVE NON-ML COLUMNS
        # ----------------------------------------------------

        drop_columns = [
            "Unnamed: 0",
            "Flow ID",
            "Source IP",
            "Destination IP",
            "Timestamp",
            "SimillarHTTP",
            "Label"
        ]

        existing_columns = [
            column
            for column in drop_columns
            if column in chunk.columns
        ]

        X = chunk.drop(
            columns=existing_columns
        )

        # ----------------------------------------------------
        # CLEAN FEATURES
        # ----------------------------------------------------

        X = X.replace(
            [float("inf"), float("-inf")],
            0
        )

        for column in X.columns:

            X[column] = pd.to_numeric(
                X[column],
                errors="coerce"
            )

        X = X.fillna(0)

        # ----------------------------------------------------
        # PREDICTION ONLY
        # ----------------------------------------------------

        for i in range(len(X)):

            features = X.iloc[i].to_dict()

            actual_label = y.iloc[i]

            prediction = model.predict_one(
                features
            )

            y_actual.append(actual_label)
            y_predicted.append(prediction)

            rows_tested += 1

        if rows_tested % 100_000 == 0:

            print(
                f"Rows tested: "
                f"{rows_tested:,}"
            )

    testing_time = time.time() - start_time

    # --------------------------------------------------------
    # METRICS
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_actual,
        y_predicted
    )

    precision = precision_score(
        y_actual,
        y_predicted,
        average="weighted",
        zero_division=0
    )

    recall = recall_score(
        y_actual,
        y_predicted,
        average="weighted",
        zero_division=0
    )

    f1 = f1_score(
        y_actual,
        y_predicted,
        average="weighted",
        zero_division=0
    )

    # --------------------------------------------------------
    # RESULTS
    # --------------------------------------------------------

    print("\n" + "-" * 70)

    print(
        f"Rows tested : {rows_tested:,}"
    )

    print(
        f"Testing time: "
        f"{testing_time / 60:.2f} minutes"
    )

    print(
        f"\nAccuracy    : "
        f"{accuracy * 100:.2f}%"
    )

    print(
        f"Precision   : "
        f"{precision * 100:.2f}%"
    )

    print(
        f"Recall      : "
        f"{recall * 100:.2f}%"
    )

    print(
        f"F1-score    : "
        f"{f1 * 100:.2f}%"
    )

    # --------------------------------------------------------
    # CLASSES
    # --------------------------------------------------------

    print("\nActual classes:")
    print(sorted(set(y_actual)))

    print("\nPredicted classes:")
    print(sorted(set(y_predicted)))

    # --------------------------------------------------------
    # CLASSIFICATION REPORT
    # --------------------------------------------------------

    print("\nClassification Report:")

    print(
        classification_report(
            y_actual,
            y_predicted,
            zero_division=0
        )
    )

    # --------------------------------------------------------
    # CONFUSION MATRIX
    # --------------------------------------------------------

    labels = sorted(
        set(y_actual) |
        set(y_predicted)
    )

    cm = confusion_matrix(
        y_actual,
        y_predicted,
        labels=labels
    )

    print("Confusion Matrix:")

    print("\nLabels:")
    print(labels)

    print("\nMatrix:")
    print(cm)

    return y_actual, y_predicted


# ============================================================
# TEST DNS
# ============================================================

dns_actual, dns_predicted = test_model(
    "DrDoS_DNS_test.csv",
    model
)


# ============================================================
# TEST LDAP
# ============================================================

ldap_actual, ldap_predicted = test_model(
    "DrDoS_LDAP_test.csv",
    model
)


# ============================================================
# FINAL
# ============================================================

print("\n" + "=" * 70)
print("CHECKPOINT 02 EXPERIMENT COMPLETE")
print("=" * 70)

print("\nThe ARF has now been trained on:")
print("  1. DrDoS_DNS")
print("  2. DrDoS_LDAP")

print("\nCheckpoint created:")
print("  arf_after_02_LDAP.pkl")

print("\nTesting was performed on:")
print("  DNS 20% test data")
print("  LDAP 20% test data")

print("\nIMPORTANT:")
print("The test data was used ONLY for prediction.")
print("No learn_one() calls were made during testing.")
print("Checkpoint 1 was NOT modified.")
print("Checkpoint 2 contains the updated ARF state.")