import os
import pickle
import time

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

TEST_FOLDER = "../test_data"

TEST_FILES = [
    "DrDoS_DNS_test.csv",
    "DrDoS_LDAP_test.csv",
    "DrDoS_MSSQL_test.csv",
    "DrDoS_NetBIOS_test.csv"
]

MODEL_PATH = "../results/arf_checkpoint.pkl"

CHUNK_SIZE = 10_000

# Number of DNS samples to inspect individually
DIAGNOSTIC_SAMPLES = 5


# ============================================================
# LOAD ARF CHECKPOINT
# ============================================================

print("=" * 70)
print("ADAPTIVE RANDOM FOREST - CHECKPOINT DIAGNOSTICS + EVALUATION")
print("=" * 70)

print(f"\nModel: {MODEL_PATH}")

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        f"\nARF checkpoint not found:\n{MODEL_PATH}"
    )

print("\nLoading trained ARF...")

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

print("ARF loaded successfully.")


# ============================================================
# CHECKPOINT DIAGNOSTICS
# ============================================================

print("\n" + "=" * 70)
print("CHECKPOINT DIAGNOSTICS")
print("=" * 70)

print("\nModel type:")
print(type(model))

print("\nNumber of trees:")

try:
    print(len(model.models))
except Exception as e:
    print("Could not determine tree count.")
    print("Error:", e)

print("\nARF methods available:")
print(
    "predict_one       :",
    hasattr(model, "predict_one")
)

print(
    "predict_proba_one :",
    hasattr(model, "predict_proba_one")
)

print(
    "learn_one         :",
    hasattr(model, "learn_one")
)

print("\nCheckpoint loaded successfully.")

print(
    "\nIMPORTANT:"
    "\nThis script will NOT call learn_one()."
    "\nThe checkpoint will not be modified."
)


# ============================================================
# STORAGE FOR OVERALL RESULTS
# ============================================================

all_actual = []
all_predicted = []

overall_start = time.time()

diagnostic_done = False


# ============================================================
# TEST EACH FILE
# ============================================================

for filename in TEST_FILES:

    filepath = os.path.join(
        TEST_FOLDER,
        filename
    )

    if not os.path.exists(filepath):
        raise FileNotFoundError(
            f"\nTest file not found:\n{filepath}"
        )

    print("\n" + "=" * 70)
    print(f"TESTING: {filename}")
    print("=" * 70)

    file_actual = []
    file_predicted = []

    file_start = time.time()
    rows_processed = 0

    # --------------------------------------------------------
    # READ CSV IN CHUNKS
    # --------------------------------------------------------

    for chunk in pd.read_csv(
        filepath,
        chunksize=CHUNK_SIZE,
        low_memory=False
    ):

        # ----------------------------------------------------
        # CLEAN COLUMN NAMES
        # ----------------------------------------------------

        chunk.columns = chunk.columns.str.strip()

        # ----------------------------------------------------
        # CHECK LABEL COLUMN
        # ----------------------------------------------------

        if "Label" not in chunk.columns:
            raise ValueError(
                f"'Label' column not found in {filename}"
            )

        # Strip accidental whitespace from labels too
        y = chunk["Label"].astype(str).str.strip()

        # ----------------------------------------------------
        # REMOVE NON-FEATURE COLUMNS
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
        # CLEAN INFINITY / NaN
        # ----------------------------------------------------

        X = X.replace(
            [float("inf"), float("-inf")],
            0
        )

        X = X.fillna(0)

        # ----------------------------------------------------
        # FORCE FEATURES TO NUMERIC
        # ----------------------------------------------------

        for column in X.columns:
            X[column] = pd.to_numeric(
                X[column],
                errors="coerce"
            )

        X = X.fillna(0)

        # ----------------------------------------------------
        # DIAGNOSTIC:
        # FIRST 5 DNS SAMPLES
        #
        # This only calls prediction.
        # It DOES NOT train the ARF.
        # ----------------------------------------------------

        if (
            not diagnostic_done
            and filename == "DrDoS_DNS_test.csv"
        ):

            print("\n" + "-" * 70)
            print("DNS SAMPLE PREDICTION DIAGNOSTICS")
            print("-" * 70)

            sample_count = min(
                DIAGNOSTIC_SAMPLES,
                len(X)
            )

            for i in range(sample_count):

                features = X.iloc[i].to_dict()

                actual = y.iloc[i]

                # Prediction
                prediction = model.predict_one(
                    features
                )

                # Probability distribution
                probabilities = model.predict_proba_one(
                    features
                )

                print(f"\nSample {i + 1}")

                print(
                    f"Actual     : {actual}"
                )

                print(
                    f"Prediction : {prediction}"
                )

                print("Probabilities:")

                if probabilities:

                    sorted_probabilities = sorted(
                        probabilities.items(),
                        key=lambda item: item[1],
                        reverse=True
                    )

                    for label, probability in sorted_probabilities:

                        print(
                            f"  {label}: "
                            f"{probability:.6f}"
                        )

                else:
                    print(
                        "  No probabilities returned."
                    )

            print("-" * 70)

            diagnostic_done = True

        # ----------------------------------------------------
        # NORMAL TESTING
        #
        # ONLY predict_one()
        #
        # NEVER learn_one()
        # ----------------------------------------------------

        for i in range(len(X)):

            features = X.iloc[i].to_dict()

            actual = y.iloc[i]

            predicted = model.predict_one(
                features
            )

            if predicted is None:
                predicted = "UNKNOWN"

            file_actual.append(actual)
            file_predicted.append(predicted)

            all_actual.append(actual)
            all_predicted.append(predicted)

            rows_processed += 1

    # ========================================================
    # FILE RESULTS
    # ========================================================

    file_time = time.time() - file_start

    accuracy = accuracy_score(
        file_actual,
        file_predicted
    )

    precision = precision_score(
        file_actual,
        file_predicted,
        average="weighted",
        zero_division=0
    )

    recall = recall_score(
        file_actual,
        file_predicted,
        average="weighted",
        zero_division=0
    )

    f1 = f1_score(
        file_actual,
        file_predicted,
        average="weighted",
        zero_division=0
    )

    print(
        f"\nRows tested : {rows_processed:,}"
    )

    print(
        f"Time        : "
        f"{file_time / 60:.2f} minutes"
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

    print("\nActual classes:")
    print(sorted(set(file_actual)))

    print("\nPredicted classes:")
    print(sorted(set(file_predicted)))

    print("\nClassification Report:")

    print(
        classification_report(
            file_actual,
            file_predicted,
            zero_division=0
        )
    )

    print("Confusion Matrix:")

    print(
        confusion_matrix(
            file_actual,
            file_predicted
        )
    )


# ============================================================
# OVERALL RESULTS
# ============================================================

overall_time = time.time() - overall_start

print("\n" + "=" * 70)
print("OVERALL EVALUATION")
print("=" * 70)

overall_accuracy = accuracy_score(
    all_actual,
    all_predicted
)

overall_precision = precision_score(
    all_actual,
    all_predicted,
    average="weighted",
    zero_division=0
)

overall_recall = recall_score(
    all_actual,
    all_predicted,
    average="weighted",
    zero_division=0
)

overall_f1 = f1_score(
    all_actual,
    all_predicted,
    average="weighted",
    zero_division=0
)

print(
    f"\nTotal test rows : "
    f"{len(all_actual):,}"
)

print(
    f"Testing time    : "
    f"{overall_time / 60:.2f} minutes"
)

print(
    f"\nAccuracy        : "
    f"{overall_accuracy * 100:.2f}%"
)

print(
    f"Precision       : "
    f"{overall_precision * 100:.2f}%"
)

print(
    f"Recall          : "
    f"{overall_recall * 100:.2f}%"
)

print(
    f"F1-score        : "
    f"{overall_f1 * 100:.2f}%"
)

print("\nActual classes:")
print(sorted(set(all_actual)))

print("\nPredicted classes:")
print(sorted(set(all_predicted)))

print("\nOverall Classification Report:")

print(
    classification_report(
        all_actual,
        all_predicted,
        zero_division=0
    )
)

print("\nOverall Confusion Matrix:")

print(
    confusion_matrix(
        all_actual,
        all_predicted
    )
)

print("\n" + "=" * 70)
print("EVALUATION COMPLETE")
print("=" * 70)

print(
    "\nIMPORTANT:"
    "\nThe 20% test data was used ONLY for prediction."
    "\nThe ARF was NOT updated during testing."
    "\nThe checkpoint was NOT modified."
)