import os
import pickle
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_PATH = "../results/arf_checkpoint.pkl"

TEST_FOLDER = "../test_data"

TEST_FILES = [
    "DrDoS_DNS_test.csv",
    "DrDoS_LDAP_test.csv",
    "DrDoS_MSSQL_test.csv",
    "DrDoS_NetBIOS_test.csv"
]


# ============================================================
# LOAD MODEL
# ============================================================

print("=" * 70)
print("ARF - ONE SAMPLE PER ATTACK TYPE")
print("=" * 70)

print("\nLoading checkpoint...")

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

print("Checkpoint loaded successfully.")

print("\nTrees:", len(model.models))


# ============================================================
# TEST ONE SAMPLE FROM EACH FILE
# ============================================================

for filename in TEST_FILES:

    filepath = os.path.join(
        TEST_FOLDER,
        filename
    )

    print("\n" + "=" * 70)
    print(f"FILE: {filename}")
    print("=" * 70)

    # Read ONLY one row
    df = pd.read_csv(
        filepath,
        nrows=1,
        low_memory=False
    )

    # Clean column names
    df.columns = df.columns.str.strip()

    # Get actual label
    actual = str(
        df["Label"].iloc[0]
    ).strip()

    # Remove non-feature columns
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
        if column in df.columns
    ]

    X = df.drop(
        columns=existing_columns
    )

    # Clean values
    X = X.replace(
        [float("inf"), float("-inf")],
        0
    )

    X = X.fillna(0)

    # Convert features to numeric
    for column in X.columns:
        X[column] = pd.to_numeric(
            X[column],
            errors="coerce"
        )

    X = X.fillna(0)

    # Convert row to River dictionary
    features = X.iloc[0].to_dict()

    # --------------------------------------------------------
    # PREDICTION
    # --------------------------------------------------------

    prediction = model.predict_one(
        features
    )

    probabilities = model.predict_proba_one(
        features
    )

    print("\nActual label:")
    print(actual)

    print("\nPredicted label:")
    print(prediction)

    print("\nProbabilities:")

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

        print("  No probabilities returned.")


# ============================================================
# DONE
# ============================================================

print("\n" + "=" * 70)
print("TEST COMPLETE")
print("=" * 70)

print(
    "\nThe checkpoint was only used for prediction."
    "\nNo learn_one() calls were made."
    "\nThe checkpoint was not modified."
)