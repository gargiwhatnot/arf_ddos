import os
import time
import pickle
import pandas as pd

from river import forest


# ============================================================
# CONFIGURATION
# ============================================================

TRAIN_FOLDER = "../train_data"

TRAIN_FILE = "DrDoS_DNS_train.csv"

CHUNK_SIZE = 10_000

N_TREES = 10

CHECKPOINT_FOLDER = "../results/checkpoints"

CHECKPOINT_PATH = os.path.join(
    CHECKPOINT_FOLDER,
    "arf_after_01_DNS.pkl"
)


# ============================================================
# SETUP
# ============================================================

os.makedirs(
    CHECKPOINT_FOLDER,
    exist_ok=True
)

print("=" * 70)
print("ADAPTIVE RANDOM FOREST - CHECKPOINT 01")
print("=" * 70)

print("\nTraining file:")
print(f"  {TRAIN_FILE}")

print(f"\nChunk size : {CHUNK_SIZE:,}")
print(f"ARF trees  : {N_TREES}")

print("\nThis run creates a NEW ARF.")
print("No previous checkpoint will be loaded.")

print(f"\nCheckpoint:")
print(f"  {CHECKPOINT_PATH}")


# ============================================================
# CREATE NEW ARF
# ============================================================

print("\n" + "=" * 70)
print("CREATING NEW ARF")
print("=" * 70)

model = forest.ARFClassifier(
    n_models=N_TREES,
    seed=42
)

print("\nNew ARF classifier created successfully.")


# ============================================================
# TRAINING
# ============================================================

filepath = os.path.join(
    TRAIN_FOLDER,
    TRAIN_FILE
)

if not os.path.exists(filepath):

    raise FileNotFoundError(
        f"\nTraining file not found:\n{filepath}"
    )


print("\n" + "=" * 70)
print("STARTING DNS TRAINING")
print("=" * 70)

start_time = time.time()

rows_trained = 0


# ============================================================
# READ CSV IN CHUNKS
# ============================================================

for chunk in pd.read_csv(
    filepath,
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
            "'Label' column not found after "
            "stripping column whitespace."
        )

    # --------------------------------------------------------
    # CLEAN LABEL VALUES
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
    # CLEAN FEATURE VALUES
    # --------------------------------------------------------

    X = X.replace(
        [float("inf"), float("-inf")],
        0
    )

    # Convert features to numeric
    for column in X.columns:

        X[column] = pd.to_numeric(
            X[column],
            errors="coerce"
        )

    X = X.fillna(0)

    # --------------------------------------------------------
    # ONLINE ARF TRAINING
    # --------------------------------------------------------

    for i in range(len(X)):

        features = X.iloc[i].to_dict()

        label = y.iloc[i]

        model.learn_one(
            features,
            label
        )

        rows_trained += 1

        # ----------------------------------------------------
        # PROGRESS
        # ----------------------------------------------------

        if rows_trained % 100_000 == 0:

            elapsed = time.time() - start_time

            print(
                f"Rows trained: "
                f"{rows_trained:,} | "
                f"Time: "
                f"{elapsed / 60:.2f} min"
            )


# ============================================================
# TRAINING COMPLETE
# ============================================================

training_time = time.time() - start_time

print("\n" + "=" * 70)
print("DNS TRAINING COMPLETE")
print("=" * 70)

print(
    f"\nRows trained : "
    f"{rows_trained:,}"
)

print(
    f"Training time: "
    f"{training_time / 60:.2f} minutes"
)


# ============================================================
# SAVE CHECKPOINT
# ============================================================

print("\n" + "=" * 70)
print("SAVING CHECKPOINT")
print("=" * 70)

with open(
    CHECKPOINT_PATH,
    "wb"
) as f:

    pickle.dump(
        model,
        f,
        protocol=pickle.HIGHEST_PROTOCOL
    )


print(
    "\nCheckpoint saved successfully:"
)

print(
    CHECKPOINT_PATH
)


# ============================================================
# FINAL INFORMATION
# ============================================================

print("\n" + "=" * 70)
print("CHECKPOINT 01 COMPLETE")
print("=" * 70)

print("\nModel:")
print("  NEW ARF")

print("\nTrained on:")
print("  DrDoS_DNS_train.csv")

print("\nTrees:")
print(f"  {N_TREES}")

print("\nRows:")
print(f"  {rows_trained:,}")

print("\nCheckpoint:")
print("  arf_after_01_DNS.pkl")

print("\nThe old checkpoint was NOT loaded.")
print("The old checkpoint was NOT modified.")