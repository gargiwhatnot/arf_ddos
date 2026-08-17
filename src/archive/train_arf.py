import os
import time
import pickle
import pandas as pd

from river import forest


# ============================================================
# CONFIGURATION
# ============================================================

TRAIN_FOLDER = "../train_data"

# Two files for THIS training run
TRAIN_FILES = [
    "DrDoS_MSSQL_train.csv",
    "DrDoS_NetBIOS_train.csv"
]

# Process CSV in manageable chunks
CHUNK_SIZE = 10_000

# Number of trees in Adaptive Random Forest
N_TREES = 10

# Where the trained ARF will be saved
MODEL_FOLDER = "../results"
MODEL_PATH = os.path.join(
    MODEL_FOLDER,
    "arf_checkpoint.pkl"
)


# ============================================================
# SETUP
# ============================================================

os.makedirs(MODEL_FOLDER, exist_ok=True)

print("=" * 70)
print("ADAPTIVE RANDOM FOREST - TWO FILE TRAINING")
print("=" * 70)

print("\nFiles to train:")

for file in TRAIN_FILES:
    print(f"  - {file}")

print(f"\nChunk size : {CHUNK_SIZE:,}")
print(f"ARF trees  : {N_TREES}")
print(f"Checkpoint : {MODEL_PATH}")


# ============================================================
# LOAD EXISTING MODEL OR CREATE NEW MODEL
# ============================================================

if os.path.exists(MODEL_PATH):

    print("\nExisting ARF checkpoint found.")
    print("Loading previous ARF...")

    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)

    print("Previous ARF loaded successfully.")

else:

    print("\nNo previous checkpoint found.")
    print("Creating a NEW Adaptive Random Forest...")

    model = forest.ARFClassifier(
        n_models=N_TREES,
        seed=42
    )

    print("New ARF created successfully.")


# ============================================================
# TRAINING
# ============================================================

print("\n" + "=" * 70)
print("STARTING TRAINING")
print("=" * 70)


total_rows = 0

overall_start = time.time()


for filename in TRAIN_FILES:

    filepath = os.path.join(
        TRAIN_FOLDER,
        filename
    )

    if not os.path.exists(filepath):

        raise FileNotFoundError(
            f"\nFile not found:\n{filepath}"
        )

    print("\n" + "-" * 70)
    print(f"TRAINING FILE: {filename}")
    print("-" * 70)

    file_start = time.time()

    file_rows = 0

    # --------------------------------------------------------
    # READ THE FILE IN CHUNKS
    # --------------------------------------------------------

    for chunk in pd.read_csv(
        filepath,
        chunksize=CHUNK_SIZE,
        low_memory=False
    ):

        # Remove accidental spaces from column names
        chunk.columns = chunk.columns.str.strip()

        # ----------------------------------------------------
        # CHECK LABEL
        # ----------------------------------------------------

        if "Label" not in chunk.columns:

            raise ValueError(
                f"'Label' column not found in {filename}"
            )

        # ----------------------------------------------------
        # SEPARATE LABEL
        # ----------------------------------------------------

        y = chunk["Label"]

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
        # CLEAN VALUES
        # ----------------------------------------------------

        X = X.replace(
            [float("inf"), float("-inf")],
            0
        )

        X = X.fillna(0)

        # ----------------------------------------------------
        # ONLINE ARF TRAINING
        # ----------------------------------------------------

        for i in range(len(X)):

            features = X.iloc[i].to_dict()

            label = y.iloc[i]

            # ONE FLOW AT A TIME
            model.learn_one(
                features,
                label
            )

            file_rows += 1
            total_rows += 1

            # Progress every 100,000 rows
            if file_rows % 100_000 == 0:

                elapsed = time.time() - file_start

                print(
                    f"{filename} | "
                    f"Rows trained: {file_rows:,} | "
                    f"Time: {elapsed / 60:.2f} min"
                )

    file_time = time.time() - file_start

    print(
        f"\nFinished {filename}"
    )

    print(
        f"Rows trained : {file_rows:,}"
    )

    print(
        f"Time         : {file_time / 60:.2f} minutes"
    )


# ============================================================
# SAVE CHECKPOINT
# ============================================================

total_time = time.time() - overall_start

print("\n" + "=" * 70)
print("TRAINING RUN COMPLETE")
print("=" * 70)

print(
    f"Rows processed this run : {total_rows:,}"
)

print(
    f"Training time           : "
    f"{total_time / 60:.2f} minutes"
)


print("\nSaving ARF checkpoint...")


with open(MODEL_PATH, "wb") as f:

    pickle.dump(
        model,
        f,
        protocol=pickle.HIGHEST_PROTOCOL
    )


print(
    f"ARF checkpoint saved to:\n{MODEL_PATH}"
)

print("\n" + "=" * 70)
print("CHECKPOINT SAVED SUCCESSFULLY")
print("=" * 70)