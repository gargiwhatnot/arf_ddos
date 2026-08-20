import pandas as pd
import numpy as np
from pathlib import Path
import time

# ============================================================
# SETTINGS
# ============================================================

INPUT_FOLDER = Path("../processed")

TRAIN_FOLDER = Path("../train_data")
TEST_FOLDER = Path("../test_data")

CHUNK_SIZE = 100_000

TRAIN_RATIO = 0.80

RANDOM_SEED = 42

# ============================================================
# CREATE OUTPUT FOLDERS
# ============================================================

TRAIN_FOLDER.mkdir(exist_ok=True)
TEST_FOLDER.mkdir(exist_ok=True)

# ============================================================
# FIND CLEANED DATASETS
# ============================================================

csv_files = sorted(INPUT_FOLDER.glob("*_clean.csv"))

print(f"\nFound {len(csv_files)} cleaned CSV files.\n")

if len(csv_files) == 0:
    raise FileNotFoundError(
        "No *_clean.csv files were found in the processed folder."
    )

# ============================================================
# PROCESS EACH DATASET
# ============================================================

for input_file in csv_files:

    print("=" * 70)
    print(f"Processing: {input_file.name}")

    start_time = time.time()

    train_file = TRAIN_FOLDER / input_file.name.replace(
        "_clean.csv",
        "_train.csv"
    )

    test_file = TEST_FOLDER / input_file.name.replace(
        "_clean.csv",
        "_test.csv"
    )

    # Remove old output files if they already exist
    if train_file.exists():
        train_file.unlink()

    if test_file.exists():
        test_file.unlink()

    first_chunk = True

    total_rows = 0
    train_rows = 0
    test_rows = 0

    # ========================================================
    # READ FILE IN CHUNKS
    # ========================================================

    for chunk in pd.read_csv(
        input_file,
        chunksize=CHUNK_SIZE,
        low_memory=False
    ):

        total_rows += len(chunk)

        # ----------------------------------------------------
        # Generate reproducible random numbers
        # ----------------------------------------------------

        rng = np.random.default_rng(
            RANDOM_SEED + total_rows
        )

        random_values = rng.random(len(chunk))

        train_mask = random_values < TRAIN_RATIO

        train_chunk = chunk[train_mask]
        test_chunk = chunk[~train_mask]

        train_rows += len(train_chunk)
        test_rows += len(test_chunk)

        # ----------------------------------------------------
        # Save training data
        # ----------------------------------------------------

        if len(train_chunk) > 0:

            train_chunk.to_csv(
                train_file,
                mode="w" if first_chunk else "a",
                header=first_chunk,
                index=False
            )

        # ----------------------------------------------------
        # Save testing data
        # ----------------------------------------------------

        if len(test_chunk) > 0:

            test_chunk.to_csv(
                test_file,
                mode="w" if first_chunk else "a",
                header=first_chunk,
                index=False
            )

        first_chunk = False

    elapsed = time.time() - start_time

    # ========================================================
    # RESULTS
    # ========================================================

    train_percentage = (
        train_rows / total_rows * 100
        if total_rows > 0
        else 0
    )

    test_percentage = (
        test_rows / total_rows * 100
        if total_rows > 0
        else 0
    )

    print(f"\nOriginal rows : {total_rows:,}")

    print(
        f"Training rows : {train_rows:,} "
        f"({train_percentage:.2f}%)"
    )

    print(
        f"Testing rows  : {test_rows:,} "
        f"({test_percentage:.2f}%)"
    )

    print(f"Time          : {elapsed:.2f} seconds")

print("\n" + "=" * 70)
print("80/20 TRAIN-TEST SPLIT COMPLETED SUCCESSFULLY")
print("=" * 70)