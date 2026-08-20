import pandas as pd
import numpy as np
from pathlib import Path
import time

# ============================================================
# SETTINGS
# ============================================================

DATASET_FOLDER_01 = Path("../dataset/01-12")
DATASET_FOLDER_03 = Path("../dataset/03-11")

OUTPUT_FOLDER = Path("../processed")

CHUNK_SIZE = 100000

OUTPUT_FOLDER.mkdir(exist_ok=True)

# ============================================================
# FOUR FILES TO PROCESS
# ============================================================

FILES_TO_PROCESS = [
    (DATASET_FOLDER_01 / "Syn.csv", "Syn_clean.csv"),
    (DATASET_FOLDER_01 / "UDPLag.csv", "UDPLag_clean.csv"),

    (DATASET_FOLDER_03 / "Syn2.csv", "Syn2_clean.csv"),
    (DATASET_FOLDER_03 / "UDPLag2.csv", "UDPLag2_clean.csv"),
]

# ============================================================
# COLUMNS TO REMOVE
# ============================================================

DROP_COLUMNS = [
    "Unnamed: 0",
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Timestamp"
]

# Constant columns found during our verification
CONSTANT_COLUMNS = [
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "FIN Flag Count",
    "PSH Flag Count",
    "ECE Flag Count",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate"
]

# ============================================================
# PROCESS
# ============================================================

for input_file, output_name in FILES_TO_PROCESS:

    print("\n" + "=" * 70)
    print(f"Processing: {input_file}")
    print(f"Output    : {output_name}")

    if not input_file.exists():
        print("ERROR: Input file not found!")
        continue

    output_file = OUTPUT_FOLDER / output_name

    # Delete existing output if present
    if output_file.exists():
        output_file.unlink()

    start_time = time.time()

    first_chunk = True

    total_rows = 0
    nan_removed = 0
    duplicate_removed = 0

    # Hashes of rows already encountered
    seen_hashes = set()

    # ========================================================
    # READ IN CHUNKS
    # ========================================================

    for chunk in pd.read_csv(
        input_file,
        chunksize=CHUNK_SIZE,
        low_memory=False
    ):

        total_rows += len(chunk)

        # ----------------------------------------------------
        # Clean column names
        # ----------------------------------------------------

        chunk.columns = chunk.columns.str.strip()

        # ----------------------------------------------------
        # Remove identifier columns
        # ----------------------------------------------------

        chunk.drop(
            columns=DROP_COLUMNS,
            errors="ignore",
            inplace=True
        )

        # ----------------------------------------------------
        # Remove constant columns
        # ----------------------------------------------------

        chunk.drop(
            columns=CONSTANT_COLUMNS,
            errors="ignore",
            inplace=True
        )

        # ----------------------------------------------------
        # Replace infinity
        # ----------------------------------------------------

        chunk.replace(
            [np.inf, -np.inf],
            np.nan,
            inplace=True
        )

        # ----------------------------------------------------
        # Remove NaN rows
        # ----------------------------------------------------

        before_nan = len(chunk)

        chunk.dropna(inplace=True)

        nan_removed += before_nan - len(chunk)

        # ----------------------------------------------------
        # Remove duplicate rows
        # ----------------------------------------------------

        if len(chunk) > 0:

            row_hashes = pd.util.hash_pandas_object(
                chunk,
                index=False
            )

            keep_mask = []
            new_hashes = set()

            for row_hash in row_hashes:

                row_hash = int(row_hash)

                if row_hash in seen_hashes:
                    keep_mask.append(False)
                    duplicate_removed += 1

                else:
                    keep_mask.append(True)
                    seen_hashes.add(row_hash)

            chunk = chunk.loc[keep_mask]

        # ----------------------------------------------------
        # Save cleaned chunk
        # ----------------------------------------------------

        if len(chunk) > 0:

            chunk.to_csv(
                output_file,
                mode="w" if first_chunk else "a",
                header=first_chunk,
                index=False
            )

            first_chunk = False

    # ========================================================
    # FINAL INFORMATION
    # ========================================================

    final_rows = len(seen_hashes)

    elapsed = time.time() - start_time

    print("\nCompleted:")
    print(f"Original rows      : {total_rows:,}")
    print(f"NaN rows removed   : {nan_removed:,}")
    print(f"Duplicates removed : {duplicate_removed:,}")
    print(f"Final rows         : {final_rows:,}")
    print(f"Time               : {elapsed:.2f} seconds")

print("\n" + "=" * 70)
print("FOUR DATASETS CLEANED SUCCESSFULLY")
print("=" * 70)