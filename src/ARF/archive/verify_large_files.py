import pandas as pd
import numpy as np
from pathlib import Path

# ============================================================
# SETTINGS
# ============================================================

PROCESSED_FOLDER = Path("../processed")

FILES_TO_CHECK = [
    "TFTP_clean.csv",
    "UDP_clean.csv",
    "UDPLag_clean.csv"
]

CHUNK_SIZE = 100000


# ============================================================
# CHECK EACH LARGE FILE
# ============================================================

for filename in FILES_TO_CHECK:

    file = PROCESSED_FOLDER / filename

    print("\n" + "=" * 70)
    print(f"Checking : {filename}")

    if not file.exists():
        print("ERROR: File not found!")
        continue

    total_rows = 0
    nan_count = 0
    infinity_count = 0

    # For detecting constant columns
    first_chunk = True
    unique_values = {}

    # For label distribution
    label_counts = {}

    # For duplicate detection
    # Stores hashes of rows already seen
    seen_hashes = set()
    duplicate_count = 0

    for chunk in pd.read_csv(
        file,
        chunksize=CHUNK_SIZE,
        low_memory=False
    ):

        total_rows += len(chunk)

        # ----------------------------------------------------
        # NaN values
        # ----------------------------------------------------

        nan_count += chunk.isna().sum().sum()

        # ----------------------------------------------------
        # Infinity values
        # ----------------------------------------------------

        numeric_data = chunk.select_dtypes(include=[np.number])

        infinity_count += np.isinf(numeric_data).sum().sum()

        # ----------------------------------------------------
        # Constant-column check
        # ----------------------------------------------------

        if first_chunk:

            for column in chunk.columns:
                unique_values[column] = set()

            first_chunk = False

        for column in chunk.columns:
            # Only keep enough information to determine
            # whether a column has more than one value.
            if len(unique_values[column]) <= 1:
                values = chunk[column].dropna().unique()

                for value in values:
                    unique_values[column].add(value)

                    if len(unique_values[column]) > 1:
                        break

        # ----------------------------------------------------
        # Label distribution
        # ----------------------------------------------------

        if "Label" in chunk.columns:

            counts = chunk["Label"].value_counts()

            for label, count in counts.items():
                label_counts[label] = (
                    label_counts.get(label, 0) + count
                )

        # ----------------------------------------------------
        # Duplicate rows
        # ----------------------------------------------------

        # Hash each row instead of storing the entire row.
        row_hashes = pd.util.hash_pandas_object(
            chunk,
            index=False
        )

        for row_hash in row_hashes:

            row_hash = int(row_hash)

            if row_hash in seen_hashes:
                duplicate_count += 1
            else:
                seen_hashes.add(row_hash)

    # ========================================================
    # RESULTS
    # ========================================================

    constant_columns = [
        column
        for column, values in unique_values.items()
        if len(values) <= 1
    ]

    print(f"\nRows                 : {total_rows:,}")
    print(f"NaN values           : {nan_count:,}")
    print(f"Infinity values      : {infinity_count:,}")
    print(f"Duplicate rows       : {duplicate_count:,}")
    print(f"Constant columns     : {len(constant_columns)}")

    if constant_columns:

        print("\nConstant Columns:")

        for column in constant_columns:
            print(f"   - {column}")

    print("\nLabel Distribution:")

    for label, count in sorted(
        label_counts.items(),
        key=lambda x: x[1],
        reverse=True
    ):
        print(f"   {str(label):<25} {count:,}")

print("\n" + "=" * 70)
print("LARGE FILE VERIFICATION COMPLETE")
print("=" * 70)