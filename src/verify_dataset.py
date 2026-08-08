import pandas as pd
import numpy as np
from pathlib import Path

# ======================================================
# SETTINGS
# ======================================================

PROCESSED_FOLDER = Path("../processed")

csv_files = sorted(PROCESSED_FOLDER.glob("*_clean.csv"))

print(f"\nFound {len(csv_files)} cleaned datasets.\n")

summary = []

# ======================================================
# VERIFY EACH DATASET
# ======================================================

for file in csv_files:

    print("=" * 70)
    print(f"Checking : {file.name}")

    df = pd.read_csv(file, low_memory=False)

    rows, cols = df.shape

    # NaN values
    nan_count = df.isna().sum().sum()

    # Infinite values
    inf_count = np.isinf(df.select_dtypes(include=[np.number])).sum().sum()

    # Duplicate rows
    duplicate_rows = df.duplicated().sum()

    # Constant columns
    constant_columns = [
        col for col in df.columns
        if df[col].nunique(dropna=False) == 1
    ]

    # Label distribution
    label_distribution = (
        df["Label"]
        .value_counts()
        .to_dict()
        if "Label" in df.columns
        else {}
    )

    print(f"Rows                 : {rows:,}")
    print(f"Columns              : {cols}")
    print(f"NaN values           : {nan_count}")
    print(f"Infinity values      : {inf_count}")
    print(f"Duplicate rows       : {duplicate_rows}")
    print(f"Constant columns     : {len(constant_columns)}")

    if constant_columns:
        print("\nConstant Columns:")
        for c in constant_columns:
            print(f"   - {c}")

    print("\nLabel Distribution:")
    for label, count in label_distribution.items():
        print(f"   {label:<20} {count:,}")

    summary.append({
        "Dataset": file.name,
        "Rows": rows,
        "Columns": cols,
        "NaN": nan_count,
        "Infinity": inf_count,
        "Duplicates": duplicate_rows,
        "Constant Columns": len(constant_columns)
    })

# ======================================================
# FINAL SUMMARY
# ======================================================

print("\n")
print("=" * 70)
print("FINAL SUMMARY")
print("=" * 70)

summary_df = pd.DataFrame(summary)

print(summary_df)

summary_df.to_csv("../results/dataset_summary.csv", index=False)

print("\nSummary saved to results/dataset_summary.csv")