import pandas as pd
from pathlib import Path

PROCESSED_FOLDER = Path("../processed")

files = sorted(PROCESSED_FOLDER.glob("*_clean.csv"))

print(f"Found {len(files)} cleaned files.\n")

reference_columns = None
reference_file = None

for file in files:

    # Only read the header, not the entire huge file
    columns = pd.read_csv(
        file,
        nrows=0
    ).columns.tolist()

    print(f"{file.name}: {len(columns)} columns")

    if reference_columns is None:
        reference_columns = columns
        reference_file = file.name
        continue

    if columns == reference_columns:
        print("   ✓ Columns match")
    else:
        print("   ✗ Columns DO NOT match")

        missing = [
            col for col in reference_columns
            if col not in columns
        ]

        extra = [
            col for col in columns
            if col not in reference_columns
        ]

        if missing:
            print("   Missing:")
            for col in missing:
                print(f"      - {col}")

        if extra:
            print("   Extra:")
            for col in extra:
                print(f"      - {col}")

print("\n" + "=" * 60)

if all(
    pd.read_csv(file, nrows=0).columns.tolist() == reference_columns
    for file in files
):
    print("SUCCESS: All cleaned files have identical columns.")
else:
    print("WARNING: Some files have different columns.")

print("=" * 60)