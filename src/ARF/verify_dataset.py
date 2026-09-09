"""Verify cleaned datasets using streaming checks."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def verify_file(path: Path, chunk_size: int) -> dict:
    rows = 0
    nan_count = 0
    inf_count = 0
    duplicate_rows = 0
    label_counts = Counter()
    seen_hashes: set[int] = set()
    unique_values: dict[str, set] = {}

    for chunk in pd.read_csv(path, chunksize=chunk_size, low_memory=False):
        chunk.columns = chunk.columns.astype(str).str.strip()
        rows += len(chunk)
        nan_count += int(chunk.isna().sum().sum())
        numeric = chunk.select_dtypes(include=[np.number])
        inf_count += int(np.isinf(numeric).sum().sum())
        if "Label" in chunk.columns:
            label_counts.update(chunk["Label"].astype(str).str.strip())

        for column in chunk.columns:
            values = unique_values.setdefault(column, set())
            if len(values) <= 1:
                values.update(chunk[column].dropna().unique().tolist()[:2])

        for value in pd.util.hash_pandas_object(chunk, index=False):
            row_hash = int(value)
            if row_hash in seen_hashes:
                duplicate_rows += 1
            else:
                seen_hashes.add(row_hash)

    constants = [column for column, values in unique_values.items() if len(values) == 1]
    return {
        "file": path.name,
        "rows": rows,
        "columns": len(unique_values),
        "nan": nan_count,
        "infinity": inf_count,
        "duplicates": duplicate_rows,
        "constant_columns": len(constants),
        "constant_names": constants,
        "labels": dict(label_counts),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", default=str(PROJECT_ROOT / "processed"))
    parser.add_argument("--results-dir", default=str(PROJECT_ROOT / "results"))
    parser.add_argument("--chunk-size", type=int, default=100_000)
    args = parser.parse_args()

    input_dir = Path(args.input_dir).expanduser().resolve()
    results_dir = Path(args.results_dir).expanduser().resolve()
    results_dir.mkdir(parents=True, exist_ok=True)
    files = sorted(input_dir.glob("*_clean.csv"))
    if not files:
        raise FileNotFoundError(f"No *_clean.csv files found in {input_dir}")

    summaries = []
    for file in files:
        summary = verify_file(file, args.chunk_size)
        summaries.append(summary)
        print("\n" + "=" * 70)
        print(f"Checking: {summary['file']}")
        print(f"Rows             : {summary['rows']:,}")
        print(f"Columns          : {summary['columns']}")
        print(f"NaN values       : {summary['nan']:,}")
        print(f"Infinity values  : {summary['infinity']:,}")
        print(f"Duplicate rows   : {summary['duplicates']:,}")
        print(f"Constant columns : {summary['constant_columns']}")
        print(f"Labels           : {summary['labels']}")

    output = results_dir / "dataset_summary.csv"
    pd.DataFrame(
        [{key: value for key, value in summary.items() if key not in {"labels", "constant_names"}}
         for summary in summaries]
    ).to_csv(output, index=False)
    print(f"\nSummary saved to: {output}")


if __name__ == "__main__":
    main()
