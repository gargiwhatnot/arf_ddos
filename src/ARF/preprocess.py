"""Clean CIC-DDoS2019 CSV files without loading a whole file into memory.

Numerical scaling is deliberately fitted later by ``train_arf_v2.py`` on the
training split only, preventing test-set leakage.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import time

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT_CANDIDATES = [
    PROJECT_ROOT / "datasets",
    PROJECT_ROOT / "dataset",
    PROJECT_ROOT / "src" / "dataset",
    PROJECT_ROOT.parent / "dataset",
]
DEFAULT_OUTPUT = PROJECT_ROOT / "processed"
CHUNK_SIZE = 100_000

DROP_COLUMNS = {
    "unnamed: 0",
    "flow id",
    "source ip",
    "destination ip",
    "timestamp",
}

CONSTANT_COLUMNS = {
    "bwd psh flags",
    "fwd urg flags",
    "bwd urg flags",
    "fin flag count",
    "psh flag count",
    "ece flag count",
    "fwd avg bytes/bulk",
    "fwd avg packets/bulk",
    "fwd avg bulk rate",
    "bwd avg bytes/bulk",
    "bwd avg packets/bulk",
    "bwd avg bulk rate",
}


def find_input_dir(value: str | None) -> Path:
    if value:
        path = Path(value).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"Input dataset directory not found: {path}")
        return path
    for path in DEFAULT_INPUT_CANDIDATES:
        if path.exists() and any(path.rglob("*.csv")):
            return path
    choices = ", ".join(str(path) for path in DEFAULT_INPUT_CANDIDATES)
    raise FileNotFoundError(
        "No dataset CSV directory found. Checked: " + choices
    )


def output_name(input_file: Path) -> str:
    stem = input_file.stem
    return f"{stem}.csv" if stem.endswith("_clean") else f"{stem}_clean.csv"


def process_file(input_file: Path, output_file: Path, chunk_size: int) -> dict:
    if output_file.exists():
        output_file.unlink()

    first_chunk = True
    total_rows = 0
    nan_removed = 0
    duplicate_removed = 0
    final_rows = 0
    seen_hashes: set[int] = set()
    start = time.time()

    for chunk in pd.read_csv(input_file, chunksize=chunk_size, low_memory=False):
        total_rows += len(chunk)
        chunk.columns = chunk.columns.astype(str).str.strip()

        drop_columns = [
            column for column in chunk.columns
            if column.strip().lower() in DROP_COLUMNS
            or column.strip().lower() in CONSTANT_COLUMNS
        ]
        if drop_columns:
            chunk.drop(columns=drop_columns, inplace=True)

        if "Label" in chunk.columns:
            chunk["Label"] = chunk["Label"].astype(str).str.strip()

        chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
        before = len(chunk)
        chunk.dropna(inplace=True)
        nan_removed += before - len(chunk)

        if not chunk.empty:
            hashes = pd.util.hash_pandas_object(chunk, index=False)
            keep = []
            for value in hashes:
                row_hash = int(value)
                if row_hash in seen_hashes:
                    keep.append(False)
                    duplicate_removed += 1
                else:
                    keep.append(True)
                    seen_hashes.add(row_hash)
            chunk = chunk.loc[keep]

        if not chunk.empty:
            chunk.to_csv(
                output_file,
                mode="w" if first_chunk else "a",
                header=first_chunk,
                index=False,
            )
            first_chunk = False
            final_rows += len(chunk)

    return {
        "input": str(input_file),
        "output": str(output_file),
        "original_rows": total_rows,
        "nan_removed": nan_removed,
        "duplicates_removed": duplicate_removed,
        "final_rows": final_rows,
        "seconds": round(time.time() - start, 2),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", help="Raw dataset directory")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--files", nargs="*", help="Specific CSV paths")
    parser.add_argument("--chunk-size", type=int, default=CHUNK_SIZE)
    args = parser.parse_args()

    input_dir = find_input_dir(args.input_dir)
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    files = [
        Path(file).expanduser().resolve() for file in args.files
    ] if args.files else sorted(input_dir.rglob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files found under {input_dir}")

    print(f"Input directory : {input_dir}")
    print(f"Output directory: {output_dir}")
    print(f"Files found     : {len(files)}")

    for input_file in files:
        if not input_file.exists():
            print(f"SKIP missing file: {input_file}")
            continue
        output_file = output_dir / output_name(input_file)
        print(f"\nProcessing: {input_file}")
        summary = process_file(input_file, output_file, args.chunk_size)
        print(f"Original rows      : {summary['original_rows']:,}")
        print(f"NaN rows removed   : {summary['nan_removed']:,}")
        print(f"Duplicates removed : {summary['duplicates_removed']:,}")
        print(f"Final rows         : {summary['final_rows']:,}")
        print(f"Time               : {summary['seconds']:.2f} seconds")

    print("\nDATASET CLEANING COMPLETED")


if __name__ == "__main__":
    main()
