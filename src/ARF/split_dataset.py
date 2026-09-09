"""Create reproducible train/test CSV splits from cleaned files."""

from __future__ import annotations

import argparse
from pathlib import Path
import time

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", default=str(PROJECT_ROOT / "processed"))
    parser.add_argument("--train-dir", default=str(PROJECT_ROOT / "train_data"))
    parser.add_argument("--test-dir", default=str(PROJECT_ROOT / "test_data"))
    parser.add_argument("--ratio", type=float, default=0.80)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--chunk-size", type=int, default=100_000)
    args = parser.parse_args()

    if not 0.0 < args.ratio < 1.0:
        raise ValueError("--ratio must be between 0 and 1")

    input_dir = Path(args.input_dir).expanduser().resolve()
    train_dir = Path(args.train_dir).expanduser().resolve()
    test_dir = Path(args.test_dir).expanduser().resolve()
    train_dir.mkdir(parents=True, exist_ok=True)
    test_dir.mkdir(parents=True, exist_ok=True)

    files = sorted(input_dir.glob("*_clean.csv"))
    if not files:
        raise FileNotFoundError(f"No *_clean.csv files found in {input_dir}")

    rng = np.random.default_rng(args.seed)
    print(f"Found {len(files)} cleaned files")

    for input_file in files:
        train_file = train_dir / input_file.name.replace("_clean.csv", "_train.csv")
        test_file = test_dir / input_file.name.replace("_clean.csv", "_test.csv")
        for path in (train_file, test_file):
            if path.exists():
                path.unlink()

        train_written = False
        test_written = False
        total_rows = train_rows = test_rows = 0
        start = time.time()

        for chunk in pd.read_csv(input_file, chunksize=args.chunk_size, low_memory=False):
            total_rows += len(chunk)
            train_mask = rng.random(len(chunk)) < args.ratio
            train_chunk = chunk.loc[train_mask]
            test_chunk = chunk.loc[~train_mask]
            train_rows += len(train_chunk)
            test_rows += len(test_chunk)

            if not train_chunk.empty:
                train_chunk.to_csv(
                    train_file,
                    mode="a" if train_written else "w",
                    header=not train_written,
                    index=False,
                )
                train_written = True
            if not test_chunk.empty:
                test_chunk.to_csv(
                    test_file,
                    mode="a" if test_written else "w",
                    header=not test_written,
                    index=False,
                )
                test_written = True

        print(
            f"{input_file.name}: total={total_rows:,}, "
            f"train={train_rows:,} ({train_rows / total_rows * 100:.2f}%), "
            f"test={test_rows:,} ({test_rows / total_rows * 100:.2f}%), "
            f"time={time.time() - start:.2f}s"
        )

    print("80/20 TRAIN-TEST SPLIT COMPLETED")


if __name__ == "__main__":
    main()
