"""Train a binary Adaptive Random Forest with the shared feature schema."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from shared.pipeline import CANONICAL_FEATURES, canonicalize_row, normalize_label
from shared.preprocessing import StandardFeatureScaler


def discover_files(train_dir: Path, requested: list[str] | None) -> list[Path]:
    if requested:
        files = []
        for value in requested:
            path = Path(value).expanduser()
            path = path if path.is_absolute() else train_dir / path
            files.append(path.resolve())
    else:
        files = sorted(train_dir.glob("*.csv"))
    files = [path for path in files if path.exists()]
    if not files:
        raise FileNotFoundError(f"No training CSV files found in {train_dir}")
    return files


def iter_rows(path: Path, chunk_size: int, binary: bool):
    for chunk in pd.read_csv(path, chunksize=chunk_size, low_memory=False):
        chunk.columns = chunk.columns.astype(str).str.strip()
        if "Label" not in chunk.columns:
            raise ValueError(f"'Label' column not found in {path}")
        for record in chunk.to_dict(orient="records"):
            yield canonicalize_row(record), normalize_label(
                record.get("Label"), binary=binary
            )


def collect_fit_sample(
    files: list[Path],
    sample_limit: int,
    chunk_size: int,
    binary: bool,
) -> tuple[list[dict[str, float]], list[str]]:
    rows: list[dict[str, float]] = []
    labels: list[str] = []
    per_file = max(100, sample_limit // max(len(files), 1))

    for path in files:
        taken = 0
        for features, label in iter_rows(path, chunk_size, binary):
            rows.append(features)
            labels.append(label)
            taken += 1
            if taken >= per_file:
                break
        if len(rows) >= sample_limit:
            break

    return rows[:sample_limit], labels[:sample_limit]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train-dir", default=str(PROJECT_ROOT / "train_data"))
    parser.add_argument("--output", default=str(PROJECT_ROOT / "results" / "arf_controller.pkl"))
    parser.add_argument("--summary", default=str(PROJECT_ROOT / "results" / "training_summary.json"))
    parser.add_argument("--files", nargs="*", help="Training CSV names or paths")
    parser.add_argument("--trees", type=int, default=10)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--fit-sample", type=int, default=50_000)
    parser.add_argument("--chunk-size", type=int, default=10_000)
    parser.add_argument(
        "--multiclass",
        action="store_true",
        help="Keep original attack labels instead of Normal/DDoS",
    )
    args = parser.parse_args()

    try:
        from river import forest
    except ImportError as error:
        raise SystemExit(
            "River is required. Install dependencies before training the ARF."
        ) from error

    train_dir = Path(args.train_dir).expanduser().resolve()
    files = discover_files(train_dir, args.files)
    binary = not args.multiclass

    print("=" * 70)
    print("ADAPTIVE RANDOM FOREST")
    print("=" * 70)
    print(f"Training directory: {train_dir}")
    print("Files:")
    for path in files:
        print(f"  - {path.name}")

    print("\nCollecting a bounded sample to validate both classes...")
    fit_rows, fit_labels = collect_fit_sample(
        files, args.fit_sample, args.chunk_size, binary
    )
    class_counts = Counter(fit_labels)
    print(f"Validation sample rows: {len(fit_rows):,}")
    print(f"Validation sample labels: {dict(class_counts)}")

    if len(class_counts) < 2:
        raise ValueError(
            "Training data contains only one class. Add labelled normal traffic "
            "(Label=BENIGN or Normal) and at least one DDoS class before training."
        )

    scaler = StandardFeatureScaler(CANONICAL_FEATURES).fit(fit_rows)
    print(
        "Preprocessing: StandardFeatureScaler fitted on "
        f"{scaler.rows_seen:,} training row(s)"
    )

    model_features = list(CANONICAL_FEATURES)
    print(f"Model features: {len(model_features)} canonical features")

    model = forest.ARFClassifier(n_models=args.trees, seed=args.seed)
    total_rows = 0
    training_counts = Counter()
    start = time.time()

    for file_number, path in enumerate(files, start=1):
        file_rows = 0
        for features, label in iter_rows(path, args.chunk_size, binary):
            scaled = scaler.transform(features)
            model.learn_one(scaled, label)
            total_rows += 1
            file_rows += 1
            training_counts[label] += 1
            if total_rows % 100_000 == 0:
                elapsed = (time.time() - start) / 60.0
                print(
                    f"[{file_number}/{len(files)}] rows={total_rows:,} "
                    f"time={elapsed:.2f} min"
                )
        print(f"Finished {path.name}: {file_rows:,} rows")

    if len(training_counts) < 2:
        raise ValueError(
            "The complete training stream contains only one class; no useful "
            "Normal/DDoS detector was produced."
        )

    output = Path(args.output).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "format_version": 3,
        "artifact_type": "arf_controller",
        "model": model,
        "preprocessor": scaler.to_dict(),
        "feature_names": model_features,
        "feature_schema": "canonical_v1",
        "label_mode": "multiclass" if args.multiclass else "binary",
        "classes_seen": sorted(training_counts),
        "rows_trained": total_rows,
        "training_files": [str(path) for path in files],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    import pickle

    with output.open("wb") as handle:
        pickle.dump(artifact, handle, protocol=pickle.HIGHEST_PROTOCOL)

    summary_path = Path(args.summary).expanduser().resolve()
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(
            {
                "model": str(output),
                "rows_trained": total_rows,
                "class_counts": dict(training_counts),
                "feature_schema": model_features,
                "preprocessing": scaler.to_dict(),
                "trees": args.trees,
                "label_mode": artifact["label_mode"],
                "seconds": round(time.time() - start, 2),
            },
            indent=2,
        )
    )

    print("\nTRAINING COMPLETE")
    print(f"Rows trained     : {total_rows:,}")
    print(f"Class counts     : {dict(training_counts)}")
    print(f"Model checkpoint : {output}")
    print(f"Training summary : {summary_path}")


if __name__ == "__main__":
    main()
