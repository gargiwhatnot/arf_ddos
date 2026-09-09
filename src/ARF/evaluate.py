"""Evaluate an ARF checkpoint on test CSVs without updating the model."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys
import time

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from shared.arf_runtime import ARFDetector
from shared.pipeline import canonicalize_row, normalize_label


def discover_files(test_dir: Path, requested: list[str] | None) -> list[Path]:
    if requested:
        files = []
        for value in requested:
            path = Path(value).expanduser()
            path = path if path.is_absolute() else test_dir / path
            files.append(path.resolve())
    else:
        files = sorted(test_dir.glob("*.csv"))
    files = [path for path in files if path.exists()]
    if not files:
        raise FileNotFoundError(f"No testing CSV files found in {test_dir}")
    return files


def iter_test_rows(path: Path, chunk_size: int, binary: bool):
    for chunk in pd.read_csv(path, chunksize=chunk_size, low_memory=False):
        chunk.columns = chunk.columns.astype(str).str.strip()
        if "Label" not in chunk.columns:
            raise ValueError(f"'Label' column not found in {path}")
        for record in chunk.to_dict(orient="records"):
            yield canonicalize_row(record), normalize_label(
                record.get("Label"), binary=binary
            )


def calculate_metrics(actual: Counter, predicted: Counter, pairs: Counter, total: int, correct: int):
    labels = sorted(set(actual) | set(predicted))
    per_class = {}
    weighted_precision = weighted_recall = weighted_f1 = 0.0

    for label in labels:
        true_positive = pairs[(label, label)]
        predicted_count = predicted[label]
        actual_count = actual[label]
        precision = true_positive / predicted_count if predicted_count else 0.0
        recall = true_positive / actual_count if actual_count else 0.0
        f1 = (
            2.0 * precision * recall / (precision + recall)
            if precision + recall > 0
            else 0.0
        )
        per_class[label] = {
            "support": actual_count,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }
        weighted_precision += precision * actual_count
        weighted_recall += recall * actual_count
        weighted_f1 += f1 * actual_count

    denominator = max(total, 1)
    return {
        "rows": total,
        "accuracy": correct / denominator,
        "weighted_precision": weighted_precision / denominator,
        "weighted_recall": weighted_recall / denominator,
        "weighted_f1": weighted_f1 / denominator,
        "classes": labels,
        "actual_counts": dict(actual),
        "predicted_counts": dict(predicted),
        "confusion_matrix": {
            actual_label: {
                predicted_label: pairs[(actual_label, predicted_label)]
                for predicted_label in labels
            }
            for actual_label in labels
        },
        "per_class": per_class,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default=str(PROJECT_ROOT / "results" / "arf_controller.pkl"))
    parser.add_argument("--test-dir", default=str(PROJECT_ROOT / "test_data"))
    parser.add_argument("--output", default=str(PROJECT_ROOT / "results" / "evaluation.json"))
    parser.add_argument("--files", nargs="*", help="Testing CSV names or paths")
    parser.add_argument("--chunk-size", type=int, default=10_000)
    parser.add_argument("--max-rows", type=int, default=0, help="0 means all rows")
    parser.add_argument("--multiclass", action="store_true")
    args = parser.parse_args()

    test_dir = Path(args.test_dir).expanduser().resolve()
    files = discover_files(test_dir, args.files)
    detector = ARFDetector(args.model, attack_threshold=0.70)
    binary = not args.multiclass and getattr(detector, "label_mode", "binary") != "multiclass"
    actual = Counter()
    predicted = Counter()
    pairs = Counter()
    total = correct = 0
    start = time.time()

    print("=" * 70)
    print("ARF EVALUATION (PREDICTION ONLY)")
    print("=" * 70)
    print(f"Model: {Path(args.model).expanduser().resolve()}")
    for path in files:
        file_rows = 0
        for features, expected in iter_test_rows(path, args.chunk_size, binary):
            if args.max_rows and total >= args.max_rows:
                break
            result = detector.predict_batch(
                [features], preprocessed=False
            )[0]
            observed = result["prediction"]
            if args.multiclass and result["raw_prediction"] is not None:
                observed = str(result["raw_prediction"])
            actual[expected] += 1
            predicted[observed] += 1
            pairs[(expected, observed)] += 1
            total += 1
            file_rows += 1
            correct += int(expected == observed)
        print(f"{path.name}: tested {file_rows:,} row(s)")
        if args.max_rows and total >= args.max_rows:
            break

    metrics = calculate_metrics(actual, predicted, pairs, total, correct)
    metrics["files"] = [str(path) for path in files]
    metrics["seconds"] = round(time.time() - start, 2)

    output = Path(args.output).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(metrics, indent=2))

    print("\nRESULTS")
    print(f"Rows       : {metrics['rows']:,}")
    print(f"Accuracy   : {metrics['accuracy'] * 100:.2f}%")
    print(f"Precision  : {metrics['weighted_precision'] * 100:.2f}%")
    print(f"Recall     : {metrics['weighted_recall'] * 100:.2f}%")
    print(f"F1-score   : {metrics['weighted_f1'] * 100:.2f}%")
    print(f"Evaluation : {output}")


if __name__ == "__main__":
    main()
