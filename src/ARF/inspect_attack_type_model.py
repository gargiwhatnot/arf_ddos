"""Inspect an attack-only River ARF checkpoint without changing it."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from shared.attack_type_features import ATTACK_TYPE_FEATURES
from shared.attack_type_runtime import AttackTypeARF


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True, help="Path to raw River ARF pickle")
    args = parser.parse_args()

    detector = AttackTypeARF(args.model)
    print("ATTACK-TYPE ARF INSPECTION")
    print(f"Model        : {detector.model_path}")
    print(f"Mode         : {detector.mode}")
    print(f"Trees        : {len(getattr(detector.model, 'models', []))}")
    print(f"Feature count: {len(detector.feature_names)}")
    print(f"Labels       : {', '.join(detector.class_labels)}")
    print("Safety       : attack-type candidate only; no Normal class; no mitigation")
    print("\nExpected features:")
    for feature in ATTACK_TYPE_FEATURES:
        print(f"  - {feature}")


if __name__ == "__main__":
    main()
