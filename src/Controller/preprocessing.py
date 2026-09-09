"""Controller-side preprocessing using the shared offline/live transform."""

from pathlib import Path
import sys

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from shared.pipeline import CANONICAL_FEATURES, canonicalize_row
from shared.preprocessing import StandardFeatureScaler


class Preprocessor:
    def __init__(self, scaler: StandardFeatureScaler | None = None):
        self.scaler = scaler

    def set_scaler(self, scaler: StandardFeatureScaler | None) -> None:
        self.scaler = scaler

    def normalize(self, features):
        canonical = canonicalize_row(features)
        return self.scaler.transform(canonical) if self.scaler else canonical

    def normalize_many(self, rows):
        return [self.normalize(row) for row in rows]


__all__ = ["CANONICAL_FEATURES", "Preprocessor"]
