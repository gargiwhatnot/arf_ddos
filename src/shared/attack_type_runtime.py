"""Safe runtime wrapper for the supplied attack-only River ARF checkpoint."""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Mapping, Sequence

from .attack_type_features import ATTACK_TYPE_FEATURES
from .pipeline import as_float


class AttackTypeARF:
    """Classify a flow into an attack family without enabling mitigation.

    The external checkpoint contains attack labels only; it has no benign class.
    Therefore every returned label is a candidate attack family, not proof that
    a flow is malicious.  The binary Normal/DDoS detector remains responsible
    for any detection or mitigation decision.
    """

    mode = "attack-type-only"

    def __init__(self, model_path: str | Path) -> None:
        self.model_path = Path(model_path).expanduser().resolve()
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Attack-type ARF checkpoint not found: {self.model_path}"
            )
        with self.model_path.open("rb") as handle:
            self.model = pickle.load(handle)
        if not hasattr(self.model, "predict_one"):
            raise TypeError("Checkpoint does not contain a River-compatible model")

        self.feature_names = list(ATTACK_TYPE_FEATURES)
        self.class_labels = self._class_labels()

    def _class_labels(self) -> list[str]:
        labels: set[str] = set()
        for tree in getattr(self.model, "models", []):
            classes = getattr(tree, "classes", ())
            if isinstance(classes, Mapping):
                labels.update(str(label) for label in classes)
            else:
                labels.update(str(label) for label in classes or ())
        return sorted(labels)

    def predict_batch(
        self, rows: Sequence[Mapping[str, object]]
    ) -> list[dict[str, object]]:
        predictions = []
        for row in rows:
            missing = [name for name in self.feature_names if name not in row]
            prepared = {
                name: as_float(row.get(name)) for name in self.feature_names
            }
            predicted = self.model.predict_one(prepared)
            try:
                probabilities = dict(self.model.predict_proba_one(prepared) or {})
            except Exception:
                probabilities = {}
            confidence = max(
                (as_float(value) for value in probabilities.values()), default=0.0
            )
            predictions.append(
                {
                    "prediction": str(predicted) if predicted is not None else "UNKNOWN",
                    "raw_prediction": predicted,
                    "probabilities": probabilities,
                    "confidence": confidence,
                    "feature_coverage": len(self.feature_names) - len(missing),
                    "missing_features": missing,
                    "mode": self.mode,
                    "safe_for_mitigation": False,
                }
            )
        return predictions


__all__ = ["AttackTypeARF"]
