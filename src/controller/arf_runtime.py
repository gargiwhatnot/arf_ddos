"""Runtime wrapper for the pretrained River ARF checkpoint."""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any, Mapping

from models.arf_model import StandardFeatureScaler, canonicalize_row


class ARFDetector:
    """Load the CIC-DDoS checkpoint and classify canonical feature rows."""

    def __init__(self, model_path: str, attack_threshold: float = 0.25):
        self.model_path = str(Path(model_path))
        self.attack_threshold = float(attack_threshold)
        self.scaler: StandardFeatureScaler | None = None
        with open(self.model_path, "rb") as handle:
            self.model = pickle.load(handle)

    def predict_batch(
        self,
        rows: list[Mapping[str, Any]],
        preprocessed: bool = False,
    ) -> list[dict[str, Any]]:
        results = []
        for row in rows:
            features = canonicalize_row(dict(row))
            prediction = str(self.model.predict_one(features))
            probabilities = {
                str(label): float(probability)
                for label, probability in (
                    self.model.predict_proba_one(features)
                    if hasattr(self.model, "predict_proba_one")
                    else {}
                ).items()
            }
            confidence = max(probabilities.values(), default=0.0)
            attack_probability = sum(
                probability
                for label, probability in probabilities.items()
                if label.upper() != "BENIGN"
            )
            is_attack = (
                prediction.upper() != "BENIGN"
                and attack_probability >= self.attack_threshold
            )
            results.append(
                {
                    "prediction": prediction,
                    "raw_prediction": prediction,
                    "probabilities": probabilities,
                    "attack_score": attack_probability,
                    "confidence": confidence,
                    "is_attack": is_attack,
                }
            )
        return results


__all__ = ["ARFDetector"]