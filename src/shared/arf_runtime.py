"""Runtime loader and inference wrapper for the trained River ARF."""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Mapping, Sequence

from .pipeline import CANONICAL_FEATURES, as_float, is_attack_label, normalize_label
from .preprocessing import StandardFeatureScaler


class ARFDetector:
    def __init__(self, model_path: str | Path, attack_threshold: float = 0.70) -> None:
        self.model_path = Path(model_path).expanduser().resolve()
        if not self.model_path.exists():
            raise FileNotFoundError(f"ARF model checkpoint not found: {self.model_path}")

        with self.model_path.open("rb") as handle:
            artifact = pickle.load(handle)

        if isinstance(artifact, dict) and "model" in artifact:
            self.model = artifact["model"]
            self.model_features = list(artifact.get("feature_names") or [])
            if self.model_features != list(CANONICAL_FEATURES):
                missing = [
                    name for name in CANONICAL_FEATURES
                    if name not in self.model_features
                ]
                extra = [
                    name for name in self.model_features
                    if name not in CANONICAL_FEATURES
                ]
                raise ValueError(
                    "Incompatible ARF checkpoint schema. Retrain the controller "
                    "model with the current canonical features. "
                    f"Missing={missing}; extra={extra}"
                )
            self.label_mode = artifact.get("label_mode", "binary")
        else:
            raise ValueError(
                "Unsupported raw River ARF checkpoint. This file has no saved "
                "feature schema or scaler; retrain it with src/ARF/train_arf_v2.py."
            )

        preprocessor_payload = None
        if isinstance(artifact, dict):
            preprocessor_payload = artifact.get("preprocessor") or artifact.get(
                "scaler"
            )
        self.scaler = (
            StandardFeatureScaler.from_dict(preprocessor_payload)
            if isinstance(preprocessor_payload, Mapping)
            else None
        )
        if self.scaler is None:
            raise ValueError(
                "ARF checkpoint is missing its training scaler. Retrain the "
                "controller model with src/ARF/train_arf_v2.py."
            )

        self.attack_threshold = min(max(float(attack_threshold), 0.0), 1.0)

    def predict_batch(
        self,
        rows: Sequence[Mapping[str, object]],
        preprocessed: bool = False,
    ) -> list[dict[str, object]]:
        # The live collector preprocesses before calling this method.  Offline
        # evaluation passes canonical rows and therefore uses the checkpoint's
        # saved scaler here.  This flag prevents accidental double scaling.
        model_rows = list(rows)
        if not preprocessed:
            model_rows = [
                self.scaler.transform(row)
                if self.scaler is not None
                else dict(row)
                for row in model_rows
            ]

        predictions = []
        for row in model_rows:
            model_features = {
                feature: as_float(row.get(feature, 0.0))
                for feature in self.model_features
            }
            predicted = self.model.predict_one(model_features)
            probabilities = {}
            try:
                probabilities = dict(self.model.predict_proba_one(model_features) or {})
            except Exception:
                probabilities = {}

            attack_score = sum(
                as_float(probability)
                for label, probability in probabilities.items()
                if is_attack_label(label)
            )
            predicted_attack = predicted is not None and is_attack_label(predicted)
            confidence = max(
                (as_float(probability) for probability in probabilities.values()),
                default=1.0 if predicted is not None else 0.0,
            )
            is_attack = (
                attack_score >= self.attack_threshold
                or (predicted_attack and confidence >= self.attack_threshold)
            )

            predictions.append(
                {
                    "prediction": normalize_label(predicted, binary=True)
                    if predicted is not None
                    else "UNKNOWN",
                    "raw_prediction": predicted,
                    "probabilities": probabilities,
                    "attack_score": attack_score,
                    "confidence": confidence,
                    "is_attack": is_attack,
                }
            )
        return predictions
