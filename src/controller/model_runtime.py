"""Model lifecycle for the ARF detector and related prediction helpers."""

from __future__ import annotations

import logging
import pickle
from typing import Any

from river.forest import ARFClassifier

from controller.feature_pipeline import preprocess_flow

logger = logging.getLogger("ARFModelRuntime")

arf = None
attack_threshold = 0.7


def configure(model_path: str | None, threshold: float):
    """Load a checkpoint or create a fresh ARF model."""

    global arf, attack_threshold
    attack_threshold = threshold

    try:
        if model_path:
            with open(model_path, "rb") as handle:
                arf = pickle.load(handle)
            logger.info("Loaded pretrained ARF model from %s", model_path)
        else:
            arf = ARFClassifier()
            logger.info("Initialized new ARF model")
    except Exception as exc:  # pragma: no cover - safe fallback for runtime boot
        logger.error("Failed to configure ARF: %s", exc)
        arf = ARFClassifier()


def predict_flow(flow_features: dict[str, Any]):
    """Return the label and a simple confidence-style score."""

    if arf is None:
        return "Unknown", 0.0

    vector = preprocess_flow(flow_features)
    y_pred = arf.predict_one(vector)
    score = 1.0 if y_pred == "Attack" else 0.0
    return y_pred, score


def train_flow(flow_features: dict[str, Any], label: str):
    """Update the model with one labeled flow."""

    if arf is None:
        return
    vector = preprocess_flow(flow_features)
    arf.learn_one(vector, label)


__all__ = ["arf", "attack_threshold", "configure", "predict_flow", "train_flow"]
