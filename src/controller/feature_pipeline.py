"""Shared feature schema and preprocessing for the live detection pipeline."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import numpy as np

from models.arf_model import CANONICAL_FEATURES, StandardFeatureScaler, canonicalize_row


def preprocess_flow(
    flow_features: Mapping[str, Any],
    scaler: StandardFeatureScaler | None = None,
) -> np.ndarray:
    """Convert a flow dictionary to the canonical numeric vector expected by River."""

    canonical = canonicalize_row(dict(flow_features))
    if scaler is not None:
        canonical = scaler.transform(canonical)
    return np.asarray([float(canonical[name]) for name in CANONICAL_FEATURES], dtype=float)


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


__all__ = ["CANONICAL_FEATURES", "Preprocessor", "preprocess_flow"]
