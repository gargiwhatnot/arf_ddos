"""Leakage-safe numerical preprocessing shared by training and live inference.

The controller and the offline trainer must apply exactly the same transform.
This module intentionally has no pandas or scikit-learn dependency so it can be
loaded by the OS-Ken process in the VM.  Statistics are fitted on training rows
only and serialized into the ARF checkpoint.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .pipeline import CANONICAL_FEATURES, as_float, canonicalize_row


class StandardFeatureScaler:
    """A small, serializable StandardScaler for the project feature schema.

    Each feature is transformed as ``(value - mean) / scale``.  ``scale`` is
    the population standard deviation from the fit rows; constant features
    use a scale of 1.0.  The scaler never learns from live traffic.
    """

    format_version = 1

    def __init__(self, feature_names: Sequence[str] | None = None) -> None:
        self.feature_names = list(feature_names or CANONICAL_FEATURES)
        self.means = {name: 0.0 for name in self.feature_names}
        self.scales = {name: 1.0 for name in self.feature_names}
        self.rows_seen = 0
        self.fitted = False

    def fit(self, rows: Iterable[Mapping[str, Any]]) -> "StandardFeatureScaler":
        """Fit means and standard deviations from an iterable of rows.

        Welford's online algorithm keeps this compatible with chunked dataset
        processing and avoids materializing a complete dataset in memory.
        """

        means = {name: 0.0 for name in self.feature_names}
        m2 = {name: 0.0 for name in self.feature_names}
        count = 0

        for row in rows:
            canonical = canonicalize_row(row)
            count += 1
            for name in self.feature_names:
                value = as_float(canonical.get(name))
                delta = value - means[name]
                means[name] += delta / count
                m2[name] += delta * (value - means[name])

        if count == 0:
            raise ValueError("Cannot fit the feature scaler on zero rows")

        self.means = means
        self.scales = {
            name: self._safe_scale(m2[name] / count)
            for name in self.feature_names
        }
        self.rows_seen = count
        self.fitted = True
        return self

    @staticmethod
    def _safe_scale(variance: float) -> float:
        variance = as_float(variance)
        if variance <= 1e-12:
            return 1.0
        scale = math.sqrt(variance)
        return scale if math.isfinite(scale) and scale > 0.0 else 1.0

    @staticmethod
    def _validated_scale(scale: float) -> float:
        """Validate an already-computed standard deviation from JSON."""

        scale = as_float(scale, 1.0)
        return scale if math.isfinite(scale) and scale > 0.0 else 1.0

    def transform(self, row: Mapping[str, Any]) -> dict[str, float]:
        """Canonicalize and standardize one row using fitted statistics."""

        if not self.fitted:
            raise RuntimeError("Feature scaler must be fitted before transform")
        canonical = canonicalize_row(row)
        return {
            name: (as_float(canonical.get(name)) - self.means[name])
            / self.scales[name]
            for name in self.feature_names
        }

    def transform_many(
        self, rows: Iterable[Mapping[str, Any]]
    ) -> list[dict[str, float]]:
        return [self.transform(row) for row in rows]

    def fit_transform(
        self, rows: Iterable[Mapping[str, Any]]
    ) -> list[dict[str, float]]:
        materialized = list(rows)
        self.fit(materialized)
        return self.transform_many(materialized)

    def to_dict(self) -> dict[str, Any]:
        if not self.fitted:
            raise RuntimeError("Cannot serialize an unfitted feature scaler")
        return {
            "format_version": self.format_version,
            "method": "standard",
            "feature_names": list(self.feature_names),
            "means": {name: self.means[name] for name in self.feature_names},
            "scales": {name: self.scales[name] for name in self.feature_names},
            "rows_seen": self.rows_seen,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "StandardFeatureScaler":
        """Load serialized scaler statistics with strict schema validation."""

        method = str(payload.get("method", "standard")).lower()
        if method not in {"standard", "standardscaler"}:
            raise ValueError(f"Unsupported preprocessing method: {method}")

        names = list(payload.get("feature_names") or CANONICAL_FEATURES)
        if names != list(CANONICAL_FEATURES):
            raise ValueError(
                "Preprocessor feature schema does not match CANONICAL_FEATURES"
            )

        means = payload.get("means")
        scales = payload.get("scales")
        if not isinstance(means, Mapping) or not isinstance(scales, Mapping):
            raise ValueError("Serialized scaler is missing means or scales")

        scaler = cls(names)
        scaler.means = {
            name: as_float(means.get(name)) for name in scaler.feature_names
        }
        scaler.scales = {
            name: cls._validated_scale(as_float(scales.get(name), 1.0))
            for name in scaler.feature_names
        }
        scaler.rows_seen = max(0, int(as_float(payload.get("rows_seen"))))
        scaler.fitted = True
        return scaler

    def save(self, path: str | Path) -> Path:
        output = Path(path).expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(self.to_dict(), indent=2, allow_nan=False) + "\n")
        return output

    @classmethod
    def load(cls, path: str | Path) -> "StandardFeatureScaler":
        source = Path(path).expanduser().resolve()
        with source.open() as handle:
            payload = json.load(handle)
        return cls.from_dict(payload)


__all__ = ["StandardFeatureScaler"]
