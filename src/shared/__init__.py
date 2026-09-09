"""Shared building blocks for offline ARF training and live SDN inference."""

from .pipeline import CANONICAL_FEATURES, canonicalize_row, normalize_label
__all__ = [
    "CANONICAL_FEATURES",
    "canonicalize_row",
    "normalize_label",
]
