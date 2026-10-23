"""Unsupervised prefix detectors over trajectory features v2 (Phase R1-e).

Fit on benign prefixes only. Hyperparameters are fixed a priori (ADR-0005) and
never tuned on test. ``score`` is "higher = more anomalous" for both models.
"""

from __future__ import annotations

from typing import Literal

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.preprocessing import QuantileTransformer, StandardScaler
from sklearn.svm import OneClassSVM

Kind = Literal["iforest", "ocsvm"]
Scaler = Literal["standard", "standard_floor", "quantile"]
STD_FLOOR = 0.1  # R1b (ADR-0006 grid)


class FlooredStandardScaler(BaseEstimator, TransformerMixin):  # type: ignore[misc]
    """Standardize with std floored at ``floor``.

    sklearn's StandardScaler gives zero-variance features scale 1, but a feature
    that is *almost* constant in benign training (e.g. std 0.05) turns a single
    rare-but-benign value into z = 20 and dominates the RBF distance. The floor
    caps how extreme a rarely seen value can look (R1 failure cause C3).
    """

    def __init__(self, floor: float = STD_FLOOR) -> None:
        self.floor = floor

    def fit(self, x, y=None):  # type: ignore[no-untyped-def]
        x = np.asarray(x, dtype=float)
        self.mean_ = x.mean(axis=0)
        self.scale_ = np.maximum(x.std(axis=0), self.floor)
        return self

    def transform(self, x):  # type: ignore[no-untyped-def]
        return (np.asarray(x, dtype=float) - self.mean_) / self.scale_


KINDS: tuple[Kind, ...] = ("iforest", "ocsvm")
STOCHASTIC: dict[Kind, bool] = {"iforest": True, "ocsvm": False}


def _scaler(name: Scaler):  # type: ignore[no-untyped-def]
    if name == "standard":
        return StandardScaler()
    if name == "standard_floor":
        return FlooredStandardScaler()
    if name == "quantile":
        return QuantileTransformer(output_distribution="uniform", n_quantiles=1000, subsample=10**9)
    raise ValueError(name)


def _build(kind: Kind, seed: int, nu: float = 0.05, scaler: Scaler = "standard") -> Pipeline:
    if kind == "iforest":
        # Affine scaling does not change trees; a quantile transform does (it
        # moves where random splits fall), which is why it is in the R1b grid.
        model = IsolationForest(n_estimators=200, max_samples="auto", contamination="auto",
                                random_state=seed)
    elif kind == "ocsvm":
        # nu = upper bound on the fraction of training points treated as outliers.
        model = OneClassSVM(kernel="rbf", gamma="scale", nu=nu)
    else:
        raise ValueError(kind)
    return make_pipeline(_scaler(scaler), model)


class PrefixDetector:
    def __init__(self, kind: Kind, seed: int = 0, nu: float = 0.05, scaler: Scaler = "standard") -> None:
        """Defaults reproduce the R1 detectors exactly (plain StandardScaler, nu 0.05)."""
        self.kind = kind
        self.seed = seed
        self._pipe = _build(kind, seed, nu, scaler)
        self._fitted = False

    def fit(self, benign_rows: list[list[float]]) -> PrefixDetector:
        if not benign_rows:
            raise ValueError("no benign prefixes to fit")
        self._pipe.fit(np.asarray(benign_rows, dtype=float))
        self._fitted = True
        return self

    def score(self, rows: list[list[float]]) -> list[float]:
        if not self._fitted:
            raise RuntimeError("detector not fit")
        if not rows:
            return []
        x = np.asarray(rows, dtype=float)
        if self.kind == "iforest":
            return (-self._pipe.score_samples(x)).tolist()
        return (-self._pipe.decision_function(x)).tolist()
