"""Unsupervised prefix detectors over trajectory features v2 (Phase R1-e).

Fit on benign prefixes only. Hyperparameters are fixed a priori (ADR-0005) and
never tuned on test. ``score`` is "higher = more anomalous" for both models.
"""

from __future__ import annotations

from typing import Literal

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

Kind = Literal["iforest", "ocsvm"]
KINDS: tuple[Kind, ...] = ("iforest", "ocsvm")
STOCHASTIC: dict[Kind, bool] = {"iforest": True, "ocsvm": False}


def _build(kind: Kind, seed: int) -> Pipeline:
    if kind == "iforest":
        # Trees are scale-invariant; the scaler is a no-op kept for a uniform pipeline.
        model = IsolationForest(n_estimators=200, max_samples="auto", contamination="auto",
                                random_state=seed)
    elif kind == "ocsvm":
        # nu = upper bound on the fraction of training points treated as outliers.
        model = OneClassSVM(kernel="rbf", gamma="scale", nu=0.05)
    else:
        raise ValueError(kind)
    return make_pipeline(StandardScaler(), model)


class PrefixDetector:
    def __init__(self, kind: Kind, seed: int = 0) -> None:
        self.kind = kind
        self.seed = seed
        self._pipe = _build(kind, seed)
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
