from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest

from argus.events.schema import Event
from argus.features.prefix import prefix_matrix


class PrefixIsolationForest:
    def __init__(self, seed: int = 0) -> None:
        self._model = IsolationForest(
            n_estimators=64,
            contamination=0.1,
            random_state=seed,
        )
        self._fitted = False

    def fit_benign(self, benign_trajectories: list[list[Event]]) -> None:
        rows: list[list[float]] = []
        for traj in benign_trajectories:
            rows.extend(prefix_matrix(traj))
        if not rows:
            raise ValueError("no benign prefixes to fit")
        self._model.fit(np.asarray(rows, dtype=float))
        self._fitted = True

    def score_prefixes(self, events: list[Event]) -> list[float]:
        """Higher = more anomalous. IsolationForest.score_samples is higher for inliers."""
        if not self._fitted:
            raise RuntimeError("model not fit")
        x = np.asarray(prefix_matrix(events), dtype=float)
        return (-self._model.score_samples(x)).tolist()
