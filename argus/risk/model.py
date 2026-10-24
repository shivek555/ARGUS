"""R3-b: transparent, calibrated risk model (ADR-0012).

    risk_points = baseline + Σ_i contribution_i
    contribution_i = POINTS_PER_LOGIT · w_i · (x_i − mean_i) / std_i
    probability    = σ(a · logit + b)          (Platt, fit on out-of-fold logits)

One logistic regression (L2) gives the weights, so contributions sum to the
score exactly; calibration is a monotone map applied afterwards, so it never
changes which call is riskier, only what the number means.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.linear_model import LogisticRegression

POINTS_PER_LOGIT = 10.0


def _sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-z))


@dataclass
class RiskModel:
    names: tuple[str, ...]
    mean: np.ndarray
    std: np.ndarray
    coef: np.ndarray
    intercept: float
    platt_a: float = 1.0
    platt_b: float = 0.0
    C: float = 1.0

    @classmethod
    def fit(cls, X: np.ndarray, y: np.ndarray, names: tuple[str, ...], C: float = 1.0) -> RiskModel:
        X = np.asarray(X, dtype=float)
        mean = X.mean(axis=0)
        std = X.std(axis=0)
        std = np.where(std > 1e-9, std, 1.0)  # constant columns: weight stays ~0, no division by 0
        lr = LogisticRegression(C=C, max_iter=5000)
        lr.fit((X - mean) / std, np.asarray(y, dtype=int))
        return cls(tuple(names), mean, std, lr.coef_[0].copy(), float(lr.intercept_[0]), C=C)

    def _z(self, X: np.ndarray) -> np.ndarray:
        return (np.atleast_2d(np.asarray(X, dtype=float)) - self.mean) / self.std

    def logit(self, X: np.ndarray) -> np.ndarray:
        return self._z(X) @ self.coef + self.intercept

    def risk_points(self, X: np.ndarray) -> np.ndarray:
        return POINTS_PER_LOGIT * self.logit(X)

    def contributions(self, x: list[float] | np.ndarray) -> tuple[float, dict[str, float]]:
        """(baseline points, {signal: points}); baseline + sum(values) == risk_points(x)."""
        z = self._z(x)[0]
        parts = {n: float(POINTS_PER_LOGIT * w * zi) for n, w, zi in zip(self.names, self.coef, z)}
        return float(POINTS_PER_LOGIT * self.intercept), parts

    def calibrate(self, oof_logits: np.ndarray, y: np.ndarray) -> RiskModel:
        cal = LogisticRegression(C=1e6, max_iter=5000)
        cal.fit(np.asarray(oof_logits, dtype=float).reshape(-1, 1), np.asarray(y, dtype=int))
        self.platt_a, self.platt_b = float(cal.coef_[0][0]), float(cal.intercept_[0])
        return self

    def probability_from_points(self, points: np.ndarray | float) -> np.ndarray:
        return _sigmoid(self.platt_a * (np.asarray(points, dtype=float) / POINTS_PER_LOGIT) + self.platt_b)

    def to_dict(self) -> dict[str, Any]:
        return {"names": list(self.names), "mean": self.mean.tolist(), "std": self.std.tolist(),
                "coef": self.coef.tolist(), "intercept": self.intercept, "platt_a": self.platt_a,
                "platt_b": self.platt_b, "C": self.C, "points_per_logit": POINTS_PER_LOGIT}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RiskModel:
        return cls(tuple(d["names"]), np.asarray(d["mean"]), np.asarray(d["std"]), np.asarray(d["coef"]),
                   float(d["intercept"]), float(d["platt_a"]), float(d["platt_b"]), float(d.get("C", 1.0)))

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> RiskModel:
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))
