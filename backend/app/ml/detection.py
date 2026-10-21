"""Poisoning / anomaly detection and Data Trust Score.

An anomaly is evidence, not proof of malicious intent. Ground-truth poison labels are never an input here.
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.neighbors import LocalOutlierFactor, NearestNeighbors
from sklearn.preprocessing import StandardScaler

from .pipeline import feature_types

DEFAULT_CONFIG = {
    "weights": {"statistical_normality": 0.25, "label_consistency": 0.25, "provenance": 0.20,
                "data_quality": 0.15, "model_impact": 0.15},
    "high_trust_min": 80.0,
    "review_min": 50.0,
    "contamination": 0.05,
    "anomaly_flag": 0.6,
    "missing_evidence_value": 0.5,   # neutral prior for unavailable components (never a perfect 1.0)
    "min_evidence_weight": 0.5,      # below this available weight -> insufficient_evidence
    "invalid_missing_frac": 0.5,
    "random_state": 42,
}


def merged_config(cfg: dict | None) -> dict:
    c = {**DEFAULT_CONFIG, **(cfg or {})}
    c["weights"] = {**DEFAULT_CONFIG["weights"], **((cfg or {}).get("weights") or {})}
    tot = sum(c["weights"].values())
    if tot <= 0:
        raise ValueError("weights must sum to a positive value")
    c["weights"] = {k: v / tot for k, v in c["weights"].items()}
    if not (0 <= c["review_min"] <= c["high_trust_min"] <= 100):
        raise ValueError("thresholds must satisfy 0 <= review_min <= high_trust_min <= 100")
    return c


def _design_matrix(df: pd.DataFrame, label_col: str | None):
    num, cat = feature_types(df, label_col)
    parts = []
    if num:
        parts.append(df[num].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan))
    for c in cat:
        if df[c].nunique() <= 20:
            parts.append(pd.get_dummies(df[c].astype(str), prefix=c, dtype=float))
    if not parts:
        raise ValueError("No usable feature columns for detection.")
    X = pd.concat(parts, axis=1)
    X = X.fillna(X.median(numeric_only=True)).fillna(0.0)
    return StandardScaler().fit_transform(X.values), num


def _unit(a: np.ndarray) -> np.ndarray:
    lo, hi = np.nanmin(a), np.nanmax(a)
    return np.zeros_like(a) if hi - lo < 1e-12 else (a - lo) / (hi - lo)


def _label_evidence(X, y, rs):
    classes, counts = np.unique(y, return_counts=True)
    if len(classes) < 2 or counts.min() < 2:
        return None, None
    n = len(y)
    k = min(10, n - 1)
    nn = NearestNeighbors(n_neighbors=k + 1).fit(X)
    idx = nn.kneighbors(X, return_distance=False)[:, 1:]
    knn_agree = (y[idx] == y[:, None]).mean(axis=1)
    folds = int(min(5, counts.min()))
    rf_p = np.full(n, 0.5)
    if folds >= 2:
        proba = cross_val_predict(RandomForestClassifier(n_estimators=100, random_state=rs, n_jobs=1), X, y,
                                  cv=StratifiedKFold(folds, shuffle=True, random_state=rs), method="predict_proba")
        cls_idx = {c: i for i, c in enumerate(classes)}
        rf_p = proba[np.arange(n), [cls_idx[v] for v in y]]
    consistency = 0.5 * knn_agree + 0.5 * rf_p

    # model-impact proxy: per-sample logistic-loss gradient norm under out-of-fold logistic regression
    impact = None
    try:
        folds_lr = int(min(5, counts.min()))
        if folds_lr >= 2:
            p = cross_val_predict(LogisticRegression(max_iter=500, random_state=rs), X, y,
                                  cv=StratifiedKFold(folds_lr, shuffle=True, random_state=rs), method="predict_proba")
            cls_idx = {c: i for i, c in enumerate(classes)}
            p_true = p[np.arange(n), [cls_idx[v] for v in y]]
            grad = (1 - p_true) * np.linalg.norm(X, axis=1)
            ranks = pd.Series(grad).rank(pct=True).values
            # Only the top ~10% most loss-influential records are penalised; a plain rank would force the
            # average safety to 0.5 on perfectly clean data and flood the review queue.
            impact = 1.0 - np.clip((ranks - 0.9) / 0.1, 0, 1)
    except Exception:
        impact = None
    return consistency, impact


def run_detection(df: pd.DataFrame, label_col: str | None, provenance: float | None = None,
                  integrity_failed: bool = False, config: dict | None = None) -> tuple[pd.DataFrame, dict]:
    """Returns per-row result frame and dataset-level summary."""
    cfg = merged_config(config)
    rs = cfg["random_state"]
    n = len(df)
    if n < 10:
        raise ValueError("Need at least 10 rows for detection.")
    X, num_cols = _design_matrix(df, label_col)

    # --- Isolation Forest
    iso = IsolationForest(n_estimators=200, contamination=cfg["contamination"], random_state=rs).fit(X)
    iso_anom = _unit(-iso.score_samples(X))
    # --- Local Outlier Factor
    lof = LocalOutlierFactor(n_neighbors=max(2, min(20, n - 1)), contamination=cfg["contamination"])
    lof.fit_predict(X)
    lof_anom = _unit(-lof.negative_outlier_factor_)
    # --- feature distribution analysis (robust z-scores)
    if num_cols:
        M = df[num_cols].apply(pd.to_numeric, errors="coerce")
        med = M.median()
        mad = (M - med).abs().median().replace(0, np.nan)
        z = ((M - med).abs() / (1.4826 * mad)).fillna(0.0)
        zmax = z.max(axis=1).values
        dist_normality = 1.0 - np.clip((zmax - 3.0) / 5.0, 0, 1)
        zcols = z.values
    else:
        zmax, dist_normality, zcols = np.zeros(n), np.ones(n), None
    stat_norm = 0.4 * (1 - iso_anom) + 0.3 * (1 - lof_anom) + 0.3 * dist_normality

    # --- label evidence
    label_cons, impact = None, None
    if label_col and label_col in df.columns:
        y = df[label_col].astype(str).values
        label_cons, impact = _label_evidence(X, y, rs)

    # --- data quality (from the version's own contents)
    missing_frac = df.isna().mean(axis=1).values
    dup = df.duplicated(keep="first").values.astype(float)
    quality = np.clip(1.0 - missing_frac - 0.5 * dup, 0, 1)
    invalid = missing_frac > cfg["invalid_missing_frac"]
    if num_cols:
        raw_num = df[num_cols].apply(pd.to_numeric, errors="coerce")
        invalid = invalid | np.isinf(raw_num.fillna(0)).any(axis=1).values

    w = cfg["weights"]
    neutral = cfg["missing_evidence_value"]
    comps = {
        "statistical_normality": stat_norm,
        "label_consistency": label_cons,
        "provenance": None if provenance is None else np.full(n, float(provenance)),
        "data_quality": quality,
        "model_impact": impact,
    }
    avail_w = sum(w[k] for k, v in comps.items() if v is not None)
    total = np.zeros(n)
    for k, v in comps.items():
        total += w[k] * (v if v is not None else neutral)
    trust = 100.0 * total

    rows = []
    for i in range(n):
        reasons = []
        if iso_anom[i] >= cfg["anomaly_flag"]:
            reasons.append(f"Isolation Forest flags this record as unusual (score {iso_anom[i]:.2f}).")
        if lof_anom[i] >= cfg["anomaly_flag"]:
            reasons.append(f"Local Outlier Factor shows it is isolated from its neighbours (score {lof_anom[i]:.2f}).")
        if zmax[i] > 3:
            top = ""
            if zcols is not None:
                top = f" in '{num_cols[int(np.argmax(zcols[i]))]}'"
            reasons.append(f"Extreme feature value{top} (robust z={zmax[i]:.1f}).")
        if label_cons is not None and label_cons[i] < 0.5:
            reasons.append(f"Label disagrees with similar records (consistency {label_cons[i]:.2f}).")
        if impact is not None and impact[i] < 0.2:
            reasons.append("High estimated influence on model loss.")
        if missing_frac[i] > 0:
            reasons.append(f"{missing_frac[i]*100:.0f}% of fields missing.")
        if dup[i]:
            reasons.append("Duplicate of an earlier record.")
        missing_comp = [k for k, v in comps.items() if v is None]
        if missing_comp:
            reasons.append("Evidence unavailable: " + ", ".join(missing_comp) + " (neutral value used).")

        critical = bool(integrity_failed)
        if invalid[i]:
            cat, critical = "invalid", True
        elif integrity_failed:
            cat = "highly_suspicious"
        elif avail_w < cfg["min_evidence_weight"]:
            cat = "insufficient_evidence"
        elif trust[i] >= cfg["high_trust_min"]:
            cat = "high_trust"
        elif trust[i] >= cfg["review_min"]:
            cat = "requires_review"
        else:
            cat = "highly_suspicious"
        if integrity_failed:
            reasons.insert(0, "CRITICAL: dataset SHA-256 integrity verification failed.")
        rows.append({
            "row_index": i,
            "iforest_score": float(iso_anom[i]), "lof_score": float(lof_anom[i]),
            "distribution_score": float(dist_normality[i]),
            "label_consistency": None if label_cons is None else float(label_cons[i]),
            "data_quality": float(quality[i]), "provenance": None if provenance is None else float(provenance),
            "model_impact": None if impact is None else float(impact[i]),
            "statistical_normality": float(stat_norm[i]),
            "trust_score": float(trust[i]) if cat != "invalid" else None,
            "category": cat, "critical_failure": critical, "explanation": reasons,
        })
    res = pd.DataFrame(rows)
    valid = res[res.category != "invalid"]["trust_score"]
    summary = {
        "n_records": n,
        "dataset_trust_score": float(valid.mean()) if len(valid) else None,
        "category_counts": res.category.value_counts().to_dict(),
        "method_flags": {
            "isolation_forest": int((res.iforest_score >= cfg["anomaly_flag"]).sum()),
            "local_outlier_factor": int((res.lof_score >= cfg["anomaly_flag"]).sum()),
            "feature_distribution": int((res.distribution_score < 0.5).sum()),
            "label_consistency": int((res.label_consistency.dropna() < 0.5).sum()) if label_cons is not None else None,
        },
        "evidence_available": [k for k, v in comps.items() if v is not None],
        "evidence_missing": [k for k, v in comps.items() if v is None],
        "config": {k: cfg[k] for k in ("weights", "high_trust_min", "review_min", "contamination", "anomaly_flag")},
        "disclaimer": "Anomalies are statistical evidence, not proof of malicious behaviour. Review before acting.",
    }
    return res, summary
