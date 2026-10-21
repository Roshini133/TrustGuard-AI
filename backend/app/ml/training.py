"""Reproducible model training and evaluation."""
import io
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier

from .pipeline import feature_types

MODEL_TYPES = ("logistic_regression", "random_forest", "decision_tree")
SEED = 42


def _estimator(model_type: str):
    if model_type == "logistic_regression":
        return LogisticRegression(max_iter=1000, random_state=SEED)
    if model_type == "random_forest":
        return RandomForestClassifier(n_estimators=100, random_state=SEED, n_jobs=1)
    if model_type == "decision_tree":
        return DecisionTreeClassifier(random_state=SEED)
    raise ValueError(f"Unsupported model type '{model_type}'")


def build_pipeline(model_type: str, df: pd.DataFrame, target: str) -> Pipeline:
    num, cat = feature_types(df, target)
    pre = ColumnTransformer([
        ("num", Pipeline([("imp", SimpleImputer(strategy="median")), ("sc", StandardScaler())]), num),
        ("cat", Pipeline([("imp", SimpleImputer(strategy="most_frequent")),
                          ("oh", OneHotEncoder(handle_unknown="ignore"))]), cat),
    ])
    return Pipeline([("pre", pre), ("model", _estimator(model_type))])


def _prep(df: pd.DataFrame, target: str):
    X = df.drop(columns=[target]).copy()
    for c in X.columns:
        if not pd.api.types.is_numeric_dtype(X[c]):
            conv = pd.to_numeric(X[c], errors="coerce")
            if conv.notna().mean() >= 0.9:
                X[c] = conv
    return X, df[target].astype(str)


def split(df: pd.DataFrame, target: str, test_size: float = 0.2):
    y = df[target]
    strat = y if y.value_counts().min() >= 2 else None
    return train_test_split(df, test_size=test_size, random_state=SEED, stratify=strat)


def evaluate(pipe: Pipeline, test: pd.DataFrame, target: str) -> dict:
    X, y = _prep(test, target)
    pred = pipe.predict(X)
    binary = y.nunique() <= 2
    avg = "binary" if binary else "weighted"
    kw = {"zero_division": 0}
    metrics = {"accuracy": float(accuracy_score(y, pred)),
               "precision": float(precision_score(y, pred, average=avg, pos_label=sorted(y.unique())[-1] if binary else 1, **kw)),
               "recall": float(recall_score(y, pred, average=avg, pos_label=sorted(y.unique())[-1] if binary else 1, **kw)),
               "f1": float(f1_score(y, pred, average=avg, pos_label=sorted(y.unique())[-1] if binary else 1, **kw)),
               "roc_auc": None, "n_test": int(len(y))}
    try:
        proba = pipe.predict_proba(X)
        classes = list(pipe.classes_)
        if binary and len(classes) == 2:
            metrics["roc_auc"] = float(roc_auc_score((y == classes[1]).astype(int), proba[:, 1]))
        elif len(classes) > 2 and set(y.unique()) <= set(classes) and y.nunique() == len(classes):
            metrics["roc_auc"] = float(roc_auc_score(y, proba, multi_class="ovr", average="weighted", labels=classes))
    except Exception:
        pass
    return metrics


def train_and_eval(model_type: str, train: pd.DataFrame, test: pd.DataFrame, target: str):
    t0 = time.perf_counter()
    X, y = _prep(train, target)
    pipe = build_pipeline(model_type, train, target)
    pipe.fit(X, y)
    secs = time.perf_counter() - t0
    return pipe, evaluate(pipe, test, target), secs


def serialize(pipe) -> bytes:
    buf = io.BytesIO()
    joblib.dump(pipe, buf, compress=3)
    return buf.getvalue()
