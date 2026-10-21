"""Data engineering: loading, validation, quality report, cleaning, transformation tracking."""
import io

import numpy as np
import pandas as pd

ALLOWED_EXT = {".csv", ".xlsx"}
MAX_COLS = 500


class DatasetError(ValueError):
    pass


def load_dataframe(data: bytes, filename: str) -> pd.DataFrame:
    name = filename.lower()
    try:
        if name.endswith(".csv"):
            df = pd.read_csv(io.BytesIO(data))
        elif name.endswith(".xlsx"):
            df = pd.read_excel(io.BytesIO(data), engine="openpyxl")
        else:
            raise DatasetError("Only .csv and .xlsx files are supported.")
    except DatasetError:
        raise
    except Exception as e:
        raise DatasetError(f"Could not parse file: {type(e).__name__}")
    validate_schema(df)
    return df


def validate_schema(df: pd.DataFrame):
    if df.shape[0] < 10:
        raise DatasetError("Dataset needs at least 10 rows.")
    if df.shape[1] < 2:
        raise DatasetError("Dataset needs at least 2 columns.")
    if df.shape[1] > MAX_COLS:
        raise DatasetError(f"Dataset has too many columns (max {MAX_COLS}).")
    cols = [str(c).strip() for c in df.columns]
    if any(c == "" or c.lower().startswith("unnamed") for c in cols):
        raise DatasetError("All columns must have a header name.")
    if len(set(cols)) != len(cols):
        raise DatasetError("Duplicate column names are not allowed.")
    df.columns = cols


def to_csv_bytes(df: pd.DataFrame) -> bytes:
    return df.to_csv(index=False).encode()


def _numeric_like(s: pd.Series) -> bool:
    if pd.api.types.is_numeric_dtype(s):
        return True
    nn = s.dropna()
    if nn.empty:
        return False
    conv = pd.to_numeric(nn, errors="coerce")
    return conv.notna().mean() >= 0.9


def feature_types(df: pd.DataFrame, label_col: str | None):
    num, cat = [], []
    for c in df.columns:
        if c == label_col:
            continue
        (num if _numeric_like(df[c]) else cat).append(c)
    return num, cat


def quality_report(df: pd.DataFrame, label_col: str | None = None) -> dict:
    n = len(df)
    num, cat = feature_types(df, label_col)
    missing = {c: int(df[c].isna().sum()) for c in df.columns if df[c].isna().any()}
    invalid = {}
    for c in num:
        conv = pd.to_numeric(df[c], errors="coerce")
        bad_type = int((conv.isna() & df[c].notna()).sum())
        inf = int(np.isinf(conv.fillna(0)).sum())
        if bad_type or inf:
            invalid[c] = {"non_numeric": bad_type, "infinite": inf}
    dup = int(df.duplicated().sum())
    const = [c for c in df.columns if df[c].nunique(dropna=True) <= 1]
    issues = len(missing) + len(invalid) + (1 if dup else 0) + len(const)
    label_info = None
    if label_col and label_col in df.columns:
        vc = df[label_col].value_counts(dropna=False)
        label_info = {"classes": {str(k): int(v) for k, v in vc.items()},
                      "imbalance_ratio": float(vc.max() / max(vc.min(), 1))}
    return {
        "rows": n, "columns": df.shape[1],
        "dtypes": {c: str(df[c].dtype) for c in df.columns},
        "numeric_features": num, "categorical_features": cat,
        "missing_by_column": missing, "missing_cells": int(df.isna().sum().sum()),
        "missing_pct": round(float(df.isna().sum().sum()) / max(n * df.shape[1], 1) * 100, 3),
        "invalid_values": invalid, "duplicate_rows": dup, "constant_columns": const,
        "label": label_info, "issue_count": issues,
    }


def clean(df: pd.DataFrame, label_col: str | None = None) -> tuple[pd.DataFrame, list[dict]]:
    """Returns cleaned copy and an ordered transformation log. The raw data is never modified."""
    log = []
    out = df.copy()
    num, cat = feature_types(out, label_col)
    for c in num:
        if not pd.api.types.is_numeric_dtype(out[c]):
            before = int(out[c].notna().sum())
            out[c] = pd.to_numeric(out[c], errors="coerce")
            log.append({"step": "coerce_numeric", "column": c, "values_invalidated": before - int(out[c].notna().sum())})
        n_inf = int(np.isinf(out[c]).sum())
        if n_inf:
            out[c] = out[c].replace([np.inf, -np.inf], np.nan)
            log.append({"step": "replace_infinite", "column": c, "count": n_inf})
    d = int(out.duplicated().sum())
    if d:
        out = out.drop_duplicates().reset_index(drop=True)
        log.append({"step": "drop_duplicates", "count": d})
    if label_col and label_col in out.columns:
        nl = int(out[label_col].isna().sum())
        if nl:
            out = out[out[label_col].notna()].reset_index(drop=True)
            log.append({"step": "drop_missing_label", "count": nl})
    for c in num:
        m = int(out[c].isna().sum())
        if m:
            med = float(out[c].median()) if out[c].notna().any() else 0.0
            out[c] = out[c].fillna(med)
            log.append({"step": "impute_median", "column": c, "count": m, "value": med})
    for c in cat:
        m = int(out[c].isna().sum())
        if m:
            mode = out[c].mode(dropna=True)
            val = mode.iloc[0] if len(mode) else "unknown"
            out[c] = out[c].fillna(val)
            log.append({"step": "impute_mode", "column": c, "count": m, "value": str(val)})
    return out.reset_index(drop=True), log
