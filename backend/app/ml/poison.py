"""Controlled poisoning simulations on COPIES of data. Returns the poisoned frame and ground-truth mask.
The mask is stored in restricted metadata and is never passed to detection."""
import numpy as np
import pandas as pd

ATTACKS = ("label_flip", "feature_manipulation", "injection", "backdoor")


def poison(df: pd.DataFrame, label_col: str, attack: str, rate: float, seed: int = 42,
           numeric_cols: list[str] | None = None) -> tuple[pd.DataFrame, np.ndarray]:
    if attack not in ATTACKS:
        raise ValueError(f"Unknown attack '{attack}'")
    if not (0.0 < rate <= 0.5):
        raise ValueError("poison_rate must be in (0, 0.5]")
    rng = np.random.default_rng(seed)
    out = df.copy().reset_index(drop=True)
    n = len(out)
    k = max(1, int(round(n * rate)))
    classes = out[label_col].unique()
    if len(classes) < 2:
        raise ValueError("Need at least 2 classes")
    num = numeric_cols or [c for c in out.columns if c != label_col and pd.api.types.is_numeric_dtype(out[c])]
    if not num and attack != "label_flip":
        raise ValueError("Attack needs numeric feature columns")
    mask = np.zeros(n, dtype=bool)

    if attack == "label_flip":
        idx = rng.choice(n, k, replace=False)
        for i in idx:
            others = [c for c in classes if c != out.at[i, label_col]]
            out.at[i, label_col] = rng.choice(others)
        mask[idx] = True

    elif attack == "feature_manipulation":
        idx = rng.choice(n, k, replace=False)
        cols = rng.choice(num, size=max(1, len(num) // 2), replace=False)
        for c in cols:
            sd = float(out[c].std()) or 1.0
            out.loc[idx, c] = out.loc[idx, c] + rng.choice([-1, 1], size=k) * rng.uniform(4, 8, size=k) * sd
        mask[idx] = True

    elif attack == "injection":
        base = out.sample(k, replace=True, random_state=seed).reset_index(drop=True)
        for c in num:
            sd = float(out[c].std()) or 1.0
            base[c] = rng.normal(float(out[c].mean()), 2.5 * sd, size=k)
        base[label_col] = rng.choice(classes, size=k)
        out = pd.concat([out, base], ignore_index=True)
        mask = np.concatenate([mask, np.ones(k, dtype=bool)])

    elif attack == "backdoor":
        idx = rng.choice(n, k, replace=False)
        trig = num[0]
        trigger_val = float(out[trig].max() + 2 * (out[trig].std() or 1.0))
        target = classes[0]
        out.loc[idx, trig] = trigger_val
        out.loc[idx, label_col] = target
        mask[idx] = True
    return out, mask
