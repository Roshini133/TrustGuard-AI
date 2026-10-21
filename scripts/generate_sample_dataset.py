#!/usr/bin/env python3
"""Generate a sample classification CSV (with seeded missing values and duplicates) for trying TrustGuard AI.

Usage: python scripts/generate_sample_dataset.py [rows] [output.csv]
"""
import sys

import numpy as np
import pandas as pd
from sklearn.datasets import make_classification

rows = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
out = sys.argv[2] if len(sys.argv) > 2 else "sample_dataset.csv"
X, y = make_classification(n_samples=rows, n_features=8, n_informative=5, n_redundant=1, class_sep=1.5, random_state=7)
df = pd.DataFrame(X, columns=[f"feature_{i + 1}" for i in range(8)]).round(4)
df["label"] = y
rng = np.random.default_rng(1)
for c in df.columns[:2]:
    df.loc[rng.choice(len(df), max(1, rows // 100), replace=False), c] = np.nan
df = pd.concat([df, df.iloc[:3]], ignore_index=True)
df.to_csv(out, index=False)
print(f"wrote {out}: {len(df)} rows, label column = 'label'")
