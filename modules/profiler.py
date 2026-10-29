from __future__ import annotations

import logging
from typing import Any, Dict, List
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


def format_bytes(num_bytes: int | float) -> str:
    """Format byte size into human-readable string."""
    if num_bytes < 0:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def infer_general_type(series: pd.Series) -> str:
    """Classify series into a standardized general type category."""
    dtype_str = str(series.dtype).lower()
    if pd.api.types.is_bool_dtype(series):
        return "Boolean"
    if pd.api.types.is_numeric_dtype(series):
        return "Numeric"
    if pd.api.types.is_datetime64_any_dtype(series):
        return "Datetime"
    if isinstance(series.dtype, pd.CategoricalDtype):
        return "Categorical"
    return "Text/Categorical"


def get_dataset_overview(df: pd.DataFrame) -> Dict[str, Any]:
    """Calculate comprehensive dataset overview statistics.

    Safely handles empty DataFrames and division by zero.
    """
    if not isinstance(df, pd.DataFrame):
        raise TypeError("Input must be a pandas DataFrame.")

    row_count = int(df.shape[0])
    col_count = int(df.shape[1])
    total_cells = int(row_count * col_count)

    if row_count == 0 or col_count == 0:
        return {
            "row_count": row_count,
            "col_count": col_count,
            "total_cells": 0,
            "missing_cells": 0,
            "missing_cells_pct": 0.0,
            "completeness_pct": 100.0 if total_cells == 0 else 0.0,
            "duplicate_row_count": 0,
            "duplicate_row_pct": 0.0,
            "memory_usage_bytes": 0,
            "memory_usage_str": "0 B",
            "column_names": list(df.columns),
            "dtypes": {str(c): str(t) for c, t in df.dtypes.items()},
        }

    missing_cells = int(df.isna().sum().sum())
    missing_cells_pct = round((missing_cells / total_cells) * 100, 2) if total_cells > 0 else 0.0
    completeness_pct = round(100.0 - missing_cells_pct, 2)

    try:
        duplicate_row_count = int(df.duplicated().sum())
    except Exception as e:
        logger.warning("Failed to calculate duplicate rows: %s", e)
        duplicate_row_count = 0

    duplicate_row_pct = round((duplicate_row_count / row_count) * 100, 2) if row_count > 0 else 0.0

    try:
        mem_usage = int(df.memory_usage(deep=True).sum())
    except Exception:
        mem_usage = int(df.memory_usage().sum())

    return {
        "row_count": row_count,
        "col_count": col_count,
        "total_cells": total_cells,
        "missing_cells": missing_cells,
        "missing_cells_pct": missing_cells_pct,
        "completeness_pct": completeness_pct,
        "duplicate_row_count": duplicate_row_count,
        "duplicate_row_pct": duplicate_row_pct,
        "memory_usage_bytes": mem_usage,
        "memory_usage_str": format_bytes(mem_usage),
        "column_names": [str(c) for c in df.columns],
        "dtypes": {str(c): str(t) for c, t in df.dtypes.items()},
    }


def get_column_profiles(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Generate detailed column-by-column profile records."""
    if df.empty or df.shape[1] == 0:
        return []

    profiles: List[Dict[str, Any]] = []
    row_count = df.shape[0]

    for col in df.columns:
        series = df[col]
        null_count = int(series.isna().sum())
        non_null_count = row_count - null_count
        null_pct = round((null_count / row_count) * 100, 2) if row_count > 0 else 0.0

        try:
            unique_count = int(series.nunique(dropna=True))
        except Exception:
            unique_count = 0

        unique_pct = round((unique_count / non_null_count) * 100, 2) if non_null_count > 0 else 0.0

        try:
            mem_bytes = int(series.memory_usage(deep=True))
        except Exception:
            mem_bytes = 0

        # Safe sample values extraction (converted to string, up to 3 non-null distinct items)
        samples = []
        try:
            valid_samples = series.dropna().unique()[:3]
            for val in valid_samples:
                str_val = str(val)
                if len(str_val) > 40:
                    str_val = str_val[:37] + "..."
                samples.append(str_val)
        except Exception:
            samples = []

        profiles.append({
            "column": str(col),
            "dtype": str(series.dtype),
            "general_type": infer_general_type(series),
            "non_null_count": non_null_count,
            "null_count": null_count,
            "null_pct": null_pct,
            "unique_count": unique_count,
            "unique_pct": unique_pct,
            "sample_values": ", ".join(samples) if samples else "N/A",
            "memory_usage_bytes": mem_bytes,
            "memory_usage_str": format_bytes(mem_bytes),
        })

    return profiles


def get_dtype_distribution(df: pd.DataFrame) -> Dict[str, int]:
    """Return counts of columns by generalized data type category."""
    if df.empty or df.shape[1] == 0:
        return {}

    dist: Dict[str, int] = {}
    for col in df.columns:
        cat = infer_general_type(df[col])
        dist[cat] = dist.get(cat, 0) + 1
    return dist


def get_numerical_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Return descriptive statistics for all numerical columns."""
    if df.empty or df.shape[1] == 0:
        return pd.DataFrame()

    num_df = df.select_dtypes(include=[np.number])
    if num_df.empty or num_df.shape[1] == 0:
        return pd.DataFrame()

    desc = num_df.describe().T
    desc = desc.reset_index().rename(columns={"index": "column"})
    for num_col in ["mean", "std", "min", "25%", "50%", "75%", "max"]:
        if num_col in desc.columns:
            desc[num_col] = desc[num_col].round(2)
    return desc
