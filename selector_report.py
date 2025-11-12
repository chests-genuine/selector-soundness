#!/usr/bin/env python3
"""Generate selector soundness reports from CSV inputs.

Importing this module has no side effects; all behavior is opt-in via functions/CLI.
"""

from __future__ import annotations
import logging
from __future__ import annotations

__version__: str = "0.1.0"
__author__: str = "Contributors"

# Library-friendly logger (silent unless configured by the host app)
logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())
    logger.propagate = False
__all__: list[str] = []

import argparse
import collections
import csv
import datetime as dt
import pathlib
import statistics
from typing import Iterable, List, Tuple, Dict, Any


def _read_rows(
    path: pathlib.Path,
    *,
    id_col: str,
    truth_col: str,
    pred_col: str,
    selector_col: str | None,
) -> Tuple[List[str], List[str], List[str], List[str] | None]:
    ids, y_true, y_pred, selectors = [], [], [], ([] if selector_col else None)

    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        required = {id_col, truth_col, pred_col} | ({selector_col} if selector_col else set())
        missing = [c for c in required if c and c not in reader.fieldnames]
        if missing:
            raise SystemExit(f"Input CSV is missing columns: {missing} — found {reader.fieldnames}")

        for i, row in enumerate(reader, start=2):  # header is line 1
            rid = (row.get(id_col) or "").strip()
            t = (row.get(truth_col) or "").strip()
            p = (row.get(pred_col) or "").strip()
            if not rid or not t or not p:
                raise SystemExit(f"Line {i}: empty value in one of [{id_col},{truth_col},{pred_col}]")

            ids.append(rid)
            y_true.append(t)
            y_pred.append(p)
            if selector_col:
                selectors.append((row.get(selector_col) or "").strip())

    return ids, y_true, y_pred, selectors


def _confusion(
    y_true: Iterable[str], y_pred: Iterable[str]
) -> Tuple[List[str], Dict[Tuple[str, str], int]]:
    labels = sorted(set(y_true) | set(y_pred))
    counts: Dict[Tuple[str, str], int] = collections.Counter(zip(y_true, y_pred))
    return labels, counts


def _safe_div(n: float, d: float) -> float:
    return n / d if d else 0.0


def _prf_for_label(
    label: str, labels: List[str], cm: Dict[Tuple[str, str], int]
) -> Tuple[float, float, float]:
    tp = cm.get((label, label), 0)
    fp = sum(cm.get((l, label), 0) for l in labels if l != label)
    fn = sum(cm.get((label, l), 0) for l in labels if l != label)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def _macro_micro(
    labels: List[str], cm: Dict[Tuple[str, str], int]
) -> Tuple[float, float, float, float, float, float]:
    # macro
    per_label = [_prf_for_label(l, labels, cm) for l in labels]
    macro_p = statistics.fmean(p for p, _, _ in per_label) if per_label else 0.0
    macro_r = statistics.fmean(r for _, r, _ in per_label) if per_label else 0.0
    macro_f1 = statistics.fmean(f for _, _, f in per_label) if per_label else 0.0

    # micro
    tp = sum(cm.get((l, l), 0) for l in labels)
    total = sum(cm.values())
    micro_acc = _safe_div(tp, total)
    # For single-label multi-class, micro P/R/F1 reduce to accuracy
    micro_p = micro_r = micro_f1 = micro_acc
    return macro_p, macro_r, macro_f1, micro_p, micro_r, micro_f1


def _dq_checks(
    ids: List[str], y_true: List[str], y_pred: List[str], selectors: List[str] | None
) -> List[str]:
    issues = []
    # Duplicate IDs
    dup = [k for k, v in collections.Counter(ids).items() if v > 1]
    if dup:
        issues.append(f"• Duplicate IDs detected: {len(dup)} (examples: {dup[:5]})")

    # Class coverage
    missing_truth = sorted(set(y_pred) - set(y_true))
    if missing_truth:
        issues.append(f"• Predictions include unseen classes vs truth: {missing_truth}")

    # Imbalance (simple heuristic)
    counts = collections.Counter(y_true)
    if counts:
        total = sum(counts.values())
        top_label, top_count = max(counts.items(), key=lambda kv: kv[1])
        if _safe_div(top_count, total) >= 0.9:
            issues.append(
                f"
