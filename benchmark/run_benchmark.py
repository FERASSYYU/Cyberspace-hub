"""Score the JSON engine against the synthetic ground-truth labels.

The dataset is 8 files, far too small for meaningful statistics. The output says so.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from pbh.engines.json_engine import analyze_json_document

ROOT = Path(__file__).resolve().parents[1]


def run() -> dict:
    truth = json.loads((ROOT / "lab" / "ground_truth.json").read_text(encoding="utf-8"))["files"]
    tp = fp = fn = 0
    start = time.perf_counter()
    for rel, expected in truth.items():
        path = ROOT / "lab" / "fixtures" / rel
        kind = "jsonc" if path.suffix == ".jsonc" else "json"
        found, err = analyze_json_document(path.read_text(encoding="utf-8"), kind=kind, rel=rel,
                                           program_id="lab", detected_at="benchmark")
        got = {"SYNTAX_ERROR"} if err else {f.category for f in found}
        want = set(expected)
        tp += len(got & want)
        fp += len(got - want)
        fn += len(want - got)
    elapsed = time.perf_counter() - start
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "files": len(truth),
        "true_positive_categories": tp,
        "false_positive_categories": fp,
        "false_negative_categories": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "runtime_seconds": round(elapsed, 4),
        "caveat": "Synthetic labels written by the same author as the engine; not evidence of real-world accuracy.",
        "sample_size_note": "8 files is too small for meaningful statistics.",
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
