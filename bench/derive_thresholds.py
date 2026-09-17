"""Derive PromptGuard's thresholds from the measured ROC curves.

Design decision, learned from the data: an earlier version pooled the two
datasets' attack-score distributions and picked thresholds by recall target.
That produced 10-70% false-alarm rates, because the two corpora have very
different score distributions and a pooled recall quantile is dominated by
whichever corpus has more low-scoring attacks.

So thresholds are chosen by **false-alarm budget** instead, which is the
constraint that actually decides whether a filter can be deployed: a security
filter that blocks 10% of real users gets turned off in a week. We pick the
lowest threshold whose false-alarm rate stays inside budget on EVERY dataset,
then report the recall that budget buys.
"""

from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path

import numpy as np

# level -> (block false-alarm budget, flag false-alarm budget)
FA_BUDGETS = {"balanced": (0.01, 0.05), "strict": (0.05, 0.12), "paranoid": (0.20, 0.35)}


def load(pattern: str) -> dict[str, tuple[np.ndarray, np.ndarray]]:
    out = {}
    for f in sorted(glob.glob(pattern)):
        rows = [json.loads(l) for l in Path(f).read_text().splitlines()]
        ok = [r for r in rows if "p_attack" in r]
        if not ok:
            continue
        out[Path(f).stem.replace("injection_", "")] = (
            np.array([r["label"] for r in ok]),
            np.array([r["p_attack"] for r in ok]),
        )
    return out


def threshold_for_budget(data: dict, budget: float) -> float:
    """Lowest threshold whose false-alarm rate is within budget on every dataset.

    Lower threshold = more attacks caught, so we want the smallest one that is
    still safe everywhere. The binding constraint is the worst dataset.
    """
    per_dataset = []
    for y, p in data.values():
        benign = p[y == 0]
        # the (1-budget) quantile of benign scores is the lowest threshold that
        # keeps this dataset's false-alarm rate at or under budget
        per_dataset.append(float(np.quantile(benign, 1 - budget)) + 1e-6)
    return max(per_dataset)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pattern", default=str(Path(__file__).parent / "injection_*.jsonl"))
    a = ap.parse_args()

    data = load(a.pattern)
    if not data:
        raise SystemExit(f"no benchmark files matched {a.pattern}")

    table = {}
    for level, (block_fa, flag_fa) in FA_BUDGETS.items():
        block = threshold_for_budget(data, block_fa)
        flag = min(threshold_for_budget(data, flag_fa), block)
        table[level] = (round(block, 3), round(flag, 3))

        print(f"\n{level}: block>={table[level][0]}  flag>={table[level][1]}  "
              f"(false-alarm budget {block_fa:.0%})")
        for name, (y, p) in data.items():
            pred = p >= table[level][0]
            flagged = p >= table[level][1]
            recall = ((pred) & (y == 1)).sum() / max((y == 1).sum(), 1)
            fa = ((pred) & (y == 0)).sum() / max((y == 0).sum(), 1)
            prec = ((pred) & (y == 1)).sum() / max(pred.sum(), 1)
            caught = ((flagged) & (y == 1)).sum() / max((y == 1).sum(), 1)
            print(f"    {name:32s} block_recall={recall:.3f} false_alarm={fa:.4f} "
                  f"precision={prec:.3f} block_or_flag_recall={caught:.3f}")

    print("\n_LEVELS = {")
    for level in ("balanced", "strict", "paranoid"):
        print(f'    "{level}": {table[level]},')
    print("}")


if __name__ == "__main__":
    main()
