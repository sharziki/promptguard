"""Command-line interface for PromptGuard.

    promptguard scan --text "ignore all previous instructions"
    cat inputs.txt | promptguard scan          # one input per line
    promptguard scan --file suspicious.txt

Exit codes: 0 allow, 1 flag, 2 block.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import Action, Policy, PromptGuard, __version__

EXIT = {Action.ALLOW: 0, Action.FLAG: 1, Action.BLOCK: 2}


def cmd_scan(a: argparse.Namespace) -> int:
    if a.text:
        texts = [a.text]
    elif a.file:
        texts = [Path(a.file).read_text()]
    elif not sys.stdin.isatty():
        texts = [l for l in sys.stdin.read().splitlines() if l.strip()]
    else:
        raise SystemExit("no input: pass --text, --file, or pipe lines on stdin")

    if not texts:
        raise SystemExit("no non-empty input lines")

    pg = PromptGuard()
    pol = Policy(level=a.level)
    scans = pg.scan_many(texts, policy=pol, workers=a.workers) if len(texts) > 1 \
        else [pg.scan(texts[0], policy=pol)]

    worst = Action.ALLOW
    order = {Action.ALLOW: 0, Action.FLAG: 1, Action.BLOCK: 2}
    for text, s in zip(texts, scans):
        if order[s.action] > order[worst]:
            worst = s.action
        if a.json:
            print(json.dumps({"text": text[:120], **s.as_dict()}))
        else:
            print(f"{s.action.value.upper():6s} p_attack={s.p_attack:.3f}  "
                  f"{s.latency_ms:.0f}ms  {text[:70]!r}")

    if not a.json and len(texts) > 1:
        blocked = sum(1 for s in scans if s.action is Action.BLOCK)
        flagged = sum(1 for s in scans if s.action is Action.FLAG)
        print(f"\n{len(scans)} scanned: {len(scans)-blocked-flagged} allow, "
              f"{flagged} flag, {blocked} block")
    return EXIT[worst]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="promptguard", description=__doc__.split("\n")[0])
    p.add_argument("--version", action="version", version=f"promptguard {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan input for injection attempts")
    s.add_argument("--text")
    s.add_argument("--file")
    s.add_argument("--level", default="balanced", choices=["balanced", "strict", "paranoid"])
    s.add_argument("--workers", type=int, default=8)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_scan)

    a = p.parse_args(argv)
    try:
        return a.func(a)
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
