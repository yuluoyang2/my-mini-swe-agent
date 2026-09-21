from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def normalize_called(called: list[str]) -> list[str]:
    return sorted(set(callee for callee in called if callee))


def build_indexes(callgraph: list[dict[str, Any]]) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    callees: dict[str, list[dict[str, Any]]] = {}
    callers: dict[str, list[dict[str, Any]]] = {}
    seen_callees = set()
    seen_callers = set()
    for record in callgraph:
        function = record.get("function", "")
        file = record.get("file", "")
        called = normalize_called(record.get("called", []))
        if not function:
            continue
        callee_key = (function, file, tuple(called))
        if callee_key not in seen_callees:
            callees.setdefault(function, []).append({"file": file, "called": called})
            seen_callees.add(callee_key)
        for callee in called:
            caller_key = (callee, function, file)
            if caller_key in seen_callers:
                continue
            callers.setdefault(callee, []).append({"function": function, "file": file})
            seen_callers.add(caller_key)
    return dict(sorted(callees.items())), dict(sorted(callers.items()))


def main() -> None:
    parser = argparse.ArgumentParser(description="Build forward and reverse indexes for a Linux function callgraph.")
    parser.add_argument("callgraph", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    callgraph = json.loads(args.callgraph.read_text())
    callees, callers = build_indexes(callgraph)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "callees.index.json").write_text(json.dumps(callees, indent=2, sort_keys=True))
    (args.output_dir / "callers.index.json").write_text(json.dumps(callers, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
