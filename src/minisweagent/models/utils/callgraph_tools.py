from __future__ import annotations

import argparse
import json
from collections import deque
from functools import lru_cache
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_DATA_ROOT = REPO_ROOT / "data/linux-6.6"


@lru_cache
def read_json(path: str) -> Any:
    return json.loads(Path(path).read_text())


def callgraph_dir(data_root: Path) -> Path:
    return data_root / "callgraph"


def callees_index(data_root: Path) -> dict[str, list[dict[str, Any]]]:
    return read_json(str(callgraph_dir(data_root) / "callees.index.json"))


def callers_index(data_root: Path) -> dict[str, list[dict[str, Any]]]:
    return read_json(str(callgraph_dir(data_root) / "callers.index.json"))


def limit_records(records: list[dict[str, Any]], max_results: int | None) -> list[dict[str, Any]]:
    if max_results is None or max_results <= 0:
        return records
    return records[:max_results]


def matches_hint(record: dict[str, Any], file_hint: str | None) -> bool:
    if not file_hint:
        return True
    file = record.get("file", "")
    return file_hint in file or file.endswith(file_hint)


def function_files(function: str, data_root: Path) -> list[str]:
    return sorted({record["file"] for record in callees_index(data_root).get(function, []) if record.get("file")})


def get_func_callees(
    function: str,
    *,
    file_hint: str | None = None,
    max_results: int = 20,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    records = [dict(record) for record in callees_index(data_root).get(function, []) if matches_hint(record, file_hint)]
    return {"function": function, "file_hint": file_hint, "records": limit_records(records, max_results)}


def attach_source(
    record: dict[str, Any],
    *,
    source_limit: int,
    data_root: Path,
) -> dict[str, Any]:
    from minisweagent.models.utils.kernel_source_tools import get_function_source

    name = record["function"]
    file_hint = record.get("file") or (record.get("files") or [None])[0]
    sources = get_function_source(name, file_hint=file_hint, max_results=1, data_root=data_root).get("records") or []
    if not sources:
        record["source"] = ""
        record["source_truncated"] = False
        return record
    source = sources[0].get("source") or ""
    truncated = source_limit > 0 and len(source) > source_limit
    record["line"] = sources[0].get("line")
    record["source"] = source[:source_limit] if truncated else source
    record["source_truncated"] = truncated
    if not record.get("file") and sources[0].get("file"):
        record["file"] = sources[0]["file"]
    return record


def reconstruct_path(function: str, parent: dict[str, str], start: str) -> list[str]:
    path = [function]
    seen = {function}
    current = function
    while current in parent:
        current = parent[current]
        if current in seen:
            break
        path.append(current)
        seen.add(current)
        if current == start:
            break
    return path


def get_func_callers(
    function: str,
    *,
    file_hint: str | None = None,
    max_results: int = 50,
    include_source: bool = True,
    source_limit: int = 3500,
    max_source_records: int = 12,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    records = [dict(record) for record in callers_index(data_root).get(function, []) if matches_hint(record, file_hint)]
    records = limit_records(records, max_results)
    for index, record in enumerate(records):
        record["depth"] = 1
        record["path"] = [record["function"], function]
        if include_source and index < max_source_records:
            attach_source(record, source_limit=source_limit, data_root=data_root)
    return {"function": function, "file_hint": file_hint, "records": records}


def forward_neighbors(function: str, data_root: Path) -> list[dict[str, Any]]:
    return [
        {"function": called, "files": function_files(called, data_root)}
        for record in callees_index(data_root).get(function, [])
        for called in record.get("called", [])
    ]


def reverse_neighbors(function: str, data_root: Path) -> list[dict[str, Any]]:
    return [
        {"function": record["function"], "files": [record["file"]]}
        for record in callers_index(data_root).get(function, [])
    ]


def func_bfs(
    start: str,
    direction: str = "reverse",
    *,
    file_hint: str | None = None,
    max_depth: int = 3,
    max_nodes: int = 100,
    include_source: bool = True,
    source_limit: int = 3500,
    max_source_records: int = 12,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    if direction not in {"forward", "reverse"}:
        raise ValueError("direction must be 'forward' or 'reverse'")
    start_files = [record["file"] for record in callees_index(data_root).get(start, []) if matches_hint(record, file_hint)]
    records = [{"depth": 0, "function": start, "files": sorted(set(start_files)), "path": [start]}]
    parent: dict[str, str] = {}
    queue = deque([(start, 0)])
    seen = {start}
    while queue and len(records) < max_nodes:
        function, depth = queue.popleft()
        if depth >= max_depth:
            continue
        neighbors = forward_neighbors(function, data_root) if direction == "forward" else reverse_neighbors(function, data_root)
        for neighbor in neighbors:
            if neighbor["function"] in seen:
                continue
            seen.add(neighbor["function"])
            parent[neighbor["function"]] = function
            records.append({
                "depth": depth + 1,
                "function": neighbor["function"],
                "files": neighbor["files"],
                "via": function,
                "path": reconstruct_path(neighbor["function"], parent, start),
            })
            if len(records) >= max_nodes:
                break
            queue.append((neighbor["function"], depth + 1))
    if include_source:
        for record in records[:max_source_records]:
            attach_source(record, source_limit=source_limit, data_root=data_root)
    return {
        "start": start,
        "direction": direction,
        "file_hint": file_hint,
        "max_depth": max_depth,
        "max_nodes": max_nodes,
        "records": records,
    }


def get_func_paths(
    source: str,
    target: str,
    *,
    source_file_hint: str | None = None,
    target_file_hint: str | None = None,
    max_depth: int = 5,
    max_results: int = 10,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    if source_file_hint and not any(matches_hint(record, source_file_hint) for record in callees_index(data_root).get(source, [])):
        return {
            "source": source,
            "target": target,
            "source_file_hint": source_file_hint,
            "target_file_hint": target_file_hint,
            "records": [],
        }
    paths = []
    queue = deque([[source]])
    while queue and len(paths) < max_results:
        path = queue.popleft()
        if len(path) - 1 >= max_depth:
            continue
        for neighbor in forward_neighbors(path[-1], data_root):
            function = neighbor["function"]
            if function in path:
                continue
            next_path = [*path, function]
            if function == target and (
                not target_file_hint or any(target_file_hint in file or file.endswith(target_file_hint) for file in neighbor["files"])
            ):
                paths.append({"length": len(next_path) - 1, "path": next_path})
                if len(paths) >= max_results:
                    break
            else:
                queue.append(next_path)
    return {
        "source": source,
        "target": target,
        "source_file_hint": source_file_hint,
        "target_file_hint": target_file_hint,
        "max_depth": max_depth,
        "records": paths,
    }


def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="Query preprocessed Linux callgraph indexes.")
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)

    callees_parser = subparsers.add_parser("callees")
    callees_parser.add_argument("function")
    callees_parser.add_argument("--file-hint")
    callees_parser.add_argument("--max-results", type=int, default=20)

    callers_parser = subparsers.add_parser("callers")
    callers_parser.add_argument("function")
    callers_parser.add_argument("--file-hint")
    callers_parser.add_argument("--max-results", type=int, default=50)
    callers_parser.add_argument("--no-source", action="store_true")

    bfs_parser = subparsers.add_parser("bfs")
    bfs_parser.add_argument("start")
    bfs_parser.add_argument("direction", choices=["forward", "reverse"])
    bfs_parser.add_argument("--file-hint")
    bfs_parser.add_argument("--max-depth", type=int, default=3)
    bfs_parser.add_argument("--max-nodes", type=int, default=100)
    bfs_parser.add_argument("--no-source", action="store_true")

    paths_parser = subparsers.add_parser("paths")
    paths_parser.add_argument("source")
    paths_parser.add_argument("target")
    paths_parser.add_argument("--source-file-hint")
    paths_parser.add_argument("--target-file-hint")
    paths_parser.add_argument("--max-depth", type=int, default=5)
    paths_parser.add_argument("--max-results", type=int, default=10)

    args = parser.parse_args()
    if args.command == "callees":
        print_json(get_func_callees(args.function, file_hint=args.file_hint, max_results=args.max_results, data_root=args.data_root))
    elif args.command == "callers":
        print_json(
            get_func_callers(
                args.function,
                file_hint=args.file_hint,
                max_results=args.max_results,
                include_source=not args.no_source,
                data_root=args.data_root,
            )
        )
    elif args.command == "bfs":
        print_json(
            func_bfs(
                args.start,
                args.direction,
                file_hint=args.file_hint,
                max_depth=args.max_depth,
                max_nodes=args.max_nodes,
                include_source=not args.no_source,
                data_root=args.data_root,
            )
        )
    elif args.command == "paths":
        print_json(
            get_func_paths(
                args.source,
                args.target,
                source_file_hint=args.source_file_hint,
                target_file_hint=args.target_file_hint,
                max_depth=args.max_depth,
                max_results=args.max_results,
                data_root=args.data_root,
            )
        )


if __name__ == "__main__":
    main()
