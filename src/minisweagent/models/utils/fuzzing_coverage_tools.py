from __future__ import annotations

import argparse
import json
from functools import lru_cache
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_DATA_ROOT = REPO_ROOT / "data/linux-6.6"


@lru_cache
def read_json(path: str) -> Any:
    return json.loads(Path(path).read_text())


def coverage_dir(data_root: Path) -> Path:
    return data_root / "progfunc_index"


def func_index(data_root: Path) -> dict[str, dict[str, Any]]:
    return read_json(str(coverage_dir(data_root) / "func_index.json"))


def syscall_index(data_root: Path) -> dict[str, dict[str, Any]]:
    return read_json(str(coverage_dir(data_root) / "syscall_index.json"))


def limit_list(items: list[Any], max_results: int | None) -> list[Any]:
    if max_results is None or max_results <= 0:
        return items
    return items[:max_results]


def get_func_fuzz_coverage(
    functions: list[str],
    *,
    expand_depth: int = 1,
    max_functions: int = 40,
    max_syscalls: int = 20,
    max_examples: int = 5,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    from minisweagent.models.utils.callgraph_tools import func_bfs

    meta: dict[str, dict[str, Any]] = {}
    names: list[str] = []
    for function in functions:
        if function not in meta:
            names.append(function)
            meta[function] = {"depth": 0, "path": [function]}
        if expand_depth <= 0 or len(names) >= max_functions:
            continue
        for record in func_bfs(
            function,
            "reverse",
            max_depth=expand_depth,
            max_nodes=max_functions,
            include_source=False,
            data_root=data_root,
        )["records"]:
            name = record["function"]
            if name not in meta:
                names.append(name)
                meta[name] = {"depth": record["depth"], "path": record["path"]}
            elif record["depth"] < meta[name]["depth"]:
                meta[name] = {"depth": record["depth"], "path": record["path"]}
            if len(names) >= max_functions:
                break
    names = names[:max_functions]
    index = func_index(data_root)
    records = []
    for function in names:
        record = index.get(function)
        records.append({
            "function": function,
            "depth": meta[function]["depth"],
            "path": meta[function]["path"],
            "exists": record is not None,
            "progs": record.get("progs", 0) if record else 0,
            "syscalls": limit_list(record.get("syscalls", []) if record else [], max_syscalls),
            "examples": limit_list(record.get("examples", []) if record else [], max_examples),
        })
    return {
        "functions": functions,
        "expand_depth": expand_depth,
        "records": records,
        "note": "A coverage hit is ground truth from real fuzzing runs. Absence only means the function was not observed.",
    }


def get_fuzz_coverage(
    *,
    functions: list[str] | None = None,
    syscall: str | None = None,
    query: str | None = None,
    expand_depth: int = 1,
    max_functions: int = 40,
    max_syscalls: int = 20,
    max_examples: int = 5,
    file_query: str | None = None,
    max_files: int = 50,
    max_results: int = 50,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    keys = [name for name, value in (("functions", functions), ("syscall", syscall), ("query", query)) if value]
    if len(keys) != 1:
        raise ValueError("supply exactly one of functions, syscall, or query")
    if functions:
        return get_func_fuzz_coverage(
            functions,
            expand_depth=expand_depth,
            max_functions=max_functions,
            max_syscalls=max_syscalls,
            max_examples=max_examples,
            data_root=data_root,
        )
    if syscall:
        return get_syscall_fuzz_coverage(syscall, file_query=file_query, max_files=max_files, data_root=data_root)
    return search_fuzz_covered_functions(
        query,
        max_results=max_results,
        max_syscalls=max_syscalls,
        max_examples=max_examples,
        data_root=data_root,
    )


def get_syscall_fuzz_coverage(
    syscall: str,
    *,
    file_query: str | None = None,
    max_files: int = 50,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    record = syscall_index(data_root).get(syscall)
    files = record.get("files", {}) if record else {}
    if file_query:
        files = {file: count for file, count in files.items() if file_query.lower() in file.lower()}
    return {
        "syscall": syscall,
        "file_query": file_query,
        "exists": record is not None,
        "progs": record.get("progs", 0) if record else 0,
        "files_truncated": record.get("files_truncated", False) if record else False,
        "records": [
            {"file": file, "count": count}
            for file, count in limit_list(sorted(files.items(), key=lambda item: item[1], reverse=True), max_files)
        ],
    }


def search_fuzz_covered_functions(
    query: str,
    *,
    max_results: int = 50,
    max_syscalls: int = 10,
    max_examples: int = 3,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    query_lower = query.lower()
    records = []
    for function, record in func_index(data_root).items():
        matched_examples = [example for example in record.get("examples", []) if query_lower in example.get("file", "").lower()]
        if query_lower not in function.lower() and not matched_examples:
            continue
        records.append({
            "function": function,
            "progs": record.get("progs", 0),
            "syscalls": limit_list(record.get("syscalls", []), max_syscalls),
            "examples": limit_list(matched_examples or record.get("examples", []), max_examples),
        })
    records.sort(key=lambda record: (query_lower not in record["function"].lower(), -record["progs"], record["function"]))
    return {"query": query, "records": limit_list(records, max_results)}


def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="Query dynamic fuzzing coverage indexes.")
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)

    func_parser = subparsers.add_parser("func")
    func_parser.add_argument("functions", nargs="+")
    func_parser.add_argument("--expand-depth", type=int, default=1)
    func_parser.add_argument("--max-functions", type=int, default=40)
    func_parser.add_argument("--max-syscalls", type=int, default=20)
    func_parser.add_argument("--max-examples", type=int, default=5)

    syscall_parser = subparsers.add_parser("syscall")
    syscall_parser.add_argument("syscall")
    syscall_parser.add_argument("--file-query")
    syscall_parser.add_argument("--max-files", type=int, default=50)

    search_parser = subparsers.add_parser("search-functions")
    search_parser.add_argument("query")
    search_parser.add_argument("--max-results", type=int, default=50)
    search_parser.add_argument("--max-syscalls", type=int, default=10)
    search_parser.add_argument("--max-examples", type=int, default=3)

    args = parser.parse_args()
    if args.command == "func":
        print_json(
            get_func_fuzz_coverage(
                args.functions,
                expand_depth=args.expand_depth,
                max_functions=args.max_functions,
                max_syscalls=args.max_syscalls,
                max_examples=args.max_examples,
                data_root=args.data_root,
            )
        )
    elif args.command == "syscall":
        print_json(
            get_syscall_fuzz_coverage(
                args.syscall,
                file_query=args.file_query,
                max_files=args.max_files,
                data_root=args.data_root,
            )
        )
    elif args.command == "search-functions":
        print_json(
            search_fuzz_covered_functions(
                args.query,
                max_results=args.max_results,
                max_syscalls=args.max_syscalls,
                max_examples=args.max_examples,
                data_root=args.data_root,
            )
        )


if __name__ == "__main__":
    main()
