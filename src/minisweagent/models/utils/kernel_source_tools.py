from __future__ import annotations

import argparse
import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_DATA_ROOT = REPO_ROOT / "data/linux-6.6"
DEFAULT_LINUX_ROOT = Path(os.environ.get("MINISWEAGENT_LINUX_ROOT", "/home/lab420/Documents/fuzz/inf/linux-6.6"))


@lru_cache
def read_json(path: str) -> Any:
    return json.loads(Path(path).read_text())


def source_dir(data_root: Path) -> Path:
    return data_root / "source"


def limit_records(records: list[dict[str, Any]], max_results: int | None) -> list[dict[str, Any]]:
    if max_results is None or max_results <= 0:
        return records
    return records[:max_results]


def matches_hint(record: dict[str, Any], file_hint: str | None) -> bool:
    if not file_hint:
        return True
    file = record.get("file", "")
    return file_hint in file or file.endswith(file_hint)


def clean_record(record: dict[str, Any]) -> dict[str, Any]:
    return dict(record)


def get_function_source(
    function: str,
    *,
    file_hint: str | None = None,
    max_results: int = 3,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    index = read_json(str(source_dir(data_root) / "func.index.json"))
    records = [clean_record(record) for record in index.get(function, []) if matches_hint(record, file_hint)]
    return {"function": function, "records": limit_records(records, max_results)}


def get_type_source(
    type_name: str,
    *,
    kind: str = "any",
    file_hint: str | None = None,
    max_results: int = 3,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    index = read_json(str(source_dir(data_root) / "type.index.json"))
    records = [
        clean_record(record)
        for record in index.get(type_name, [])
        if (kind == "any" or record.get("kind") == kind) and matches_hint(record, file_hint)
    ]
    return {"type_name": type_name, "kind": kind, "records": limit_records(records, max_results)}


def lookup_ops_by_handler(
    handler: str,
    *,
    field: str | None = None,
    table_type: str | None = None,
    file_hint: str | None = None,
    max_results: int = 10,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    index = read_json(str(source_dir(data_root) / "ops.index.json"))
    records = []
    for record in index.get("by_handler", {}).get(handler, []):
        if field and record.get("field") != field:
            continue
        if table_type and table_type not in record.get("table_type", ""):
            continue
        if not matches_hint(record, file_hint):
            continue
        records.append(clean_record(record))
    return {
        "handler": handler,
        "field": field,
        "table_type": table_type,
        "records": limit_records(records, max_results),
    }


def lookup_ops_by_table(
    table: str,
    *,
    file_hint: str | None = None,
    max_results: int = 20,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    index = read_json(str(source_dir(data_root) / "ops.index.json"))
    records = [clean_record(record) for record in index.get("by_table", {}).get(table, []) if matches_hint(record, file_hint)]
    return {"table": table, "records": limit_records(records, max_results)}


def resolve_source_path(path: str, linux_root: Path | None = None) -> Path:
    source_path = Path(path)
    if source_path.is_absolute():
        return source_path
    candidates = [
        Path.cwd() / source_path,
        REPO_ROOT / source_path,
    ]
    if linux_root:
        candidates.insert(0, linux_root / source_path)
    if DEFAULT_LINUX_ROOT.is_dir():
        candidates.append(DEFAULT_LINUX_ROOT / source_path)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


def lookup_ops(
    *,
    handler: str | None = None,
    table: str | None = None,
    field: str | None = None,
    table_type: str | None = None,
    file_hint: str | None = None,
    max_results: int | None = None,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    if bool(handler) == bool(table):
        raise ValueError("supply exactly one of handler or table")
    if handler:
        return lookup_ops_by_handler(
            handler,
            field=field,
            table_type=table_type,
            file_hint=file_hint,
            max_results=10 if max_results is None else max_results,
            data_root=data_root,
        )
    return lookup_ops_by_table(
        table,
        file_hint=file_hint,
        max_results=20 if max_results is None else max_results,
        data_root=data_root,
    )


def read_kernel_source(
    *,
    func: str | None = None,
    type_name: str | None = None,
    path: str | None = None,
    kind: str = "any",
    file_hint: str | None = None,
    start_line: int | None = None,
    end_line: int | None = None,
    line: int | None = None,
    context: int = 40,
    max_results: int = 3,
    linux_root: Path | None = None,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    keys = [name for name, value in (("func", func), ("type_name", type_name), ("path", path)) if value]
    if len(keys) != 1:
        raise ValueError("supply exactly one of func, type_name, or path")
    if func:
        return get_function_source(func, file_hint=file_hint, max_results=max_results, data_root=data_root)
    if type_name:
        return get_type_source(type_name, kind=kind, file_hint=file_hint, max_results=max_results, data_root=data_root)
    if line is not None:
        start_line = max(1, int(line) - int(context))
        end_line = int(line) + int(context)
    if start_line is None or end_line is None:
        raise ValueError("path mode requires start_line and end_line, or line")
    return get_file_snippet(path, int(start_line), int(end_line), linux_root=linux_root)


def get_file_snippet(
    path: str,
    start_line: int,
    end_line: int,
    *,
    linux_root: Path | None = None,
    max_lines: int = 200,
) -> dict[str, Any]:
    if start_line < 1 or end_line < start_line:
        raise ValueError("Expected 1 <= start_line <= end_line")
    if end_line - start_line + 1 > max_lines:
        end_line = start_line + max_lines - 1
    source_path = resolve_source_path(path, linux_root)
    lines = source_path.read_text(errors="replace").splitlines()
    end_line = min(end_line, len(lines))
    content = "\n".join(f"{line_no}: {lines[line_no - 1]}" for line_no in range(start_line, end_line + 1))
    return {"path": str(source_path), "start_line": start_line, "end_line": end_line, "content": content}


def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="Query preprocessed Linux source indexes.")
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)

    function_parser = subparsers.add_parser("get-function")
    function_parser.add_argument("function")
    function_parser.add_argument("--file-hint")
    function_parser.add_argument("--max-results", type=int, default=3)

    type_parser = subparsers.add_parser("get-type")
    type_parser.add_argument("type_name")
    type_parser.add_argument("--kind", default="any")
    type_parser.add_argument("--file-hint")
    type_parser.add_argument("--max-results", type=int, default=3)

    handler_parser = subparsers.add_parser("lookup-handler")
    handler_parser.add_argument("handler")
    handler_parser.add_argument("--field")
    handler_parser.add_argument("--table-type")
    handler_parser.add_argument("--file-hint")
    handler_parser.add_argument("--max-results", type=int, default=10)

    table_parser = subparsers.add_parser("lookup-table")
    table_parser.add_argument("table")
    table_parser.add_argument("--file-hint")
    table_parser.add_argument("--max-results", type=int, default=20)

    snippet_parser = subparsers.add_parser("snippet")
    snippet_parser.add_argument("path")
    snippet_parser.add_argument("start_line", type=int)
    snippet_parser.add_argument("end_line", type=int)
    snippet_parser.add_argument("--linux-root", type=Path)

    args = parser.parse_args()
    if args.command == "get-function":
        print_json(get_function_source(args.function, file_hint=args.file_hint, max_results=args.max_results, data_root=args.data_root))
    elif args.command == "get-type":
        print_json(
            get_type_source(
                args.type_name,
                kind=args.kind,
                file_hint=args.file_hint,
                max_results=args.max_results,
                data_root=args.data_root,
            )
        )
    elif args.command == "lookup-handler":
        print_json(
            lookup_ops_by_handler(
                args.handler,
                field=args.field,
                table_type=args.table_type,
                file_hint=args.file_hint,
                max_results=args.max_results,
                data_root=args.data_root,
            )
        )
    elif args.command == "lookup-table":
        print_json(lookup_ops_by_table(args.table, file_hint=args.file_hint, max_results=args.max_results, data_root=args.data_root))
    elif args.command == "snippet":
        print_json(get_file_snippet(args.path, args.start_line, args.end_line, linux_root=args.linux_root))


if __name__ == "__main__":
    main()
