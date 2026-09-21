from __future__ import annotations

import argparse
import json
from difflib import get_close_matches
from functools import lru_cache
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_DATA_ROOT = REPO_ROOT / "data/linux-6.6"


@lru_cache
def read_json(path: str) -> Any:
    return json.loads(Path(path).read_text())


def syzlang_dir(data_root: Path) -> Path:
    return data_root / "syzlang"


def syzlang_index(data_root: Path) -> dict[str, list[dict[str, Any]]]:
    return read_json(str(syzlang_dir(data_root) / "syzlang.index.json"))


def syscall_deps(data_root: Path) -> dict[str, dict[str, Any]]:
    return {record["syscall"]: record for record in read_json(str(syzlang_dir(data_root) / "syz_depend_inout.json"))}


def matches_hint(record: dict[str, Any], file_hint: str | None) -> bool:
    if not file_hint:
        return True
    file = record.get("file", "")
    return file_hint in file or file.endswith(file_hint)


def limit_records(records: list[dict[str, Any]], max_results: int | None) -> list[dict[str, Any]]:
    if max_results is None or max_results <= 0:
        return records
    return records[:max_results]


def list_syzlang_files(query: str | None = None, *, data_root: Path = DEFAULT_DATA_ROOT) -> dict[str, Any]:
    files = sorted(path.relative_to(syzlang_dir(data_root)).as_posix() for path in (syzlang_dir(data_root) / "linux").glob("*.txt"))
    if not query:
        return {"query": query, "fallback": False, "files": files}
    matches = [path for path in files if query.lower() in path.lower()]
    return {"query": query, "fallback": not matches, "files": matches or files}


def search_syzlang(query: str, *, max_results: int = 50, data_root: Path = DEFAULT_DATA_ROOT) -> dict[str, Any]:
    if not query:
        raise ValueError("query must not be empty")
    query_lower = query.lower()
    records = []
    for name, definitions in syzlang_index(data_root).items():
        for definition in definitions:
            source = definition.get("source", "")
            file = definition.get("file", "")
            match_fields = [
                field
                for field, value in (("name", name), ("source", source), ("file", file))
                if query_lower in value.lower()
            ]
            if not match_fields:
                continue
            records.append({
                "name": name,
                "kind": definition.get("kind"),
                "file": file,
                "line": definition.get("line"),
                "source": source,
                "match_fields": match_fields,
            })
    records.sort(key=lambda record: (
        query_lower != record["name"].lower(),
        "name" not in record["match_fields"],
        "source" not in record["match_fields"],
        record["file"],
        record["line"] or 0,
        record["name"],
    ))
    return {"query": query, "records": limit_records(records, max_results)}


def read_syzlang_def(
    name: str,
    *,
    file_hint: str | None = None,
    full: bool = True,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    records = [dict(record) for record in syzlang_index(data_root).get(name, [])]
    hinted_records = [record for record in records if matches_hint(record, file_hint)]
    records = hinted_records or records
    for record in records:
        if full:
            record["source"] = record.get("full_source", record.get("source", ""))
        record.pop("full_source", None)
    return {"name": name, "file_hint": file_hint, "full": full, "records": records}


def read_syzlang_file(
    path: str,
    start_line: int,
    end_line: int,
    *,
    max_lines: int = 200,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    if start_line < 1 or end_line < start_line:
        raise ValueError("Expected 1 <= start_line <= end_line")
    if end_line - start_line + 1 > max_lines:
        end_line = start_line + max_lines - 1
    syzlang_path = syzlang_dir(data_root) / path
    lines = syzlang_path.read_text(errors="replace").splitlines()
    end_line = min(end_line, len(lines))
    return {
        "path": path,
        "start_line": start_line,
        "end_line": end_line,
        "content": "\n".join(f"{line_no}: {lines[line_no - 1]}" for line_no in range(start_line, end_line + 1)),
    }


def validate_syzlang_candidates(
    names: list[str],
    *,
    max_suggestions: int = 5,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    index = syzlang_index(data_root)
    keys = sorted(index)
    records = []
    for name in names:
        if name in index:
            records.append({
                "name": name,
                "exists": True,
                "definitions": [
                    {key: record.get(key) for key in ("kind", "file", "line")}
                    for record in index[name]
                ],
            })
        else:
            records.append({
                "name": name,
                "exists": False,
                "suggestions": get_close_matches(name, keys, n=max_suggestions),
            })
    return {"names": names, "records": records}


def get_syscall_deps(
    syscalls: str | list[str],
    *,
    include_depend: bool = True,
    include_depended: bool = True,
    max_results: int = 50,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    names = [syscalls] if isinstance(syscalls, str) else list(syscalls)
    if not names:
        raise ValueError("syscalls must not be empty")
    deps = syscall_deps(data_root)
    records = {}
    for name in names:
        record = deps.get(name, {})
        records[name] = {
            "depend": limit_records(record.get("depend", []) if include_depend else [], max_results),
            "depended": limit_records(record.get("depended", []) if include_depended else [], max_results),
        }
    return {"syscalls": records}


def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="Query preprocessed syzkaller syzlang data.")
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list-files")
    list_parser.add_argument("--query")

    search_parser = subparsers.add_parser("search")
    search_parser.add_argument("query")
    search_parser.add_argument("--max-results", type=int, default=50)

    def_parser = subparsers.add_parser("read-def")
    def_parser.add_argument("name")
    def_parser.add_argument("--file-hint")
    def_parser.add_argument("--brief", action="store_true")

    file_parser = subparsers.add_parser("read-file")
    file_parser.add_argument("path")
    file_parser.add_argument("start_line", type=int)
    file_parser.add_argument("end_line", type=int)

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("names", nargs="+")
    validate_parser.add_argument("--max-suggestions", type=int, default=5)

    deps_parser = subparsers.add_parser("deps")
    deps_parser.add_argument("syscall")
    deps_parser.add_argument("--no-depend", action="store_true")
    deps_parser.add_argument("--no-depended", action="store_true")
    deps_parser.add_argument("--max-results", type=int, default=50)

    args = parser.parse_args()
    if args.command == "list-files":
        print_json(list_syzlang_files(args.query, data_root=args.data_root))
    elif args.command == "search":
        print_json(search_syzlang(args.query, max_results=args.max_results, data_root=args.data_root))
    elif args.command == "read-def":
        print_json(read_syzlang_def(args.name, file_hint=args.file_hint, full=not args.brief, data_root=args.data_root))
    elif args.command == "read-file":
        print_json(read_syzlang_file(args.path, args.start_line, args.end_line, data_root=args.data_root))
    elif args.command == "validate":
        print_json(validate_syzlang_candidates(args.names, max_suggestions=args.max_suggestions, data_root=args.data_root))
    elif args.command == "deps":
        print_json(
            get_syscall_deps(
                args.syscall,
                include_depend=not args.no_depend,
                include_depended=not args.no_depended,
                max_results=args.max_results,
                data_root=args.data_root,
            )
        )


if __name__ == "__main__":
    main()
