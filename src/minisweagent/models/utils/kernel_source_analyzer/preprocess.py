from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

app = typer.Typer()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def split_filename(filename: str) -> tuple[str, int]:
    path, _, line = filename.rpartition(":")
    try:
        return path, int(line)
    except ValueError:
        return filename, 0


def normalize_path(path: str, linux_root: Path | None) -> str:
    if not linux_root:
        return path
    try:
        return Path(path).resolve().relative_to(linux_root.resolve()).as_posix()
    except ValueError:
        return path


def normalize_record(record: dict[str, Any], linux_root: Path | None) -> dict[str, Any]:
    path, line = split_filename(record.get("filename", ""))
    return {
        "file": normalize_path(record.get("file", path), linux_root),
        "line": int(record.get("line") or line),
        "source": record.get("source", ""),
    }


def append_index(index: dict[str, list[dict[str, Any]]], key: str, value: dict[str, Any]) -> None:
    if not key:
        return
    index.setdefault(key, []).append(value)


def build_func_index(input_dir: Path, linux_root: Path | None) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for record in read_jsonl(input_dir / "func.jsonl"):
        append_index(index, record.get("name", ""), normalize_record(record, linux_root))
    return index


def build_type_index(input_dir: Path, linux_root: Path | None) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    sources = [
        ("struct.jsonl", "struct"),
        ("enum.jsonl", "enum"),
        ("struct-typedef.jsonl", "struct_typedef"),
        ("enum-typedef.jsonl", "enum_typedef"),
    ]
    for file_name, default_kind in sources:
        for record in read_jsonl(input_dir / file_name):
            value = normalize_record(record, linux_root) | {
                "kind": record.get("kind", default_kind),
            }
            if alias := record.get("alias"):
                value["alias"] = alias
            append_index(index, record.get("name", ""), value)
    return index


def build_ops_index(input_dir: Path, linux_root: Path | None) -> dict[str, Any]:
    by_handler: dict[str, list[dict[str, Any]]] = {}
    by_table: dict[str, list[dict[str, Any]]] = {}
    for record in read_jsonl(input_dir / "ops.jsonl"):
        value = {
            "table": record.get("table", ""),
            "table_type": record.get("table_type", ""),
            "field": record.get("field", ""),
            "handler": record.get("handler", ""),
            "file": normalize_path(record.get("file", ""), linux_root),
            "line": int(record.get("line") or 0),
            "table_line": int(record.get("table_line") or 0),
            "table_key": record.get("table_key", ""),
            "source": record.get("source", ""),
            "table_source": record.get("table_source", ""),
        }
        append_index(by_handler, value["handler"], value)
        append_index(by_table, value["table"], value)
    return {"by_handler": by_handler, "by_table": by_table}


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True))


@app.command()
def build(input_dir: Path, output_dir: Path, linux_root: Path | None = None) -> None:
    """Build query indexes from raw kernel analyzer JSONL files."""
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "func.index.json", build_func_index(input_dir, linux_root))
    write_json(output_dir / "type.index.json", build_type_index(input_dir, linux_root))
    write_json(output_dir / "ops.index.json", build_ops_index(input_dir, linux_root))


if __name__ == "__main__":
    app()
