#!/usr/bin/env python3
"""Safely extract SQL occurrences from application archives.

The output is intentionally an intermediate JSON contract. Rule evaluation is
performed by the skill, while this script handles deterministic file discovery,
archive safety, source locations, and database-type hints.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Iterable, Iterator, Optional


MAX_ENTRIES = 10_000
MAX_TOTAL_BYTES = 500 * 1024 * 1024
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_NESTING = 5
MAX_SQL_LENGTH = 32_767

ARCHIVE_EXTENSIONS = (".zip", ".jar", ".war", ".ear", ".tar", ".tar.gz", ".tgz", ".7z", ".rar")
TEXT_EXTENSIONS = {
    ".sql", ".xml", ".xhtml", ".java", ".kt", ".kts", ".groovy", ".scala", ".properties",
    ".yml", ".yaml", ".json", ".py", ".go", ".js", ".ts", ".tsx", ".jsx", ".cs", ".php",
    ".rb", ".rs", ".conf", ".cfg", ".ini", ".txt", ".md", ".ftl", ".vm", ".jsp",
}
SQL_START = re.compile(
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|MERGE|REPLACE|WITH|CALL|CREATE|ALTER|DROP|TRUNCATE)\b",
    re.I,
)
# Separate alternatives avoid back-reference ambiguity between single and triple quotes.
STRING_RE = re.compile(
    r"'''(?P<triple_single>(?:\\.|(?!''').)*?)'''|\"\"\"(?P<triple_double>(?:\\.|(?!\"\"\").)*?)\"\"\"|'(?P<single>(?:\\.|[^'\\])*)'|\"(?P<double>(?:\\.|[^\"\\])*)\"",
    re.S,
)
XML_SQL_RE = re.compile(r"<(?P<tag>select|insert|update|delete|sql)\b[^>]*>(?P<body>.*?)</(?P=tag)\s*>", re.I | re.S)
XML_SQL_FRAGMENT_RE = re.compile(
    r"<sql\b(?P<attrs>[^>]*)>(?P<body>.*?)</sql\s*>", re.I | re.S
)
XML_INCLUDE_RE = re.compile(
    r"<include\b(?P<attrs>[^>]*)/?>", re.I | re.S
)


class ExtractionError(RuntimeError):
    pass


@dataclass
class SourceText:
    path: str
    text: str
    depth: int


def normalize_path(name: str) -> str:
    name = name.replace("\\", "/")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ExtractionError(f"unsafe archive path: {name}")
    return str(path)


def is_archive_name(name: str) -> bool:
    lower = name.lower()
    return any(lower.endswith(ext) for ext in ARCHIVE_EXTENSIONS)


def decode_text(data: bytes) -> Optional[str]:
    if not data or b"\x00" in data[:4096]:
        return None
    for encoding in ("utf-8-sig", "utf-8", "gb18030", "cp1252"):
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        if text.count("\ufffd") <= max(2, len(text) // 500):
            return text
    return None


def iter_zip(data: bytes, prefix: str, depth: int) -> Iterator[tuple[str, bytes, int]]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (OSError, zipfile.BadZipFile) as exc:
        raise ExtractionError(f"invalid ZIP archive at {prefix or '<input>'}: {exc}") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ENTRIES:
            raise ExtractionError(f"archive has too many entries: {len(infos)}")
        total = 0
        for info in infos:
            if info.is_dir():
                continue
            path = normalize_path(f"{prefix}/{info.filename}" if prefix else info.filename)
            if info.file_size > MAX_FILE_BYTES:
                yield path, b"", depth
                continue
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise ExtractionError("archive expands beyond the safety limit")
            # Unix symlinks must not escape the archive through a later filesystem operation.
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                continue
            yield path, archive.read(info), depth


def iter_tar(data: bytes, prefix: str, depth: int) -> Iterator[tuple[str, bytes, int]]:
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except (OSError, tarfile.TarError) as exc:
        raise ExtractionError(f"invalid TAR archive at {prefix or '<input>'}: {exc}") from exc
    with archive:
        members = archive.getmembers()
        if len(members) > MAX_ENTRIES:
            raise ExtractionError(f"archive has too many entries: {len(members)}")
        total = 0
        for member in members:
            if not member.isfile():
                continue
            path = normalize_path(f"{prefix}/{member.name}" if prefix else member.name)
            if member.size > MAX_FILE_BYTES:
                yield path, b"", depth
                continue
            total += member.size
            if total > MAX_TOTAL_BYTES:
                raise ExtractionError("archive expands beyond the safety limit")
            handle = archive.extractfile(member)
            yield path, handle.read() if handle else b"", depth


def external_archive_entries(data: bytes, name: str, prefix: str, depth: int) -> Iterator[tuple[str, bytes, int]]:
    tool = shutil.which("7z") or shutil.which("7zz") if name.lower().endswith(".7z") else shutil.which("unrar")
    if not tool:
        raise ExtractionError(f"no extractor available for {name}")
    with tempfile.TemporaryDirectory(prefix="sql-audit-") as temp:
        source = os.path.join(temp, os.path.basename(name))
        with open(source, "wb") as handle:
            handle.write(data)
        output = os.path.join(temp, "out")
        os.makedirs(output)
        if os.path.basename(tool).lower() in {"7z", "7zz"}:
            command = [tool, "x", "-y", f"-o{output}", source]
        else:
            command = [tool, "x", "-idq", source, output]
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
        if completed.returncode != 0:
            raise ExtractionError(f"failed to extract {name}: {completed.stderr.decode(errors='replace').strip()}")
        for root, _, files in os.walk(output):
            for filename in files:
                full = os.path.join(root, filename)
                relative = os.path.relpath(full, output).replace(os.sep, "/")
                path = normalize_path(f"{prefix}/{relative}" if prefix else relative)
                with open(full, "rb") as handle:
                    payload = handle.read(MAX_FILE_BYTES + 1)
                if len(payload) > MAX_FILE_BYTES:
                    payload = b""
                yield path, payload, depth


def walk_archive(data: bytes, name: str, prefix: str = "", depth: int = 0) -> Iterator[tuple[str, bytes, int]]:
    if depth > MAX_NESTING:
        raise ExtractionError("nested archive depth exceeds the safety limit")
    lower = name.lower()
    if lower.endswith((".zip", ".jar", ".war", ".ear")) or (not lower.endswith((".tar", ".tar.gz", ".tgz", ".7z", ".rar")) and data[:4] == b"PK\x03\x04"):
        yield from iter_zip(data, prefix, depth)
    elif lower.endswith((".tar", ".tar.gz", ".tgz")):
        yield from iter_tar(data, prefix, depth)
    elif lower.endswith((".7z", ".rar")):
        yield from external_archive_entries(data, name, prefix, depth)
    else:
        raise ExtractionError(f"unsupported archive format: {name}")


def unescape_literal(value: str) -> str:
    return value.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t").replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\")


def strip_xml_tags(value: str) -> str:
    value = re.sub(r"<!--.*?-->", " ", value, flags=re.S)
    # Preserve dynamic structure as reviewable markers rather than guessing a branch.
    return re.sub(r"<(/?)(if|choose|when|otherwise|foreach|where|trim|set)\b[^>]*>", r" /* <\1\2> */ ", value, flags=re.I)


def expand_xml_includes(text: str) -> str:
    """Expand resolvable MyBatis SQL fragments while preserving unknown includes."""
    fragments: dict[str, str] = {}
    for match in XML_SQL_FRAGMENT_RE.finditer(text):
        id_match = re.search(r"\bid\s*=\s*(['\"])([^'\"]+)\1", match.group("attrs"), re.I)
        if id_match:
            fragment_id = id_match.group(2).strip()
            fragments[fragment_id] = match.group("body")
            fragments.setdefault(fragment_id.rsplit(".", 1)[-1], match.group("body"))

    def expand(value: str, stack: tuple[str, ...] = ()) -> str:
        def replace(match: re.Match[str]) -> str:
            attrs = match.group("attrs")
            ref_match = re.search(r"\brefid\s*=\s*(['\"])([^'\"]+)\1", attrs, re.I)
            if not ref_match:
                return match.group(0)
            refid = ref_match.group(2).strip()
            fragment = fragments.get(refid) or fragments.get(refid.rsplit(".", 1)[-1])
            if fragment is None or refid in stack:
                return match.group(0)
            return expand(fragment, stack + (refid,))

        return XML_INCLUDE_RE.sub(replace, value)

    return expand(text)


def statement_parts(text: str, base_line: int) -> Iterator[tuple[str, int]]:
    """Split SQL text at semicolons outside quotes/comments."""
    start = 0
    quote = None
    line = base_line
    statement_line = base_line
    i = 0
    while i < len(text):
        char = text[i]
        if char == "\n":
            line += 1
        if quote:
            if char == "\\":
                i += 2
                continue
            if char == quote:
                quote = None
        elif char in {"'", '"', "`"}:
            quote = char
        elif text.startswith("--", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = len(text) if end < 0 else end + 1
        elif char == ";":
            part = text[start:i].strip()
            if SQL_START.search(sql_detection_text(part)):
                yield part, statement_line
            start = i + 1
            statement_line = line
        i += 1
    part = text[start:].strip()
    if SQL_START.search(sql_detection_text(part)):
        yield part, statement_line


def sql_detection_text(value: str) -> str:
    """Remove comments and quoted literals for SQL keyword detection only."""
    output: list[str] = []
    i = 0
    while i < len(value):
        if value.startswith("--", i) or value.startswith("//", i):
            end = value.find("\n", i + 2)
            if end < 0:
                break
            output.append("\n")
            i = end + 1
            continue
        if value.startswith("/*", i):
            end = value.find("*/", i + 2)
            if end < 0:
                break
            output.append(" " * (end + 2 - i))
            i = end + 2
            continue
        if value[i] in {"'", '"', "`"}:
            quote = value[i]
            i += 1
            while i < len(value):
                if value[i] == "\\":
                    i += 2
                    continue
                if value[i] == quote:
                    if i + 1 < len(value) and value[i + 1] == quote:
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            output.append(" ")
            continue
        output.append(value[i])
        i += 1
    return "".join(output)


def likely_sql(value: str) -> bool:
    compact = re.sub(r"\s+", " ", value).strip()
    return len(compact) >= 12 and bool(SQL_START.search(compact)) and bool(
        re.search(
            r"\b(FROM|INTO|SET|WHERE|VALUES|JOIN|CALL|TABLE|INDEX|VIEW|SEQUENCE|PROCEDURE|FUNCTION|TRIGGER|DATABASE|SCHEMA)\b",
            compact,
            re.I,
        )
    )


def extract_from_text(source: SourceText) -> Iterator[dict]:
    text = source.text
    lower = source.path.lower()
    if lower.endswith(".xml"):
        expanded_text = expand_xml_includes(text)
        matches = list(XML_SQL_RE.finditer(expanded_text))
        for match in matches:
            if match.group("tag").lower() == "sql":
                continue
            value = strip_xml_tags(match.group("body")).strip()
            if likely_sql(value):
                yield {"sql": value, "line": expanded_text.count("\n", 0, match.start()) + 1, "extractor": "xml"}
        # XML may contain SQL in attributes or non-MyBatis nodes; continue with literals.
    if lower.endswith(".sql"):
        for value, line in statement_parts(text, 1):
            if len(value) <= MAX_SQL_LENGTH:
                yield {"sql": value, "line": line, "extractor": "sql"}
        return
    for match in STRING_RE.finditer(text):
        value = next((group for group in match.groups() if group is not None), "")
        value = unescape_literal(value).strip()
        # Translation/property values frequently contain words such as
        # "WITH" or "UPDATE". Only accept a properties value when it starts
        # with an actual SQL statement keyword.
        if lower.endswith(".properties") and not SQL_START.match(value):
            continue
        if likely_sql(value) and len(value) <= MAX_SQL_LENGTH:
            yield {"sql": value, "line": text.count("\n", 0, match.start()) + 1, "extractor": "literal"}


def infer_database(text: str, sql: str) -> str:
    haystack = f"{text}\n{sql}".lower()
    checks = (
        ("Oracle", ("jdbc:oracle", "oracle.jdbc", "dbms_random", "rownum", "nvl(")),
        ("Mysql", ("jdbc:mysql", "mysql-connector", "`")),
        ("Kingbase", ("jdbc:kingbase", "kingbase")),
        ("Gbase", ("jdbc:gbase", "gbase")),
        ("Gaussdb", ("jdbc:gauss", "gaussdb")),
    )
    for database, tokens in checks:
        if any(token in haystack for token in tokens):
            return database
    return ""


def extract(input_path: str, db_type: str = "") -> dict:
    if not os.path.isfile(input_path):
        raise ExtractionError(f"input archive does not exist: {input_path}")
    name = os.path.basename(input_path)
    with open(input_path, "rb") as handle:
        payload = handle.read(MAX_TOTAL_BYTES + 1)
    if len(payload) > MAX_TOTAL_BYTES:
        raise ExtractionError("input archive exceeds the safety limit")
    candidates: list[dict] = []
    warnings: list[dict] = []
    seen_archives: set[tuple[str, int]] = set()
    def visit(data: bytes, archive_name: str, prefix: str, depth: int) -> None:
        key = (prefix, len(data))
        if key in seen_archives:
            return
        seen_archives.add(key)
        for path, content, child_depth in walk_archive(data, archive_name, prefix, depth):
            if is_archive_name(path) and child_depth < MAX_NESTING and content:
                visit(content, os.path.basename(path), path, child_depth + 1)
                continue
            if not content or path.lower().endswith(".class"):
                if not content and not path.lower().endswith(".class"):
                    warnings.append({"source": path, "reason": "file exceeds per-file extraction limit or is empty"})
                continue
            suffix = PurePosixPath(path).suffix.lower()
            # Unknown extensions are legitimate in mapper/template systems. The decoder
            # rejects binaries, so it is safe to use it as a generic text fallback.
            text = decode_text(content) if suffix in TEXT_EXTENSIONS or suffix not in {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".so", ".dll", ".exe"} else None
            if text is None:
                continue
            source = SourceText(path, text, child_depth)
            try:
                for record in extract_from_text(source):
                    sql = record["sql"].strip()
                    candidates.append({
                        "source": path,
                        "line": record["line"],
                        "sql": sql,
                        "database_type": db_type or infer_database(text, sql),
                        "extractor": record["extractor"],
                    })
            except Exception as exc:  # a bad source must not block other files
                warnings.append({"source": path, "reason": f"SQL extraction failed: {exc}"})
    visit(payload, name, "", 0)
    return {"records": candidates, "warnings": warnings, "input": input_path}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--db-type", choices=("Oracle", "Mysql", "Kingbase", "Gbase", "Gaussdb"), default="")
    args = parser.parse_args()
    try:
        result = extract(args.input, args.db_type)
    except ExtractionError as exc:
        print(f"sql-audit extraction error: {exc}", file=sys.stderr)
        return 2
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
    print(json.dumps({"records": len(result["records"]), "warnings": len(result["warnings"])}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
