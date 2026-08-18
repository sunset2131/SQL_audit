#!/usr/bin/env python3
"""Write SQL audit JSON into the supplied XLSX template without reformatting it."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import zipfile
from html import escape


MAX_CELL_LENGTH = 32_767
SHEET_NAME = "应用代码扫描结果"
SUMMARY_SHEET_NAME = "汇总信息"
SUMMARY_TITLE = "应用代码扫描汇总"
HEADERS = [
    "代码文件",
    "目标数据库类型",
    "原SQL",
    "审核结果",
    "存在问题",
    "处理建议",
    "人工复核结果",
]


def xml_text(value: str) -> str:
    return escape(str(value), quote=False)


def load_records(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    records = payload if isinstance(payload, list) else payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        raise ValueError("audit JSON must contain a records array")
    for index, record in enumerate(records, 1):
        if not isinstance(record, dict):
            raise ValueError(f"record {index} is not an object")
        for key in ("source", "sql"):
            if not isinstance(record.get(key), str) or not record[key].strip():
                raise ValueError(f"record {index} requires non-empty string field {key}")
        if len(record["sql"]) > MAX_CELL_LENGTH:
            raise ValueError(f"record {index} SQL exceeds Excel's {MAX_CELL_LENGTH}-character cell limit")
        findings = record.get("findings", [])
        if not isinstance(findings, list):
            raise ValueError(f"record {index} findings must be an array")
        for finding in findings:
            if not isinstance(finding, dict) or not finding.get("rule_id") or not finding.get("problem") or not finding.get("suggestion"):
                raise ValueError(f"record {index} contains an invalid finding")
    return records


def numbered(records: list[dict], field: str, separator: str) -> str:
    values = [str(item[field]).strip() for item in records if str(item.get(field, "")).strip()]
    return separator.join(f"{idx}. {value}" for idx, value in enumerate(values, 1)) if values else "无"


def shared_string_xml(value: str) -> str:
    preserve = ' xml:space="preserve"' if value[:1].isspace() or value[-1:].isspace() or "\n" in value else ""
    return f"<si><t{preserve}>{xml_text(value)}</t></si>"


def update_shared_strings(xml: str, values: list[str]) -> tuple[str, list[int]]:
    match = re.search(r"<sst\b([^>]*)>", xml)
    if not match:
        raise ValueError("template has no shared string table")
    existing = len(re.findall(r"<si\b", xml))
    appended = "".join(shared_string_xml(value) for value in values)
    xml = xml.replace("</sst>", appended + "</sst>", 1)
    count_match = re.search(r'\bcount="(\d+)"', xml)
    unique_match = re.search(r'\buniqueCount="(\d+)"', xml)
    if count_match:
        xml = xml[:count_match.start(1)] + str(existing + len(values)) + xml[count_match.end(1):]
    if unique_match:
        xml = xml[:unique_match.start(1)] + str(existing + len(values)) + xml[unique_match.end(1):]
    return xml, list(range(existing, existing + len(values)))


def cell(column: str, row: int, string_index: int, style: int | None = None) -> str:
    style_attr = f' s="{style}"' if style is not None else ""
    return f'<c r="{column}{row}"{style_attr} t="s"><v>{string_index}</v></c>'


def blank_cell(column: str, row: int) -> str:
    return f'<c r="{column}{row}"/>'


def number_cell(column: str, row: int, value: int, style: int | None = None) -> str:
    style_attr = f' s="{style}"' if style is not None else ""
    return f'<c r="{column}{row}"{style_attr}><v>{value}</v></c>'


def build_summary(records: list[dict]) -> dict[str, list[tuple[str, int]]]:
    database_counts: dict[str, int] = {}
    rule_counts: dict[str, int] = {}
    passed = 0
    for record in records:
        findings = record.get("findings", [])
        if findings:
            for finding in findings:
                rule_id = str(finding["rule_id"])
                rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
        else:
            passed += 1
        database_type = record.get("database_type", "") or "未识别"
        database_counts[database_type] = database_counts.get(database_type, 0) + 1

    def rule_sort_key(item: tuple[str, int]) -> tuple[int, str]:
        match = re.fullmatch(r"BUS-(\d+)", item[0])
        return (int(match.group(1)), item[0]) if match else (sys.maxsize, item[0])

    return {
        "metrics": [
            ("SQL 总数", len(records)),
            ("通过数", passed),
            ("不通过数", len(records) - passed),
        ],
        "database_types": sorted(database_counts.items()),
        "rules": sorted(rule_counts.items(), key=rule_sort_key),
    }


def summary_strings(summary: dict[str, list[tuple[str, int]]]) -> list[str]:
    values = [SUMMARY_TITLE, "统计项", "数量"]
    values.extend(label for label, _ in summary["metrics"])
    values.extend(["目标数据库类型", "SQL 数量"])
    values.extend(label for label, _ in summary["database_types"])
    values.extend(["规则 ID", "命中次数"])
    values.extend(label for label, _ in summary["rules"])
    return values


def update_sheet(xml: str, shared_indices: dict[str, int], records: list[dict]) -> str:
    xml = re.sub(r'<dimension\b[^>]*/>', f'<dimension ref="A1:G{max(1, len(records) + 1)}"/>', xml, count=1)
    xml = re.sub(r'<row\s+r="[2-9]\d*"[^>]*>.*?</row>', "", xml, flags=re.S)
    rows = []
    for offset, record in enumerate(records, 2):
        findings = record.get("findings", [])
        values = [
            record["source"],
            record.get("database_type", "") or "",
            record["sql"],
            "不通过" if findings else "通过",
            numbered(findings, "problem", "；"),
            numbered(findings, "suggestion", "\n"),
        ]
        refs = ["A", "B", "C", "D", "E", "F"]
        # Reuse the template's wrapped-data styles from example row 3.
        styles = [4, None, 4, None, 6, 5]
        row_cells = [cell(col, offset, shared_indices[value], style) for col, value, style in zip(refs, values, styles)]
        row_cells.append(blank_cell("G", offset))
        rows.append(f'<row r="{offset}" spans="1:7" ht="111">{"".join(row_cells)}</row>')
    xml = xml.replace("</sheetData>", "".join(rows) + "</sheetData>", 1)
    # Replace header values only; retain the template's header styles and layout.
    for column, header in zip("ABCDEFG", HEADERS):
        xml = re.sub(
            rf'(<c\s+r="{column}1"[^>]*>\s*<v>)\d+(</v>\s*</c>)',
            rf'\g<1>{shared_indices[header]}\g<2>',
            xml,
            count=1,
        )
    return xml


def update_summary_sheet(shared_indices: dict[str, int], summary: dict[str, list[tuple[str, int]]]) -> str:
    rows = [
        f'<row r="1" ht="24"><c r="A1" s="1" t="s"><v>{shared_indices[SUMMARY_TITLE]}</v></c></row>',
        f'<row r="3"><c r="A3" s="1" t="s"><v>{shared_indices["统计项"]}</v></c><c r="B3" s="1" t="s"><v>{shared_indices["数量"]}</v></c></row>',
    ]
    row_number = 4

    def append_rows(items: list[tuple[str, int]], header: tuple[str, str] | None = None) -> None:
        nonlocal row_number
        if header is not None:
            rows.append(
                f'<row r="{row_number}"><c r="A{row_number}" s="1" t="s"><v>{shared_indices[header[0]]}</v></c>'
                f'<c r="B{row_number}" s="1" t="s"><v>{shared_indices[header[1]]}</v></c></row>'
            )
            row_number += 1
        for label, count in items:
            rows.append(
                f'<row r="{row_number}">{cell("A", row_number, shared_indices[label], 4)}'
                f'{number_cell("B", row_number, count, 4)}</row>'
            )
            row_number += 1

    append_rows(summary["metrics"])
    row_number += 1
    append_rows(summary["database_types"], ("目标数据库类型", "SQL 数量"))
    row_number += 1
    append_rows(summary["rules"], ("规则 ID", "命中次数"))
    last_row = max(1, row_number - 1)
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<dimension ref="A1:B{last_row}"/>'
        '<sheetViews><sheetView workbookViewId="0"><selection activeCell="A1" sqref="A1"/>'
        '</sheetView></sheetViews><sheetFormatPr defaultRowHeight="15"/>'
        '<cols><col min="1" max="1" width="24" customWidth="1"/>'
        '<col min="2" max="2" width="14" customWidth="1"/></cols>'
        f'<sheetData>{"".join(rows)}</sheetData>'
        '<mergeCells count="1"><mergeCell ref="A1:B1"/></mergeCells>'
        '<pageMargins left="0.7" right="0.7" top="0.75" bottom="0.75" header="0.3" footer="0.3"/>'
        '</worksheet>'
    )


def update_workbook(xml: str, relationship_id: str) -> str:
    updated, count = re.subn(
        r'(<sheet\b[^>]*\bname=")[^"]*(")',
        rf'\g<1>{escape(SHEET_NAME, quote=True)}\g<2>',
        xml,
        count=1,
    )
    if count != 1:
        raise ValueError("template workbook does not contain a renameable worksheet")
    if f'name="{SUMMARY_SHEET_NAME}"' in updated:
        raise ValueError("template already contains the summary worksheet")
    return updated.replace(
        "</sheets>",
        f'<sheet name="{escape(SUMMARY_SHEET_NAME, quote=True)}" sheetId="2" r:id="{relationship_id}"/></sheets>',
        1,
    )


def update_workbook_relationships(xml: str) -> tuple[str, str]:
    relationship_ids = [int(value) for value in re.findall(r'\bId="rId(\d+)"', xml)]
    relationship_id = f"rId{max(relationship_ids, default=0) + 1}"
    relationship = (
        f'<Relationship Id="{relationship_id}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet2.xml"/>'
    )
    if "worksheets/sheet2.xml" in xml:
        raise ValueError("template already defines xl/worksheets/sheet2.xml")
    return xml.replace("</Relationships>", relationship + "</Relationships>", 1), relationship_id


def update_content_types(xml: str) -> str:
    if 'PartName="/xl/worksheets/sheet2.xml"' in xml:
        raise ValueError("template already defines a content type for summary worksheet")
    override = (
        '<Override PartName="/xl/worksheets/sheet2.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
    )
    return xml.replace("</Types>", override + "</Types>", 1)


def update_app_properties(xml: str) -> str:
    xml = xml.replace("<vt:i4>1</vt:i4>", "<vt:i4>2</vt:i4>", 1)
    return re.sub(
        r'(<TitlesOfParts><vt:vector size=")1(" baseType="lpstr"><vt:lpstr>)[^<]*(</vt:lpstr>)(</vt:vector></TitlesOfParts>)',
        rf'\g<1>2\g<2>{SHEET_NAME}\g<3><vt:lpstr>{SUMMARY_SHEET_NAME}</vt:lpstr>\g<4>',
        xml,
        count=1,
    )


def render(template: str, output: str, records: list[dict]) -> None:
    summary = build_summary(records)
    values = list(HEADERS)
    for record in records:
        values.extend([
            record["source"], record.get("database_type", "") or "", record["sql"],
            "不通过" if record.get("findings") else "通过",
            numbered(record.get("findings", []), "problem", "；"),
            numbered(record.get("findings", []), "suggestion", "\n"),
        ])
    values.extend(summary_strings(summary))
    with zipfile.ZipFile(template, "r") as source:
        files = {name: source.read(name) for name in source.namelist()}
    shared, indices = update_shared_strings(files["xl/sharedStrings.xml"].decode("utf-8"), values)
    # Values are appended in order; use the last occurrence's index for duplicate strings.
    shared_indices: dict[str, int] = {}
    for value, index in zip(values, indices):
        shared_indices[value] = index
    sheet = update_sheet(files["xl/worksheets/sheet1.xml"].decode("utf-8"), shared_indices, records)
    relationships, relationship_id = update_workbook_relationships(files["xl/_rels/workbook.xml.rels"].decode("utf-8"))
    workbook = update_workbook(files["xl/workbook.xml"].decode("utf-8"), relationship_id)
    files["xl/sharedStrings.xml"] = shared.encode("utf-8")
    files["xl/worksheets/sheet1.xml"] = sheet.encode("utf-8")
    files["xl/worksheets/sheet2.xml"] = update_summary_sheet(shared_indices, summary).encode("utf-8")
    files["xl/workbook.xml"] = workbook.encode("utf-8")
    files["xl/_rels/workbook.xml.rels"] = relationships.encode("utf-8")
    files["[Content_Types].xml"] = update_content_types(files["[Content_Types].xml"].decode("utf-8")).encode("utf-8")
    files["docProps/app.xml"] = update_app_properties(files["docProps/app.xml"].decode("utf-8")).encode("utf-8")
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as target:
        for name, data in files.items():
            target.writestr(name, data)


def validate(path: str, expected_records: int) -> None:
    with zipfile.ZipFile(path) as archive:
        sheet = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
        summary = archive.read("xl/worksheets/sheet2.xml").decode("utf-8")
        shared = archive.read("xl/sharedStrings.xml").decode("utf-8")
        workbook = archive.read("xl/workbook.xml").decode("utf-8")
    if f'name="{SHEET_NAME}"' not in workbook:
        raise ValueError(f"workbook does not contain sheet {SHEET_NAME}")
    if f'name="{SUMMARY_SHEET_NAME}"' not in workbook:
        raise ValueError(f"workbook does not contain sheet {SUMMARY_SHEET_NAME}")
    entries = re.findall(r"<si\b.*?</si>", shared, flags=re.S)
    strings = []
    for entry in entries:
        strings.append("".join(re.findall(r"<t[^>]*>(.*?)</t>", entry, flags=re.S)))
    actual_headers = []
    for column in "ABCDEFG":
        header_match = re.search(rf'<c\s+r="{column}1"[^>]*>\s*<v>(\d+)</v>', sheet)
        if not header_match or int(header_match.group(1)) >= len(strings):
            raise ValueError(f"column {column} header is missing or invalid")
        actual_headers.append(strings[int(header_match.group(1))])
    if actual_headers != HEADERS:
        raise ValueError(f"workbook headers do not match the required contract: {actual_headers}")
    rows = re.findall(r'<row\s+r="(\d+)"', sheet)
    data_rows = [row for row in rows if int(row) >= 2]
    if len(data_rows) != expected_records:
        raise ValueError(f"workbook has {len(data_rows)} data rows; expected {expected_records}")
    if f'<v>{strings.index(SUMMARY_TITLE)}</v>' not in summary:
        raise ValueError("summary worksheet title is missing")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()
    try:
        records = load_records(args.input)
        render(args.template, args.output, records)
        if args.validate:
            validate(args.output, len(records))
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        print(f"sql-audit report error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"output": args.output, "records": len(records), "validated": args.validate}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
