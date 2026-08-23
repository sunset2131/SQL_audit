#!/usr/bin/env python3
"""Write SQL audit JSON into the supplied XLSX template without reformatting it."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import zipfile
from html import escape, unescape


MAX_CELL_LENGTH = 32_767
DEFAULT_TEMPLATE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "assets",
    "应用代码扫描结果模板.xlsx",
)
SHEET_NAME = "应用代码扫描结果"
SUMMARY_SHEET_NAME = "汇总信息"
RULES_SHEET_NAME = "规则列表"
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
RESULT_PASS = "通过"
RESULT_ADVISORY = "建议"
RESULT_FAIL = "不通过"
RULE_LEVEL_HARD = "硬性"
RULE_LEVEL_ADVISORY = "建议"


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


def read_shared_strings(xml: str) -> list[str]:
    values = []
    for entry in re.findall(r"<si\b.*?</si>", xml, flags=re.S):
        values.append(unescape("".join(re.findall(r"<t[^>]*>(.*?)</t>", entry, flags=re.S))))
    return values


def shared_cell_value(sheet_xml: str, address: str, strings: list[str]) -> str:
    match = re.search(rf'<c\s+r="{address}"[^>]*\bt="s"[^>]*>\s*<v>(\d+)</v>', sheet_xml)
    if not match or int(match.group(1)) >= len(strings):
        raise ValueError(f"template cell {address} is missing or is not a valid shared string")
    return strings[int(match.group(1))]


def cell_attributes(row_xml: str, address: str) -> str:
    match = re.search(rf'<c\s+r="{address}"(?P<attrs>[^>]*)/?>', row_xml)
    if not match:
        raise ValueError(f"template example cell {address} is missing")
    attrs = match.group("attrs").rstrip("/")
    return re.sub(r'\s+t="[^"]*"', "", attrs)


def row_prototype(sheet_xml: str, row_number: int) -> tuple[str, str]:
    match = re.search(
        rf'<row\s+r="{row_number}"(?P<attrs>[^>]*)>(?P<body>.*?)</row>',
        sheet_xml,
        flags=re.S,
    )
    if not match:
        raise ValueError(f"template must contain example row {row_number}")
    return match.group("attrs"), match.group(0)


def template_prototypes(
    sheet_xml: str,
    shared_xml: str,
) -> tuple[str, dict[str, str], dict[str, str]]:
    """Validate the detail contract and return base and result-style prototypes."""
    strings = read_shared_strings(shared_xml)
    header_values = [shared_cell_value(sheet_xml, f"{column}1", strings) for column in "ABCDEFG"]
    if header_values != HEADERS:
        raise ValueError(f"template headers do not match the required contract: {header_values}")

    pass_row_attrs, pass_row = row_prototype(sheet_xml, 2)
    _, advisory_row = row_prototype(sheet_xml, 3)
    _, fail_row = row_prototype(sheet_xml, 4)
    prototypes = {column: cell_attributes(pass_row, f"{column}2") for column in "ABCDEFG"}
    result_prototypes = {
        RESULT_PASS: cell_attributes(pass_row, "D2"),
        RESULT_ADVISORY: cell_attributes(advisory_row, "D3"),
        RESULT_FAIL: cell_attributes(fail_row, "D4"),
    }
    if len(set(result_prototypes.values())) != 3:
        raise ValueError("template result cells D2:D4 must define distinct green, yellow, and red styles")
    return pass_row_attrs, prototypes, result_prototypes


def read_rule_levels(rules_xml: str, shared_xml: str) -> dict[str, str]:
    """Read rule levels from columns A and C of the template's rules worksheet."""
    strings = read_shared_strings(shared_xml)
    if shared_cell_value(rules_xml, "A1", strings) != "规则编号":
        raise ValueError("template rules worksheet column A must be 规则编号")
    if shared_cell_value(rules_xml, "C1", strings) != "规则级别":
        raise ValueError("template rules worksheet column C must be 规则级别")

    levels: dict[str, str] = {}
    for row_number in re.findall(r'<row\s+r="(\d+)"', rules_xml):
        if int(row_number) < 2:
            continue
        rule_id = shared_cell_value(rules_xml, f"A{row_number}", strings).strip()
        level = shared_cell_value(rules_xml, f"C{row_number}", strings).strip()
        if level not in {RULE_LEVEL_HARD, RULE_LEVEL_ADVISORY}:
            raise ValueError(f"template rule {rule_id} has unsupported level {level}")
        if rule_id in levels:
            raise ValueError(f"template rules worksheet contains duplicate rule {rule_id}")
        levels[rule_id] = level
    if not levels:
        raise ValueError("template rules worksheet contains no rules")
    return levels


def audit_result(record: dict, rule_levels: dict[str, str]) -> str:
    levels = []
    for finding in record.get("findings", []):
        rule_id = str(finding["rule_id"])
        if rule_id not in rule_levels:
            raise ValueError(f"finding references rule {rule_id}, which is absent from the template")
        levels.append(rule_levels[rule_id])
    if RULE_LEVEL_HARD in levels:
        return RESULT_FAIL
    if RULE_LEVEL_ADVISORY in levels:
        return RESULT_ADVISORY
    return RESULT_PASS


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


def build_summary(records: list[dict], rule_levels: dict[str, str]) -> dict[str, list[tuple[str, int]]]:
    rule_counts: dict[str, int] = {}
    result_counts = {RESULT_PASS: 0, RESULT_ADVISORY: 0, RESULT_FAIL: 0}
    for record in records:
        result_counts[audit_result(record, rule_levels)] += 1
        findings = record.get("findings", [])
        for finding in findings:
            rule_id = str(finding["rule_id"])
            rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1

    def rule_sort_key(item: tuple[str, int]) -> tuple[int, str]:
        match = re.fullmatch(r"BUS-(\d+)", item[0])
        return (int(match.group(1)), item[0]) if match else (sys.maxsize, item[0])

    return {
        "metrics": [
            ("SQL 总数", len(records)),
            ("通过数", result_counts[RESULT_PASS]),
            ("建议数", result_counts[RESULT_ADVISORY]),
            ("不通过数", result_counts[RESULT_FAIL]),
        ],
        "rules": sorted(rule_counts.items(), key=rule_sort_key),
    }


def summary_strings(summary: dict[str, list[tuple[str, int]]]) -> list[str]:
    values = [SUMMARY_TITLE, "统计项", "数量"]
    values.extend(label for label, _ in summary["metrics"])
    values.extend(["规则 ID", "命中次数"])
    values.extend(label for label, _ in summary["rules"])
    return values


def template_cell(column: str, row: int, string_index: int, attrs: str) -> str:
    return f'<c r="{column}{row}"{attrs} t="s"><v>{string_index}</v></c>'


def template_blank_cell(column: str, row: int, attrs: str) -> str:
    return f'<c r="{column}{row}"{attrs}/>'


def template_number_cell(column: str, row: int, value: int, attrs: str) -> str:
    return f'<c r="{column}{row}"{attrs}><v>{value}</v></c>'


def update_sheet(
    xml: str,
    shared_indices: dict[str, int],
    records: list[dict],
    results: list[str],
    row_attrs: str,
    prototypes: dict[str, str],
    result_prototypes: dict[str, str],
) -> str:
    xml = re.sub(r'<dimension\b[^>]*/>', f'<dimension ref="A1:G{max(1, len(records) + 1)}"/>', xml, count=1)
    xml = re.sub(r'<row\s+r="(?!1")\d+"[^>]*>.*?</row>', "", xml, flags=re.S)
    rows = []
    for offset, (record, result) in enumerate(zip(records, results), 2):
        findings = record.get("findings", [])
        values = [
            record["source"],
            record.get("database_type", "") or "",
            record["sql"],
            result,
            numbered(findings, "problem", "；"),
            numbered(findings, "suggestion", "\n"),
        ]
        row_cells = []
        for column, value in zip("ABCDEF", values):
            attrs = result_prototypes[result] if column == "D" else prototypes[column]
            row_cells.append(template_cell(column, offset, shared_indices[value], attrs))
        row_cells.append(template_blank_cell("G", offset, prototypes["G"]))
        rows.append(f'<row r="{offset}"{row_attrs}>{"".join(row_cells)}</row>')
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


def update_summary_sheet(
    xml: str,
    shared_indices: dict[str, int],
    summary: dict[str, list[tuple[str, int]]],
) -> str:
    title_attrs, title_row = row_prototype(xml, 1)
    metric_header_attrs, metric_header_row = row_prototype(xml, 3)
    metric_attrs, metric_row = row_prototype(xml, 4)
    rule_header_attrs, rule_header_row = row_prototype(xml, 9)
    rows = [
        f'<row r="1"{title_attrs}>{template_cell("A", 1, shared_indices[SUMMARY_TITLE], cell_attributes(title_row, "A1"))}'
        f'{template_blank_cell("B", 1, cell_attributes(title_row, "B1"))}</row>',
        f'<row r="3"{metric_header_attrs}>'
        f'{template_cell("A", 3, shared_indices["统计项"], cell_attributes(metric_header_row, "A3"))}'
        f'{template_cell("B", 3, shared_indices["数量"], cell_attributes(metric_header_row, "B3"))}</row>',
    ]
    row_number = 4
    metric_a_attrs = cell_attributes(metric_row, "A4")
    metric_b_attrs = cell_attributes(metric_row, "B4")
    for label, count in summary["metrics"]:
        rows.append(
            f'<row r="{row_number}"{metric_attrs}>'
            f'{template_cell("A", row_number, shared_indices[label], metric_a_attrs)}'
            f'{template_number_cell("B", row_number, count, metric_b_attrs)}</row>'
        )
        row_number += 1

    rows.append(
        f'<row r="9"{rule_header_attrs}>'
        f'{template_cell("A", 9, shared_indices["规则 ID"], cell_attributes(rule_header_row, "A9"))}'
        f'{template_cell("B", 9, shared_indices["命中次数"], cell_attributes(rule_header_row, "B9"))}</row>'
    )
    row_number = 10
    for label, count in summary["rules"]:
        rows.append(
            f'<row r="{row_number}"{metric_attrs}>'
            f'{template_cell("A", row_number, shared_indices[label], metric_a_attrs)}'
            f'{template_number_cell("B", row_number, count, metric_b_attrs)}</row>'
        )
        row_number += 1

    last_row = max(9, row_number - 1)
    xml = re.sub(r'<dimension\b[^>]*/>', f'<dimension ref="A1:B{last_row}"/>', xml, count=1)
    return re.sub(
        r'<sheetData>.*?</sheetData>',
        f'<sheetData>{"".join(rows)}</sheetData>',
        xml,
        count=1,
        flags=re.S,
    )


def update_workbook(xml: str) -> str:
    sheet_names = re.findall(r'<sheet\b[^>]*\bname="([^"]*)"', xml)
    if sheet_names != ["审核结果", SUMMARY_SHEET_NAME, RULES_SHEET_NAME]:
        raise ValueError(
            "template worksheets must be 审核结果, 汇总信息, 规则列表"
        )
    updated, count = re.subn(
        r'(<sheet\b[^>]*\bname=")[^"]*(")',
        rf'\g<1>{escape(SHEET_NAME, quote=True)}\g<2>',
        xml,
        count=1,
    )
    if count != 1:
        raise ValueError("template workbook does not contain a renameable worksheet")
    return updated


def update_app_properties(xml: str) -> str:
    """Keep the template's three-sheet metadata while renaming the detail tab."""
    return xml.replace(
        "<vt:lpstr>审核结果</vt:lpstr>",
        f"<vt:lpstr>{escape(SHEET_NAME)}</vt:lpstr>",
        1,
    )


def render(template: str, output: str, records: list[dict]) -> None:
    with zipfile.ZipFile(template, "r") as source:
        files = {name: source.read(name) for name in source.namelist()}
    required_files = {
        "xl/workbook.xml",
        "xl/worksheets/sheet1.xml",
        "xl/worksheets/sheet2.xml",
        "xl/worksheets/sheet3.xml",
        "xl/sharedStrings.xml",
    }
    missing = sorted(required_files.difference(files))
    if missing:
        raise ValueError(f"template is missing required files: {', '.join(missing)}")
    shared_xml = files["xl/sharedStrings.xml"].decode("utf-8")
    rule_levels = read_rule_levels(
        files["xl/worksheets/sheet3.xml"].decode("utf-8"),
        shared_xml,
    )
    results = [audit_result(record, rule_levels) for record in records]
    summary = build_summary(records, rule_levels)
    values = list(HEADERS)
    for record, result in zip(records, results):
        values.extend([
            record["source"], record.get("database_type", "") or "", record["sql"],
            result,
            numbered(record.get("findings", []), "problem", "；"),
            numbered(record.get("findings", []), "suggestion", "\n"),
        ])
    values.extend(summary_strings(summary))
    row_attrs, prototypes, result_prototypes = template_prototypes(
        files["xl/worksheets/sheet1.xml"].decode("utf-8"),
        shared_xml,
    )
    shared, indices = update_shared_strings(shared_xml, values)
    # Values are appended in order; use the last occurrence's index for duplicate strings.
    shared_indices: dict[str, int] = {}
    for value, index in zip(values, indices):
        shared_indices[value] = index
    sheet = update_sheet(
        files["xl/worksheets/sheet1.xml"].decode("utf-8"),
        shared_indices,
        records,
        results,
        row_attrs,
        prototypes,
        result_prototypes,
    )
    workbook = update_workbook(files["xl/workbook.xml"].decode("utf-8"))
    files["xl/sharedStrings.xml"] = shared.encode("utf-8")
    files["xl/worksheets/sheet1.xml"] = sheet.encode("utf-8")
    files["xl/worksheets/sheet2.xml"] = update_summary_sheet(
        files["xl/worksheets/sheet2.xml"].decode("utf-8"),
        shared_indices,
        summary,
    ).encode("utf-8")
    files["xl/workbook.xml"] = workbook.encode("utf-8")
    files["docProps/app.xml"] = update_app_properties(files["docProps/app.xml"].decode("utf-8")).encode("utf-8")
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as target:
        for name, data in files.items():
            target.writestr(name, data)


def validate(path: str, expected_records: int, template: str = DEFAULT_TEMPLATE) -> None:
    with zipfile.ZipFile(path) as archive:
        sheet = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
        summary = archive.read("xl/worksheets/sheet2.xml").decode("utf-8")
        rules = archive.read("xl/worksheets/sheet3.xml")
        shared = archive.read("xl/sharedStrings.xml").decode("utf-8")
        workbook = archive.read("xl/workbook.xml").decode("utf-8")
    with zipfile.ZipFile(template) as template_archive:
        template_sheet = template_archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
        template_rules = template_archive.read("xl/worksheets/sheet3.xml")
        template_shared = template_archive.read("xl/sharedStrings.xml").decode("utf-8")
    _, _, result_prototypes = template_prototypes(template_sheet, template_shared)
    if f'name="{SHEET_NAME}"' not in workbook:
        raise ValueError(f"workbook does not contain sheet {SHEET_NAME}")
    if f'name="{SUMMARY_SHEET_NAME}"' not in workbook:
        raise ValueError(f"workbook does not contain sheet {SUMMARY_SHEET_NAME}")
    if f'name="{RULES_SHEET_NAME}"' not in workbook:
        raise ValueError(f"workbook does not contain sheet {RULES_SHEET_NAME}")
    if workbook.count("<sheet ") != 3:
        raise ValueError("workbook must contain exactly three worksheets")
    if rules != template_rules:
        raise ValueError("rules worksheet differs from the approved template")
    strings = read_shared_strings(shared)
    actual_headers = [shared_cell_value(sheet, f"{column}1", strings) for column in "ABCDEFG"]
    if actual_headers != HEADERS:
        raise ValueError(f"workbook headers do not match the required contract: {actual_headers}")
    rows = re.findall(r'<row\s+r="(\d+)"', sheet)
    data_rows = [row for row in rows if int(row) >= 2]
    if len(data_rows) != expected_records:
        raise ValueError(f"workbook has {len(data_rows)} data rows; expected {expected_records}")
    result_counts = {RESULT_PASS: 0, RESULT_ADVISORY: 0, RESULT_FAIL: 0}
    for row_number in data_rows:
        row_match = re.search(
            rf'<row\s+r="{row_number}"[^>]*>(?P<body>.*?)</row>',
            sheet,
            flags=re.S,
        )
        if not row_match:
            raise ValueError(f"detail row {row_number} is missing")
        result = shared_cell_value(sheet, f"D{row_number}", strings)
        if result not in result_counts:
            raise ValueError(f"row {row_number} has invalid audit result {result}")
        result_counts[result] += 1
        result_attrs = cell_attributes(row_match.group(0), f"D{row_number}")
        if result_attrs != result_prototypes[result]:
            raise ValueError(f"row {row_number} audit-result style does not match {result}")
        manual_cell = re.search(rf'<c\s+r="G{row_number}"(?:\s|/|>)', row_match.group("body"))
        manual_value = re.search(
            rf'<c\s+r="G{row_number}"[^>]*>.*?<v>',
            row_match.group("body"),
            flags=re.S,
        )
        if not manual_cell or manual_value:
            raise ValueError(f"row {row_number} manual-review cell must be blank")
    title_indices = [index for index, value in enumerate(strings) if value == SUMMARY_TITLE]
    if not any(f'<v>{index}</v>' in summary for index in title_indices):
        raise ValueError("summary worksheet title is missing")
    expected_metrics = {
        "SQL 总数": expected_records,
        "通过数": result_counts[RESULT_PASS],
        "建议数": result_counts[RESULT_ADVISORY],
        "不通过数": result_counts[RESULT_FAIL],
    }
    for row_number, (label, expected) in enumerate(expected_metrics.items(), 4):
        if shared_cell_value(summary, f"A{row_number}", strings) != label:
            raise ValueError(f"summary row {row_number} must contain {label}")
        value_match = re.search(rf'<c\s+r="B{row_number}"[^>]*>\s*<v>(\d+)</v>', summary)
        if not value_match or int(value_match.group(1)) != expected:
            raise ValueError(f"summary metric {label} does not reconcile with detail rows")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", default=DEFAULT_TEMPLATE)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()
    try:
        records = load_records(args.input)
        render(args.template, args.output, records)
        if args.validate:
            validate(args.output, len(records), args.template)
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        print(f"sql-audit report error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"output": args.output, "records": len(records), "validated": args.validate}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
