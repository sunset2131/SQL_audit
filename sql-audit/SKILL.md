---
name: sql-audit
description: Audit SQL embedded in an uploaded code archive and produce the exact SQL review workbook requested by the user. Use this skill whenever a user submits or mentions a JAR, WAR, EAR, ZIP, TAR/TGZ, or other archive containing code and asks to extract, review, check, or audit SQL, database changes, MyBatis statements, JDBC queries, or embedded SQL. It also applies when the user does not say "sql-audit" but needs a rule-based SQL review workbook. Do not use it for decompiling class files, generic database design advice, or audits without a code archive.
compatibility: Python 3.9+; standard library only for archive/SQL extraction and XLSX writing. Optional 7z/RAR command-line tools enable those archive formats.
---

# SQL Audit

Use this skill for a code archive that may contain SQL. The final deliverable is an `.xlsx` workbook based on the bundled `assets/应用代码扫描结果模板.xlsx` template. Scan the archive comprehensively, while keeping the audit itself deliberately narrow: the only audit rules are in `references/rule.md`; do not add generic SQL best practices or rules from memory.

## Contract

- Scan every complete SQL occurrence in the application archive, including SQL under mapper, migration, seed, configuration, and source-code paths. Include DDL so it can be evaluated by the bundled rules.
- Never decompile, inspect, or infer SQL from `.class` files. Skip `.class` and binary files.
- Never restrict scanning to `mappers/` or filter a candidate solely because its path contains `db/migration`, `flyway`, `seed`, or a similar directory name.
- Supported native archives are ZIP/JAR/WAR/EAR/TAR/TAR.GZ/TGZ. Use 7z/RAR only when the matching system tool exists.
- Process every nested archive up to the helper's safety limits, including archives under dependency locations such as `BOOT-INF/lib` and `WEB-INF/lib`; preserve the full nested source path.
- Keep every SQL occurrence. Do not deduplicate identical statements.
- Every SQL occurrence becomes one row in the `应用代码扫描结果` worksheet. Its seven headers must be exactly `代码文件`, `目标数据库类型`, `原SQL`, `审核结果`, `存在问题`, `处理建议`, and `人工复核结果`. The workbook must contain exactly three worksheets: `应用代码扫描结果`, `汇总信息`, and `规则列表`.
- Write the SQL totals, pass/fail counts, per-database counts, and matched-rule counts into the existing `汇总信息` worksheet. Preserve the existing `规则列表` worksheet byte-for-byte from the approved template; do not populate, clear, reorder, or restyle it.
- Prefer a user-supplied database type. Otherwise infer only `Oracle`, `Mysql`, `Kingbase`, `Gbase`, or `Gaussdb` from source/config/SQL evidence. If no supported type matches, leave the cell blank.
- Any finding makes `审核结果` `不通过`, including advisory `BUS-006`.
- Leave `人工复核结果` blank.

## Workflow

### 1. Locate and extract candidates

Use the bundled helper instead of manually unpacking files:

```text
python <skill-dir>/scripts/extract_sql.py \
  --input <archive> \
  --output <working-dir>/sql-candidates.json \
  [--db-type Oracle|Mysql|Kingbase|Gbase|Gaussdb]
```

The helper records `source`, `line`, `sql`, `database_type`, and `extractor` for each occurrence. It also records skipped-file warnings in the JSON. A candidate is emitted only when a complete statement can be recovered. Dynamic fragments that cannot be reconstructed are skipped; do not invent values or a final SQL string.

Treat the extractor output as the full audit population. Remove a candidate only when inspection confirms that it is a non-SQL false positive or an incomplete statement; record that removal and its reason in the final message. Directory or file naming is never sufficient reason to exclude a complete SQL statement.

### 2. Audit candidates using only the rules

Read `references/rule.md` completely before auditing. For each candidate, apply every rule present in that file and do not substitute or add other rules.

Create an audit JSON file with this shape:

```json
{
  "records": [
    {
      "source": "BOOT-INF/classes/mapper/User.xml",
      "line": 42,
      "sql": "SELECT id FROM user WHERE name = :name",
      "database_type": "Mysql",
      "findings": [
        {
          "rule_id": "BUS-006",
          "problem": "负向查询风险：使用了NOT IN，可能导致索引利用不足；位置：WHERE条件。",
          "suggestion": "优先改写为正向条件；无法改写时补充执行计划、数据量和业务必要性供二次确认。"
        }
      ]
    }
  ]
}
```

Use the rule's prescribed problem and suggestion wording, replacing only placeholders such as `<operator>`, `<function>`, and concrete contradiction descriptions. Keep findings in rule order and do not report the same rule twice for one SQL unless distinct violations are necessary to explain the statement.

Important interpretations:

- `BUS-006` is advisory in the source rule but still makes the row `不通过` for this workflow.
- Complete DDL statements remain in the population and are evaluated against `BUS-001`; do not remove them before auditing.
- `BUS-004` concerns business parameters and bound placeholders. Do not claim a literal is a violation when it is a structural SQL keyword, a type-safe SQL clause, or a clearly non-business constant; explain the evidence.
- For dynamic SQL, preserve the original dynamic structure. If the full statement cannot be recovered, omit it and report the source path and reason outside the workbook.
- Do not treat extraction failures as SQL-rule findings.

### 3. Write the workbook

Run the writer against the bundled template. The `--template` option is optional; when omitted, the writer always uses `assets/应用代码扫描结果模板.xlsx` located beside this skill. Do not recreate the workbook with a different layout or styling.

```text
python <skill-dir>/scripts/write_report.py \
  --template <skill-dir>/assets/应用代码扫描结果模板.xlsx \
  --input <working-dir>/sql-audit.json \
  --output <working-dir>/应用代码扫描结果.xlsx
```

The writer removes the example data rows from the detail worksheet, replaces all seven headers with the exact short labels in the contract, appends one row per input record, derives `审核结果` from whether `findings` is non-empty, numbers problems and suggestions, and leaves the manual-review column empty. It replaces the contents of the existing `汇总信息` worksheet with SQL total, pass/fail counts, database-type counts (blank types are shown as `未识别` only in the summary), and matched-rule counts. It leaves `规则列表` untouched. With zero records it writes a valid three-sheet workbook. It rejects malformed audit JSON and SQL cells longer than the Excel cell limit rather than truncating them.

The workbook's visual output is template-controlled: the writer validates the three-sheet contract and exact seven headers, copies the template's example row 3 height and per-column cell styles to every generated detail row, and preserves the template's `规则列表` worksheet unchanged. Style IDs are never invented by the writer, so changing the approved template is the only supported way to change report appearance.

### 4. Report completion and limitations

Return the workbook path and summarize skipped files, unrecognized database types, and any overlong SQL separately. Do not add those notices as extra workbook rows. If the archive is corrupt, unsafe, or unsupported, stop without creating a report and state the actionable error.

## Quality Gate

Before handing off, verify the result with the writer's `--validate` mode or by reopening the workbook with an independent spreadsheet reader. Confirm the workbook has exactly `应用代码扫描结果`, `汇总信息`, and `规则列表`, the detail headers exactly match the contract and contain no parenthetical explanations, the number of detail rows equals the number of audit records, every detail row has an empty column G, the `规则列表` worksheet is unchanged from the template, and the summary totals reconcile with the detail rows.
