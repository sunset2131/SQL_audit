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
- Write the SQL total, pass/advisory/fail counts, and matched-rule counts into the existing `汇总信息` worksheet. Preserve the existing `规则列表` worksheet byte-for-byte from the approved template; do not populate, clear, reorder, or restyle it.
- Prefer a user-supplied database type. Otherwise infer only `Oracle`, `Mysql`, `Kingbase`, `Gbase`, or `Gaussdb` from source/config/SQL evidence. If no supported type matches, leave the cell blank.
- Derive each row's `审核结果` from the rule levels in the template's `规则列表`: any `硬性` finding makes the result `不通过`; findings that are all `建议` make it `建议`; no findings make it `通过`.
- Copy the template's result-cell styles so `不通过` is red, `建议` is yellow, and `通过` is green. Do not invent color values in the writer.
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

Read `references/rule.md` completely before auditing. The bundled rule reference mirrors the approved template's 14 rules. Apply every rule present there and do not substitute, weaken, or add other rules. The template's `规则列表` is the runtime authority for each rule's level, exact `存在问题` text, exact `处理建议` text, and rule order.

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
        {"rule_id": "BUS-006"}
      ]
    }
  ]
}
```

Use only the exact `存在问题` and `处理建议` text from the matching row in the template's `规则列表` (columns H and I). For `存在问题` only, append the matching rule level immediately after the template text as `【硬性】` or `【建议】`; do not add any other wording. Keep `处理建议` exactly equal to the template text. Do not copy model-written wording from the audit JSON, add explanations, append evidence, or lengthen either field. The audit JSON may provide only `rule_id`; the writer fills the two output fields from the template. Keep findings in template rule order and report each rule at most once per SQL.

Important interpretations:

- A finding's output severity is controlled by the matching rule level in the approved template. The audit JSON does not need to duplicate that level.
- When one SQL matches several rules, number `存在问题` as `1. <template problem>【硬性/建议】；2. <template problem>【硬性/建议】` and number `处理建议` as `1. ...\n2. ...`, preserving the template rule order. With no findings, write `无` in both fields.
- Audit every SQL against all 14 rules before writing findings. Do not stop after the first match. In particular, a `SELECT *` statement can also match `BUS-002` when its effective WHERE is absent, `BUS-004` for hard-coded values, and/or `BUS-006` for negative predicates; a `DELETE` or `UPDATE` can also match `BUS-002` when its effective WHERE is absent or only `WHERE 1=1`.
- Treat `?`, `:name`, `$1`, and MyBatis `#{item}` or `#{object.property}` (including optional type metadata after a comma) as bound placeholders for `BUS-004`. Do not report these as hard-coded constants. MyBatis `${item}` is string substitution, not a bound placeholder, and remains subject to `BUS-004` when it represents a business value.
- For MyBatis XML, inspect expanded `<include refid="..."/>` fragments. The extractor expands fragments defined in the same XML file; if an include or dynamic branch cannot be resolved, preserve it in the SQL and do not assume that it supplies a valid WHERE condition. Under the approved BUS-002 text, `SELECT`, `DELETE`, and `UPDATE` without an effective WHERE are findings; use the exact BUS-002 template wording in the report.
- Complete DDL statements remain in the population and are evaluated against `BUS-001`; do not remove them before auditing.
- `BUS-004` concerns business parameters and bound placeholders. Do not claim a literal is a violation when it is a structural SQL keyword, a type-safe SQL clause, or a clearly non-business constant. Use the evidence only to make the internal decision; never append it to `存在问题` or `处理建议`.
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

The writer removes the three example data rows from the detail worksheet and uses them as the green, yellow, and red style prototypes. It appends one row per input record, resolves each finding's level and exact problem/suggestion text from the template's `规则列表`, discards any model-supplied problem/suggestion wording, applies hard-over-advisory precedence, numbers multiple findings in rule order, and leaves the manual-review column empty. It replaces the contents of the existing `汇总信息` worksheet with SQL total, pass/advisory/fail counts and matched-rule counts. It leaves `规则列表` untouched. With zero records it writes a valid three-sheet workbook. It rejects malformed audit JSON, findings whose rule ID is absent from the template, output text outside the template rule vocabulary, and SQL cells longer than the Excel cell limit rather than truncating them.

The workbook's visual output is template-controlled: the writer validates the three-sheet contract, exact seven headers, the three result-style prototypes, and the `规则编号`/`规则级别` columns. It copies the template's normal cell styles plus the matching green/yellow/red result style to every generated detail row, retains the summary sheet's template styles, and preserves the template's `规则列表` worksheet unchanged. Style IDs are never invented by the writer, so changing the approved template is the supported way to change report appearance.

### 4. Report completion and limitations

Return the workbook path and summarize skipped files, unrecognized database types, and any overlong SQL separately. Do not add those notices as extra workbook rows. If the archive is corrupt, unsafe, or unsupported, stop without creating a report and state the actionable error.

## Quality Gate

Before handing off, verify the result with the writer's `--validate` mode or by reopening the workbook with an independent spreadsheet reader. Confirm the workbook has exactly `应用代码扫描结果`, `汇总信息`, and `规则列表`; the detail headers exactly match the contract; each result is `通过`, `建议`, or `不通过` with the template's green, yellow, or red style; every non-empty `存在问题` and `处理建议` item is an exact template rule string with only the required numeric prefix; multi-rule rows are numbered in template order; the number of detail rows equals the number of audit records; every detail row has an empty column G; the `规则列表` worksheet is unchanged from the template; and the total/pass/advisory/fail summary counts reconcile with the detail rows.
