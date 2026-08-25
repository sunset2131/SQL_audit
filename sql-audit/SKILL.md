---
name: sql-audit
description: Audit SQL embedded in an uploaded code archive and produce the exact SQL review workbook requested by the user. Always use this skill whenever the user mentions sql-audit, write_report.py, sql-audit.json, 应用代码扫描结果.xlsx, 应用代码扫描结果模板.xlsx, template validation, a template fingerprint mismatch, an XLSX/ZIP validation error, or asks to run or diagnose the bundled SQL report writer, even if the user does not explicitly mention an archive audit. Also use it whenever a user submits or mentions a JAR, WAR, EAR, ZIP, TAR/TGZ, or other archive containing code and asks to extract, review, check, or audit SQL, database changes, MyBatis statements, JDBC queries, or embedded SQL. Do not use it for decompiling class files, generic database design advice, or audits without a code archive.
compatibility: Python 3.9+; standard library only for archive extraction, deterministic SQL auditing, and XLSX writing. Optional 7z/RAR command-line tools enable those archive formats.
---

# SQL Audit

Use this skill for a code archive that may contain SQL. The final deliverable is an `.xlsx` workbook based on the bundled `assets/应用代码扫描结果模板.xlsx` template. Scan the archive comprehensively, while keeping the audit itself deliberately narrow: the only audit rules are in `references/rule.md`; do not add generic SQL best practices or rules from memory. The audit decision is deterministic and script-owned: after extraction, always run `scripts/audit_sql.py`; never hand-write, infer, reorder, remove, or supplement `findings` in the audit JSON.

## Contract

- Scan every complete SQL occurrence in the application archive, including SQL under mapper, migration, seed, configuration, and source-code paths. Include DDL so it can be evaluated by the bundled rules.
- Never decompile, inspect, or infer SQL from `.class` files. Skip `.class` and binary files.
- Never restrict scanning to `mappers/` or filter a candidate solely because its path contains `db/migration`, `flyway`, `seed`, or a similar directory name.
- Supported native archives are ZIP/JAR/WAR/EAR/TAR/TAR.GZ/TGZ. Use 7z/RAR only when the matching system tool exists.
- Process every nested archive up to the helper's safety limits, including archives under dependency locations such as `BOOT-INF/lib` and `WEB-INF/lib`; preserve the full nested source path.
- Keep every SQL occurrence. Do not deduplicate identical statements.
- Every SQL occurrence becomes one row in the `应用代码扫描结果` worksheet. Its seven headers must be exactly `代码文件`, `目标数据库类型`, `原SQL`, `审核结果`, `存在问题`, `处理建议`, and `人工复核结果`. The workbook must contain exactly three worksheets: `应用代码扫描结果`, `汇总信息`, and `规则列表`.
- Because the approved template has no separate line-number column, write the extractor's SQL start line in the `代码文件` cell as `source（第N行）`; if no valid line number is available, keep the source path unchanged.
- Write the SQL total, pass/advisory/fail counts, and matched-rule counts into the existing `汇总信息` worksheet. Preserve the existing `规则列表` worksheet byte-for-byte from the approved template; do not populate, clear, reorder, or restyle it.
- Prefer a user-supplied database type. Otherwise infer only `Oracle`, `Mysql`, `Kingbase`, `Gbase`, or `Gaussdb` from source/config/SQL evidence. If no supported type matches, leave the cell blank.
- For every SQL, evaluate all applicable 14 rules before deciding the result or writing findings. BUS-014 is evaluated only when `--schema` supplies the required table/index model; without it, the auditor records a warning instead of guessing. Keep every matched rule, including lower-severity matches found after a hard match; never stop at the first finding or discard advisory findings because a hard finding exists.
- Derive each row's `审核结果` only after the complete rule pass: if at least one matched rule is `硬性`, the result is `不通过` even when one or more `建议` rules also match; if all matched rules are `建议`, the result is `建议`; if no rule matches, the result is `通过`.
- Copy the template's result-cell styles so `不通过` is red, `建议` is yellow, and `通过` is green. Do not invent color values in the writer.
- The approved template uses one shared visual system across all three worksheets: dark-blue header bands, consistent body typography/borders, and severity fills in the `规则级别` column (`硬性` red, `建议` yellow). The detail-sheet result prototypes use the matching `不通过` red, `建议` yellow, and `通过` green fills. Treat these template styles as authoritative and never replace them with agent-chosen colors.
- Leave `人工复核结果` blank.
- Treat `scripts/audit_sql.py` as the only authority for rule matching. The agent may inspect its output, but must not replace it with model judgment or manually edit its `findings`.
- Treat the bundled `.xlsx` as a binary artifact. Never read it through a text-oriented viewer or decode it as UTF-8; replacement characters displayed by a tool are not evidence that the on-disk file is damaged. Use the writer's binary ZIP, worksheet, rule-catalog, and style validation as the source of truth; there is no fixed byte-level SHA requirement.

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

### 2. Audit candidates using the deterministic Python auditor

Read `references/rule.md` completely before auditing. The bundled rule reference mirrors the approved template's 14 rules. Apply every rule present there and do not substitute, weaken, or add other rules. The template's `规则列表` is the runtime authority for each rule's level, exact `存在问题` text, exact `处理建议` text, and rule order.

Run the bundled deterministic auditor against the extractor output:

```text
python <skill-dir>/scripts/audit_sql.py \
  --input <working-dir>/sql-candidates.json \
  --output <working-dir>/sql-audit.json \
  [--schema <working-dir>/schema-indexes.json]
```

The auditor expands CDATA wrappers before tokenizing SQL, removes comments while preserving string literals, distinguishes bound placeholders (`?`, `:name`, `$1`, and MyBatis `#{faultId}`/`#{item}`) from `${item}` substitution, checks BUS-001 through BUS-014 in fixed order, emits each matching rule at most once, and preserves input record order. Run it even when the archive contains no SQL so the output contract remains stable. Do not create an audit JSON manually.

The optional schema file is JSON in this shape:

```json
{"tables": {"users": {"indexes": [["id"], ["status", "id"]]}}}
```

Without `--schema`, BUS-014 is deliberately not guessed; the auditor adds an `audit_warnings` entry explaining that index availability could not be evaluated. Warnings are delivery metadata and must not become workbook rows. With `--schema`, BUS-014 is reported only when a condition column has no matching leading index column.

The auditor produces an audit JSON with this shape:

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

Use only the exact `存在问题` and `处理建议` text from the matching row in the template's `规则列表` (columns H and I). For `存在问题` only, prefix the exact rule ID and level as `BUS-00x【硬性】` or `BUS-00x【建议】`, followed immediately by the template problem text. Keep `处理建议` exactly equal to the template text. Do not copy model-written wording from the audit JSON, add explanations, append evidence, or lengthen either field. The auditor JSON contains only deterministic `rule_id` findings; the writer fills the two output fields from the template. Keep findings in template rule order and report each rule at most once per SQL.

Important interpretations:

- The matching rule level in the approved template controls output severity. The audit JSON does not need to duplicate that level, but the complete-match requirement still applies: first finish checking BUS-001 through BUS-014 (or record the explicit BUS-014 no-schema warning), then retain every matched rule in `findings`.
- `audit_sql.py` owns the per-SQL protocol: it initializes an empty match set, checks BUS-001 through BUS-014, retains every match once, sorts by template order, and leaves result precedence to `write_report.py`. A hard match changes the result color and label, but never suppresses other matched rules from `存在问题`, `处理建议`, or the summary counts.
- When one SQL matches several rules, number `存在问题` as `1. BUS-00x【硬性/建议】<template problem>；2. BUS-00x【硬性/建议】<template problem>` and number `处理建议` as `1. ...\n2. ...`, preserving the template rule order. With no findings, write `无` in both fields.
- Audit every SQL against all 14 rules before writing findings. Do not stop after the first match. In particular, a `SELECT *` statement can also match `BUS-002` when its effective WHERE is absent, `BUS-004` for hard-coded values, and/or `BUS-006` for negative predicates; a `DELETE` or `UPDATE` can also match `BUS-002` when its effective WHERE is absent or only `WHERE 1=1`.
- Treat `?`, `:name`, `$1`, and any normal MyBatis `#{parameter}` binding, including `#{faultId}`, `#{item}`, `#{object.property}`, and optional type metadata such as `#{faultId,jdbcType=VARCHAR}`, as bound placeholders for `BUS-004`. Do not report these as hard-coded constants. MyBatis `${item}` is string substitution, not a bound placeholder, and remains subject to `BUS-004` when it represents a business value.
- Do not apply `BUS-004` to DDL/database-object definitions (`CREATE`, `ALTER`, `DROP`, `TRUNCATE`, and related statements); those remain in the population and are evaluated by `BUS-001`. For business DML, ignore empty-string checks and explicit time-unit conversion factors such as `/ 1000` or `* 1000` when they are part of recognized date/time functions, but retain actual hard-coded business values in conditions, updates, and inserts.
- `BUS-001` treats `CREATE TABLE` as legal. Other DDL remains a hard finding; still inspect every SQL occurrence and keep any additional matching rules.
- `BUS-006` scans only `WHERE` predicates, including nested `WHERE` clauses. Do not report `NOT` in a SELECT list (for example `SELECT NOT NULL`) or `!=`/`<>` in a JOIN `ON` predicate. `IS NOT NULL` is not a negative-query finding.
- For MyBatis XML, inspect expanded `<include refid="..."/>` fragments. The extractor expands fragments defined in the same XML file; if an include or dynamic branch cannot be resolved, preserve it in the SQL and do not assume that it supplies a valid WHERE condition. Under the approved BUS-002 text, `SELECT`, `DELETE`, and `UPDATE` without an effective WHERE are findings; use the exact BUS-002 template wording in the report.
- Complete DDL statements remain in the population and are evaluated against `BUS-001`; do not remove them before auditing. They are not also evaluated against `BUS-004`.
- `BUS-004` concerns business parameters and bound placeholders. Do not claim a literal is a violation when it is a structural SQL keyword, a type-safe SQL clause, or a clearly non-business constant. Use the evidence only to make the internal decision; never append it to `存在问题` or `处理建议` beyond the required rule ID and level prefix.
- For dynamic SQL, preserve the original dynamic structure. If the full statement cannot be recovered, omit it and report the source path and reason outside the workbook.
- Do not treat extraction failures as SQL-rule findings.

### 3. Write the workbook

Run the bundled writer against its bundled template. Do not create the workbook manually, use a spreadsheet library directly, pass another template, modify the bundled template, or edit the generated workbook afterward. The writer validates that the bundled file is a valid XLSX and that its worksheets, headers, 14-rule catalog, and styles satisfy the contract; it always validates the result and rejects any workbook whose rule sheet or styles differ from `assets/应用代码扫描结果模板.xlsx`.

If template verification fails with a bad ZIP/central-directory error, a worksheet/rule/style contract error, or any other template-read error, stop immediately. Do not edit or repair the template, use `openpyxl` or another spreadsheet library, pass an alternate template, manually recreate the workbook, or search for an unverified replacement skill. Report the exact error and path, then have the user restore the complete skill folder from one verified clean copy before retrying. A report produced after bypassing this check is invalid.

Template versioning: an intentionally approved template update may change its SHA-256 or ZIP metadata without changing the contract. Keep the new file at the bundled path and rerun the structural, rule-catalog, style, and report-validation tests; a report-running agent must still use only that bundled file and must not replace or repair it at runtime.

```text
python <skill-dir>/scripts/write_report.py \
  --input <working-dir>/sql-audit.json \
  --output <working-dir>/应用代码扫描结果.xlsx
```

To validate only the bundled template before auditing, run `python <skill-dir>/scripts/write_report.py --validate`; this mode does not require an audit JSON or create an output workbook.

The writer removes the three example data rows from the detail worksheet and uses them as the green, yellow, and red style prototypes. The approved examples demonstrate an explicit-field bound-variable query (`通过`), a `SELECT *` query with a valid `WHERE` (`建议`), and a `SELECT *` query without a valid `WHERE` that hits both `BUS-002` and `BUS-003` (`不通过`); example text is never retained in a generated report. It appends one row per input record, resolves each finding's level and exact problem/suggestion text from the template's `规则列表`, discards any model-supplied problem/suggestion wording, applies hard-over-advisory precedence, numbers multiple findings in rule order, and leaves the manual-review column empty. It replaces the contents of the existing `汇总信息` worksheet with SQL total, pass/advisory/fail counts and matched-rule counts. It leaves `规则列表` untouched. With zero records it writes a valid three-sheet workbook. It rejects malformed audit JSON, findings whose rule ID is absent from the template, output text outside the template rule vocabulary, and SQL cells longer than the Excel cell limit rather than truncating them.

The workbook's visual output is template-controlled: the writer validates the three-sheet contract, exact seven detail headers, all nine rule headers, exactly BUS-001 through BUS-014, every A:I rule cell as non-empty, and the three result-style prototypes. It copies the template's normal cell styles plus the matching green/yellow/red result style to every generated detail row, retains the summary sheet's template styles, preserves the template's `规则列表` worksheet byte-for-byte, and verifies `styles.xml` byte-for-byte. Style IDs are never invented by the writer.

### 4. Report completion and limitations

Return the workbook path and summarize skipped files, unrecognized database types, and any overlong SQL separately. Do not add those notices as extra workbook rows. If the archive is corrupt, unsafe, or unsupported, stop without creating a report and state the actionable error.

## Quality Gate

Before handing off, verify the result with the writer's `--validate` mode or by reopening the workbook with an independent spreadsheet reader. Confirm the workbook has exactly `应用代码扫描结果`, `汇总信息`, and `规则列表`; the detail headers exactly match the contract; each result is `通过`, `建议`, or `不通过` with the template's green, yellow, or red style; every non-empty `存在问题` item has exactly `BUS-00x【硬性/建议】` followed by the matching template problem text, every non-empty `处理建议` item is exact template text, and both fields use only the required numeric prefix; multi-rule rows are numbered in template order; the number of detail rows equals the number of audit records; every detail row has an empty column G; the `规则列表` worksheet is unchanged from the template; and the total/pass/advisory/fail summary counts reconcile with the detail rows.
