# sql-audit Skill Design

## Scope

Create a portable, non-Codex-specific skill named `sql-audit`. Given an archive containing application code, it comprehensively extracts independently reviewable SQL statements, audits them only against the supplied SQL rules, and writes a result workbook based strictly on the supplied Excel template.

All complete SQL is in scope regardless of whether it appears under mapper, migration, seed, configuration, or source-code paths. This includes DDL, which remains in the audit population and is evaluated by the supplied rules. Java `.class` files, all other binary files, incomplete SQL fragments, and confirmed non-SQL false positives are skipped without decompilation or constant-pool inspection.

## Decisions

- Use a skill plus deterministic Python helpers rather than prompt-only file handling or a full SQL AST dependency.
- Bundle copies of `docs/rule.md` and the approved `sql-audit/assets/应用代码扫描结果模板.xlsx` inside the skill so execution does not depend on the caller's working directory.
- Native archive support: ZIP, JAR, WAR, EAR, TAR, TAR.GZ, and TGZ. 7Z/RAR are optional when an appropriate system extractor is available.
- Apply path-traversal and archive-bomb safeguards during extraction.
- Scan supported source/config text formats with format-aware extraction and a generic text fallback. Skip `.class` and binary files.
- Do not filter complete SQL by directory or file naming; migration DDL and seed DML remain in the audit population.
- Recursively inspect every nested archive, including dependency locations, and preserve full nested source paths. Directory naming never excludes a complete SQL occurrence.
- Emit one workbook row per SQL occurrence, without deduplication. Replace the seven template headers with exactly `代码文件`, `目标数据库类型`, `原SQL`, `审核结果`, `存在问题`, `处理建议`, and `人工复核结果`; rename the detail worksheet and output file to `应用代码扫描结果`; retain the existing column order and styles. Add a `汇总信息` worksheet containing total/pass/fail counts, counts by database type, and counts for matched rules.
- Preserve source path, complete SQL text, bound placeholders, and dynamic SQL structure. Do not invent values or reconstruct incomplete dynamic SQL. Unrecoverable statements are skipped and reported outside the workbook.
- Prefer a user-supplied database type; otherwise infer from configuration, drivers, and SQL dialect. Leave the database-type cell blank when no supported type matches.
- Any matched rule, including advisory BUS-006, makes `审核结果` `不通过`. The bundled `rule.md` is the complete and only audit rule source.
- If no SQL is found, write a valid workbook containing only the template header. Corrupt or unsupported archives fail without producing a misleading report.
- Keep the manual-review column blank. Do not add columns or explanatory rows beyond the detail template; add only the required `汇总信息` worksheet.

## Components and Data Flow

```text
archive
  -> safe extraction and nested archive traversal
  -> source/text classification
  -> SQL candidate extraction
  -> database-type inference
  -> rule-only audit
  -> template-preserving workbook writer
```

Planned skill layout:

```text
sql-audit/
|-- SKILL.md
|-- references/rule.md
|-- assets/应用代码扫描结果模板.xlsx
`-- scripts/
    |-- extract_sql.py
    `-- write_report.py
```

`extract_sql.py` owns archive safety, text detection, source paths, statement boundaries, and candidate metadata. `write_report.py` owns template copying, exact headers, row insertion, summary aggregation, cell formatting, and workbook validation. The skill instructions own the audit interpretation and user-facing workflow; they must not introduce checks outside the bundled rule file.

## Error Handling

- Reject path traversal, excessive expansion, excessive nesting, and unsupported/corrupt archives with an actionable error.
- Continue after an individual file encoding or extraction failure; report skipped files and reasons in the final message.
- Do not encode extraction uncertainty as a rule violation.
- Do not truncate or split SQL that exceeds the Excel cell limit; report it as an output limitation.

## Verification

Create at least three evaluation scenarios in `evals/evals.json`:

1. A JAR containing Java/MyBatis/XML SQL and hard/advisory violations.
2. A non-JAR ZIP or TAR.GZ containing SQL and configuration files with inferable and unknown database types.
3. A mixed archive with mapper SQL, migration DDL and seed data, nested archives, `.class` files, dynamic SQL that must be skipped, explicit false positives, and duplicate SQL occurrences.

Assertions should verify archive handling, no class decompilation, one-row-per-occurrence output, exact detail headers, the summary worksheet and its reconciled counts, the bundled rule file as the sole rule source, BUS-006 failure semantics, and blank unknown database types.
