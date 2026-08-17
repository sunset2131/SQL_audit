# sql-audit Skill Design

## Scope

Create a portable, non-Codex-specific skill named `sql-audit`. Given an archive containing application code, it extracts independently reviewable SQL statements, audits them only against the supplied SQL rules, and writes a result workbook based strictly on the supplied Excel template.

The input is business SQL only. Standalone DDL files are out of scope. Java `.class` files and all other binary files are skipped without decompilation or constant-pool inspection.

## Decisions

- Use a skill plus deterministic Python helpers rather than prompt-only file handling or a full SQL AST dependency.
- Bundle copies of `docs/rule.md` and `docs/SQL审核结果模板.xlsx` inside the skill so execution does not depend on the caller's working directory.
- Native archive support: ZIP, JAR, WAR, EAR, TAR, TAR.GZ, and TGZ. 7Z/RAR are optional when an appropriate system extractor is available.
- Apply path-traversal and archive-bomb safeguards during extraction.
- Scan supported source/config text formats with format-aware extraction and a generic text fallback. Skip `.class` and binary files.
- Recursively inspect nested archives while excluding obvious third-party dependency locations where ownership is clear; preserve full nested source paths when ownership is uncertain.
- Emit one workbook row per SQL occurrence, without deduplication. The third template column is renamed from `变更类型(DDL/DMl/业务SQL)` to exactly `原SQL`.
- Preserve source path, complete SQL text, bound placeholders, and dynamic SQL structure. Do not invent values or reconstruct incomplete dynamic SQL. Unrecoverable statements are skipped and reported outside the workbook.
- Prefer a user-supplied database type; otherwise infer from configuration, drivers, and SQL dialect. Leave the database-type cell blank when no supported type matches.
- Any matched rule, including advisory BUS-006, makes `审核结果` `不通过`. BUS-014 and BUS-015 are removed from the effective rule set because their prerequisite material rules are not supplied and the request forbids adding rules.
- If no SQL is found, write a valid workbook containing only the template header. Corrupt or unsupported archives fail without producing a misleading report.
- Keep the manual-review column blank. Do not add sheets, columns, or explanatory rows beyond the template.

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
|-- assets/SQL审核结果模板.xlsx
`-- scripts/
    |-- extract_sql.py
    `-- write_report.py
```

`extract_sql.py` owns archive safety, text detection, source paths, statement boundaries, and candidate metadata. `write_report.py` owns template copying, exact headers, row insertion, cell formatting, and workbook validation. The skill instructions own the audit interpretation and user-facing workflow; they must not introduce checks outside the bundled rule file.

## Error Handling

- Reject path traversal, excessive expansion, excessive nesting, and unsupported/corrupt archives with an actionable error.
- Continue after an individual file encoding or extraction failure; report skipped files and reasons in the final message.
- Do not encode extraction uncertainty as a rule violation.
- Do not truncate or split SQL that exceeds the Excel cell limit; report it as an output limitation.

## Verification

Create at least three evaluation scenarios in `evals/evals.json`:

1. A JAR containing Java/MyBatis/XML SQL and hard/advisory violations.
2. A non-JAR ZIP or TAR.GZ containing SQL and configuration files with inferable and unknown database types.
3. A mixed archive with nested archives, `.class` files, dynamic SQL that must be skipped, and duplicate SQL occurrences.

Assertions should verify archive handling, no class decompilation, one-row-per-occurrence output, exact workbook headers and sheet, BUS-006 failure semantics, BUS-014/BUS-015 omission, and blank unknown database types.
