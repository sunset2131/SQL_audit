# SQL Audit Skill Context

This context defines the vocabulary for the portable `sql-audit` workflow that turns code archives into rule-based SQL audit workbooks.

## Language

**Code archive**:
An uploaded compressed package containing application source, configuration, resources, and possibly compiled artifacts.
_Avoid_: source folder, JAR-only input

**SQL occurrence**:
One independently located SQL statement extracted from one source location. Repeated identical statements remain separate occurrences.
_Avoid_: unique SQL, deduplicated query

**Original SQL**:
The complete statement text recoverable from the source, retaining bound placeholders and dynamic SQL structure without guessed values.
_Avoid_: rendered SQL, interpolated SQL

**Rule-only audit**:
An audit whose findings come exclusively from the bundled `rule.md`; no inferred policy or supplemental SQL rule is added.
_Avoid_: best-practice scan, extended audit

**Audit workbook**:
The result Excel file created from the supplied template, with one row per SQL occurrence and the template's manual-review column left blank.
_Avoid_: report spreadsheet, summary workbook
