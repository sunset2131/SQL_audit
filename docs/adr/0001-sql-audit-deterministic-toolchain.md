# Use a Deterministic Helper Toolchain for sql-audit

The `sql-audit` skill will combine portable skill instructions with bundled Python helpers for archive extraction, SQL candidate discovery, and template-preserving workbook writing. This is preferred over prompt-only file handling because archive safety, one-row-per-occurrence traceability, and exact Excel structure are hard to guarantee by prose alone; a full SQL AST dependency would add dialect and installation cost without being required by the supplied rules.
