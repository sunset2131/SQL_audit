#!/usr/bin/env python3
"""Deterministically audit extracted SQL against the bundled 14-rule contract.

This script intentionally emits only rule IDs.  The report writer remains the
single source for the exact problem/suggestion wording and severity colors.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Iterable, Optional


RULE_ORDER = [f"BUS-{number:03d}" for number in range(1, 15)]
HARD_RULES = {"BUS-001", "BUS-002", "BUS-004", "BUS-005", "BUS-007", "BUS-008", "BUS-009", "BUS-011", "BUS-012", "BUS-013"}
ADVISORY_RULES = {"BUS-003", "BUS-006", "BUS-010", "BUS-014"}
MAX_SQL_LENGTH = 32_767
RULE_REFERENCE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "references", "rule.md")


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    depth: int

    @property
    def upper(self) -> str:
        return self.value.upper()


WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*")
NUMBER_RE = re.compile(r"(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?")
# MyBatis ``#{...}`` is a prepared/bound parameter regardless of its name.
# Keep the body permissive because MyBatis allows property paths and optional
# type metadata, e.g. ``#{faultId}``, ``#{item.id}``, and
# ``#{faultId,jdbcType=VARCHAR}``.
BOUND_RE = re.compile(r"#\{[^{}]*\}")
SUBST_RE = re.compile(r"\$\{[^{}]*\}")
CDATA_RE = re.compile(r"<!\[CDATA\[(.*?)\]\]>", re.S)
DDL_KEYWORDS = {"CREATE", "ALTER", "DROP", "TRUNCATE", "RENAME", "COMMENT", "GRANT", "REVOKE"}
STRUCTURAL_TIME_FUNCTIONS = {
    "DATE_FORMAT",
    "FROM_UNIXTIME",
    "TO_CHAR",
    "TO_DATE",
    "UNIX_TIMESTAMP",
}


def validate_rule_reference(path: str = RULE_REFERENCE) -> None:
    """Fail closed if the bundled rule reference is not the expected 14-rule contract."""
    with open(path, encoding="utf-8") as handle:
        entries = [line.rstrip("\n").split("\t", 2) for line in handle if line.strip()]
    ids = [entry[0] for entry in entries if entry]
    levels = {entry[0]: entry[1] for entry in entries if len(entry) > 1}
    if ids != RULE_ORDER:
        raise ValueError(f"rule reference must contain BUS-001 through BUS-014 in order: {ids}")
    expected_levels = {rule_id: "硬性" for rule_id in HARD_RULES} | {rule_id: "建议" for rule_id in ADVISORY_RULES}
    if levels != expected_levels:
        raise ValueError("rule reference levels do not match the deterministic auditor contract")


def tokenize(sql: str) -> list[Token]:
    """Tokenize SQL while removing comments and preserving string literals."""
    # XML extraction can leave CDATA wrappers around operators. Remove only
    # the wrappers so the SQL body and MyBatis bindings remain intact.
    sql = CDATA_RE.sub(lambda match: match.group(1), sql)
    tokens: list[Token] = []
    i = 0
    depth = 0
    length = len(sql)
    while i < length:
        char = sql[i]
        if char.isspace():
            i += 1
            continue
        if sql.startswith("--", i) or sql.startswith("//", i):
            end = sql.find("\n", i + 2)
            i = length if end < 0 else end + 1
            continue
        if sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            i = length if end < 0 else end + 2
            continue
        bound = BOUND_RE.match(sql, i)
        if bound:
            tokens.append(Token("bound", bound.group(0), depth))
            i = bound.end()
            continue
        subst = SUBST_RE.match(sql, i)
        if subst:
            tokens.append(Token("subst", subst.group(0), depth))
            i = subst.end()
            continue
        if char == "'":
            start = i + 1
            i += 1
            value: list[str] = []
            while i < length:
                if sql[i] == "'":
                    if i + 1 < length and sql[i + 1] == "'":
                        value.append("'")
                        i += 2
                        continue
                    break
                if sql[i] == "\\" and i + 1 < length:
                    value.append(sql[i + 1])
                    i += 2
                    continue
                value.append(sql[i])
                i += 1
            tokens.append(Token("string", "".join(value), depth))
            i = min(length, i + 1)
            continue
        if char in {'"', "`", "["}:
            closing = "]" if char == "[" else char
            i += 1
            value: list[str] = []
            while i < length:
                if sql[i] == closing:
                    if i + 1 < length and sql[i + 1] == closing:
                        value.append(closing)
                        i += 2
                        continue
                    break
                value.append(sql[i])
                i += 1
            tokens.append(Token("identifier", "".join(value), depth))
            i = min(length, i + 1)
            continue
        word = WORD_RE.match(sql, i)
        if word:
            tokens.append(Token("word", word.group(0), depth))
            i = word.end()
            continue
        number = NUMBER_RE.match(sql, i)
        if number:
            tokens.append(Token("number", number.group(0), depth))
            i = number.end()
            continue
        if char == "?":
            tokens.append(Token("bound", char, depth))
            i += 1
            continue
        if char == ":" and i + 1 < length and (sql[i + 1].isalpha() or sql[i + 1] == "_"):
            match = WORD_RE.match(sql, i + 1)
            assert match is not None
            tokens.append(Token("bound", sql[i:match.end()], depth))
            i = match.end()
            continue
        if char == "$" and i + 1 < length and sql[i + 1].isdigit():
            match = re.match(r"\$\d+", sql[i:])
            assert match is not None
            tokens.append(Token("bound", match.group(0), depth))
            i += len(match.group(0))
            continue
        operator = next((op for op in (">=", "<=", "<>", "!=", "||", ":=") if sql.startswith(op, i)), None)
        if operator:
            tokens.append(Token("operator", operator, depth))
            i += len(operator)
            continue
        if char in "=><+-*/%,.;":
            tokens.append(Token("operator" if char in "=><+-*/%" else "punct", char, depth))
            i += 1
            continue
        if char == "(":
            tokens.append(Token("punct", char, depth))
            depth += 1
            i += 1
            continue
        if char == ")":
            depth = max(0, depth - 1)
            tokens.append(Token("punct", char, depth))
            i += 1
            continue
        tokens.append(Token("symbol", char, depth))
        i += 1
    return tokens


def word_indices(tokens: list[Token], word: str, depth: Optional[int] = None) -> list[int]:
    wanted = word.upper()
    return [i for i, token in enumerate(tokens) if token.kind == "word" and token.upper == wanted and (depth is None or token.depth == depth)]


def first_statement_keyword(tokens: list[Token]) -> Optional[str]:
    for token in tokens:
        if token.kind == "word":
            if token.upper in {"SELECT", "INSERT", "UPDATE", "DELETE", "MERGE", "REPLACE", "CREATE", "ALTER", "DROP", "TRUNCATE", "RENAME", "COMMENT", "GRANT", "REVOKE", "WITH"}:
                return token.upper
    return None


def clause_end(tokens: list[Token], start: int, depth: int, clauses: set[str]) -> int:
    for i in range(start, len(tokens)):
        if tokens[i].depth == depth and tokens[i].kind == "word" and tokens[i].upper in clauses:
            return i
    return len(tokens)


def has_effective_where(tokens: list[Token], dml_index: int) -> bool:
    depth = tokens[dml_index].depth
    where_indices = [i for i in range(dml_index + 1, len(tokens)) if tokens[i].kind == "word" and tokens[i].upper == "WHERE" and tokens[i].depth == depth]
    if not where_indices:
        return False
    where = where_indices[0]
    end = clause_end(tokens, where + 1, depth, {"GROUP", "ORDER", "LIMIT", "OFFSET", "FETCH", "RETURNING", "FOR", "UNION", "EXCEPT", "INTERSECT"})
    body = tokens[where + 1:end]
    meaningful = {"AND", "OR", "NOT", "EXISTS", "IN", "LIKE", "IS", "BETWEEN"}
    for i, token in enumerate(body):
        if token.kind == "word" and token.upper in meaningful:
            if token.upper in {"EXISTS", "NOT"}:
                return True
            if token.upper in {"IN", "LIKE", "IS", "BETWEEN"}:
                left = body[i - 1] if i else None
                if left and left.kind in {"word", "identifier", "bound"}:
                    return True
        if token.kind == "operator" and token.value in {"=", "!=", "<>", ">", "<", ">=", "<="} and i:
            left = body[i - 1]
            right = body[i + 1] if i + 1 < len(body) else None
            if left.kind in {"word", "identifier", "bound"} and right and right.kind in {"word", "identifier", "bound", "string", "number", "subst"}:
                if not (left.kind == "number" or right.upper in {"TRUE", "FALSE"}):
                    return True
    return False


def select_list_has_star(tokens: list[Token]) -> bool:
    for select in word_indices(tokens, "SELECT"):
        depth = tokens[select].depth
        from_indices = [i for i in range(select + 1, len(tokens)) if tokens[i].kind == "word" and tokens[i].upper == "FROM" and tokens[i].depth == depth]
        if not from_indices:
            continue
        for i in range(select + 1, from_indices[0]):
            if tokens[i].value != "*":
                continue
            previous = tokens[i - 1] if i else None
            if previous and previous.value == ")":
                continue
            if previous and previous.kind == "word" and previous.upper in {"COUNT", "SUM", "AVG", "MIN", "MAX"}:
                continue
            if previous and previous.value == "(" and i > 1:
                function = tokens[i - 2]
                if function.kind == "word" and function.upper in {"COUNT", "SUM", "AVG", "MIN", "MAX"}:
                    continue
            return True
    return False


def is_value_token(token: Token) -> bool:
    return token.kind in {"string", "number", "subst"}


def has_hardcoded_business_value(tokens: list[Token]) -> bool:
    relevant_ops = {"=", "!=", "<>", ">", "<", ">=", "<=", "+", "-", "*", "/"}
    in_values = False
    in_set = False
    for i, token in enumerate(tokens):
        if token.kind == "word" and token.upper == "VALUES":
            in_values = True
        if token.kind == "word" and token.upper == "SET":
            in_set = True
        if token.kind == "word" and token.upper in {"WHERE", "HAVING", "ON"}:
            in_set = False
        if token.kind == "word" and token.upper in {"LIMIT", "OFFSET", "FETCH", "TOP"}:
            continue
        if token.kind == "bound":
            continue
        if not is_value_token(token):
            continue
        previous = tokens[i - 1] if i else None
        previous_two = tokens[i - 2] if i > 1 else None
        in_comparison = previous is not None and (previous.value in relevant_ops or previous.upper in {"LIKE", "IN", "BETWEEN"})
        if in_values or in_set or in_comparison:
            if token.kind == "number" and previous and previous.value in {"LIMIT", "OFFSET"}:
                continue
            if token.kind == "number" and previous and previous.value == "=" and previous_two and previous_two.kind == "number":
                continue
            # Empty-string checks and time-unit multipliers are structural SQL
            # expressions, not business values that need parameter binding.
            if token.kind == "string" and token.value == "":
                continue
            if token.kind == "number" and previous and previous.value in {"*", "/"}:
                recent_words = {
                    candidate.upper
                    for candidate in tokens[max(0, i - 12):i]
                    if candidate.kind == "word"
                }
                if recent_words.intersection(STRUCTURAL_TIME_FUNCTIONS):
                    continue
            return True
    return False


def has_null_comparison(tokens: list[Token]) -> bool:
    return any(token.kind == "word" and token.upper == "NULL" and i and tokens[i - 1].value in {"=", "!=", "<>"} for i, token in enumerate(tokens))


def has_negative_query(tokens: list[Token]) -> bool:
    for i, token in enumerate(tokens):
        if token.value in {"!=", "<>"}:
            return True
        if token.kind != "word" or token.upper != "NOT":
            continue
        previous = tokens[i - 1].upper if i else ""
        following = tokens[i + 1].upper if i + 1 < len(tokens) else ""
        if previous == "IS" or following == "NULL":
            continue
        return True
    return False


def has_same_field_or(tokens: list[Token]) -> bool:
    for i, token in enumerate(tokens):
        if token.kind != "word" or token.upper != "OR":
            continue
        left = _comparison_around(tokens, i - 1, -1)
        right = _comparison_around(tokens, i + 1, 1)
        if left and right and left[0] == right[0]:
            return True
    return False


def _comparison_around(tokens: list[Token], start: int, direction: int) -> Optional[tuple[str, str]]:
    indices = range(start, -1, -1) if direction < 0 else range(start, len(tokens))
    values = list(indices)[:5]
    if direction < 0:
        values.reverse()
    for offset, i in enumerate(values):
        if tokens[i].value != "=":
            continue
        left_index = i - 1
        right_index = i + 1
        if left_index < 0 or right_index >= len(tokens):
            continue
        left = tokens[left_index]
        right = tokens[right_index]
        if left.kind in {"word", "identifier"} and right.kind in {"word", "identifier", "bound", "string", "number", "subst"}:
            return (left.upper, right.value)
    return None


def has_leading_like_wildcard(tokens: list[Token]) -> bool:
    for i, token in enumerate(tokens):
        if token.kind == "word" and token.upper == "LIKE" and i + 1 < len(tokens):
            value = tokens[i + 1]
            if value.kind == "string" and value.value.startswith("%"):
                return True
    return False


def from_segments(tokens: list[Token]) -> Iterable[tuple[int, int, int]]:
    for from_index in word_indices(tokens, "FROM"):
        depth = tokens[from_index].depth
        end = clause_end(tokens, from_index + 1, depth, {"WHERE", "GROUP", "ORDER", "LIMIT", "OFFSET", "FETCH", "UNION", "EXCEPT", "INTERSECT", "RETURNING"})
        yield from_index, end, depth


def has_too_many_tables(tokens: list[Token]) -> bool:
    for start, end, depth in from_segments(tokens):
        count = 0
        expect_table = True
        for i in range(start + 1, end):
            token = tokens[i]
            if token.depth != depth:
                continue
            if token.kind == "word" and token.upper == "JOIN":
                count += 1
                expect_table = True
            elif expect_table and token.kind in {"word", "identifier"}:
                if token.upper not in {"LATERAL", "ONLY"}:
                    count += 1
                    expect_table = False
            elif token.value == ",":
                expect_table = True
        if count > 3:
            return True
    return False


def has_implicit_join(tokens: list[Token]) -> bool:
    for start, end, depth in from_segments(tokens):
        if any(tokens[i].value == "," and tokens[i].depth == depth for i in range(start + 1, end)):
            return True
    return False


def has_explicit_lock(tokens: list[Token]) -> bool:
    values = [token.upper for token in tokens if token.kind == "word"]
    text = " ".join(values)
    return bool(re.search(r"\bFOR\s+(?:UPDATE|SHARE)\b|\bLOCK\s+IN\s+SHARE\s+MODE\b", text))


def insert_tuple_count(tokens: list[Token]) -> int:
    values_indices = word_indices(tokens, "VALUES")
    if not values_indices:
        return 0
    values_index = values_indices[0]
    base_depth = tokens[values_index].depth
    count = 0
    for i in range(values_index + 1, len(tokens)):
        if tokens[i].depth == base_depth and tokens[i].value == "(":
            count += 1
    return count


def has_random_order(tokens: list[Token]) -> bool:
    order_indices = word_indices(tokens, "ORDER")
    for order in order_indices:
        if order + 1 >= len(tokens) or tokens[order + 1].upper != "BY":
            continue
        end = clause_end(tokens, order + 2, tokens[order].depth, {"LIMIT", "OFFSET", "FETCH", "FOR", "UNION"})
        text = " ".join(token.upper for token in tokens[order + 2:end])
        if re.search(r"\b(?:RAND|RANDOM)\s*\(|\bDBMS_RANDOM\s*\.\s*VALUE\b", text):
            return True
    return False


def normalize_schema(schema: Optional[dict[str, Any]]) -> dict[str, list[tuple[str, ...]]]:
    if not schema:
        return {}
    tables = schema.get("tables", schema) if isinstance(schema, dict) else {}
    result: dict[str, list[tuple[str, ...]]] = {}
    if not isinstance(tables, dict):
        return result
    for table, definition in tables.items():
        entries = definition.get("indexes", []) if isinstance(definition, dict) else definition
        if not isinstance(entries, list):
            continue
        indexes: list[tuple[str, ...]] = []
        for entry in entries:
            if isinstance(entry, str):
                indexes.append((entry.upper(),))
            elif isinstance(entry, list) and entry:
                indexes.append(tuple(str(column).upper() for column in entry))
        result[str(table).upper()] = indexes
    return result


def schema_missing_index(tokens: list[Token], schema: Optional[dict[str, Any]]) -> bool:
    catalog = normalize_schema(schema)
    if not catalog:
        return False
    tables = [tokens[i + 1].upper for i in word_indices(tokens, "FROM") if i + 1 < len(tokens) and tokens[i + 1].kind in {"word", "identifier"}]
    if not tables:
        return False
    columns: set[str] = set()
    for i, token in enumerate(tokens):
        if token.kind == "word" and token.upper in {"WHERE", "ON", "ORDER", "GROUP"}:
            for candidate in tokens[i + 1:i + 8]:
                if candidate.kind in {"word", "identifier"} and candidate.upper not in {"BY", "AND", "OR", "ASC", "DESC"}:
                    columns.add(candidate.upper.split(".")[-1])
                    break
    if not columns:
        return False
    all_indexes = [index for table in tables for index in catalog.get(table, [])]
    return any(not any(index and index[0] == column for index in all_indexes) for column in columns)


def audit_one(sql: str, schema: Optional[dict[str, Any]] = None) -> list[str]:
    if not isinstance(sql, str) or not sql.strip():
        return []
    tokens = tokenize(sql)
    if not tokens:
        return []
    matches: set[str] = set()
    statement_keyword = first_statement_keyword(tokens)
    if any(token.kind == "word" and token.upper in DDL_KEYWORDS for token in tokens):
        matches.add("BUS-001")
    dml_candidates = [i for i, token in enumerate(tokens) if token.kind == "word" and token.upper in {"SELECT", "DELETE", "UPDATE"}]
    minimum_depth = min((tokens[i].depth for i in dml_candidates), default=None)
    dml = next((i for i in dml_candidates if tokens[i].depth == minimum_depth), None)
    if dml is not None and not has_effective_where(tokens, dml):
        matches.add("BUS-002")
    if select_list_has_star(tokens):
        matches.add("BUS-003")
    # BUS-004 applies to business SQL, not database-object definitions. DDL
    # remains in the population and is handled by BUS-001 only.
    if statement_keyword not in DDL_KEYWORDS and has_hardcoded_business_value(tokens):
        matches.add("BUS-004")
    if has_null_comparison(tokens):
        matches.add("BUS-005")
    if has_negative_query(tokens):
        matches.add("BUS-006")
    if has_same_field_or(tokens):
        matches.add("BUS-007")
    if has_leading_like_wildcard(tokens):
        matches.add("BUS-008")
    if has_too_many_tables(tokens):
        matches.add("BUS-009")
    if has_implicit_join(tokens):
        matches.add("BUS-010")
    if has_explicit_lock(tokens):
        matches.add("BUS-011")
    if insert_tuple_count(tokens) > 5000:
        matches.add("BUS-012")
    if has_random_order(tokens):
        matches.add("BUS-013")
    if schema_missing_index(tokens, schema):
        matches.add("BUS-014")
    return [rule_id for rule_id in RULE_ORDER if rule_id in matches]


def audit_payload(payload: dict[str, Any], schema: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    records = payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        raise ValueError("extracted JSON must contain a records array")
    output_records: list[dict[str, Any]] = []
    for index, record in enumerate(records, 1):
        if not isinstance(record, dict) or not isinstance(record.get("sql"), str):
            raise ValueError(f"record {index} requires a SQL string")
        if len(record["sql"]) > MAX_SQL_LENGTH:
            raise ValueError(f"record {index} SQL exceeds Excel's {MAX_SQL_LENGTH}-character cell limit")
        updated = dict(record)
        updated["findings"] = [{"rule_id": rule_id} for rule_id in audit_one(record["sql"], schema)]
        output_records.append(updated)
    output = dict(payload)
    output["records"] = output_records
    warnings = list(output.get("warnings", [])) if isinstance(output.get("warnings", []), list) else []
    if not schema:
        warnings.append({"rule": "BUS-014", "reason": "no schema/index model supplied; BUS-014 was not evaluated"})
    output["audit_warnings"] = warnings
    output["auditor"] = "sql-audit/scripts/audit_sql.py"
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="JSON produced by extract_sql.py")
    parser.add_argument("--output", required=True, help="deterministic audit JSON for write_report.py")
    parser.add_argument("--schema", help="optional JSON table/index model for BUS-014")
    args = parser.parse_args()
    try:
        validate_rule_reference()
        with open(args.input, encoding="utf-8") as handle:
            payload = json.load(handle)
        schema = None
        if args.schema:
            with open(args.schema, encoding="utf-8") as handle:
                schema = json.load(handle)
        result = audit_payload(payload, schema)
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(result, handle, ensure_ascii=False, indent=2)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"sql-audit audit error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"records": len(result["records"]), "warnings": len(result.get("audit_warnings", []))}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
