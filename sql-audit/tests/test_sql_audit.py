import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from xml.etree import ElementTree


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


extractor = load_module("sql_audit_extractor", os.path.join(ROOT, "scripts", "extract_sql.py"))
auditor = load_module("sql_audit_auditor", os.path.join(ROOT, "scripts", "audit_sql.py"))
writer = load_module("sql_audit_writer", os.path.join(ROOT, "scripts", "write_report.py"))


class SqlAuditTests(unittest.TestCase):
    def test_auditor_validates_the_bundled_rule_reference(self):
        auditor.validate_rule_reference()

    def test_deterministic_auditor_matches_all_rule_families(self):
        cases = {
            "BUS-001": "CREATE VIEW active_users AS SELECT id FROM users",
            "BUS-002": "SELECT * FROM users",
            "BUS-003": "SELECT * FROM users WHERE id = #{id}",
            "BUS-004": "SELECT id FROM users WHERE id = 42",
            "BUS-005": "SELECT id FROM users WHERE deleted_at != NULL",
            "BUS-006": "SELECT id FROM users WHERE status NOT IN (#{status})",
            "BUS-007": "SELECT id FROM users WHERE status = #{a} OR status = #{b}",
            "BUS-008": "SELECT id FROM users WHERE name LIKE '%admin'",
            "BUS-009": "SELECT a.id FROM a JOIN b ON a.id=b.id JOIN c ON c.id=b.id JOIN d ON d.id=c.id WHERE a.id = #{id}",
            "BUS-010": "SELECT a.id FROM a, b WHERE a.id=b.id",
            "BUS-011": "SELECT id FROM users WHERE id = #{id} FOR UPDATE",
            "BUS-012": "INSERT INTO users(id) VALUES " + ",".join("(#{id})" for _ in range(5001)),
            "BUS-013": "SELECT id FROM users WHERE id = #{id} ORDER BY RAND()",
        }
        for rule_id, sql in cases.items():
            self.assertIn(rule_id, auditor.audit_one(sql), sql[:100])
        self.assertEqual([], auditor.audit_one("SELECT id FROM users WHERE id = #{id}"))
        self.assertEqual(auditor.audit_one(cases["BUS-009"]), auditor.audit_one(cases["BUS-009"]))

    def test_auditor_recognizes_mybatis_bindings_and_effective_where(self):
        self.assertNotIn("BUS-004", auditor.audit_one("SELECT id FROM users WHERE fault_id = #{faultId}"))
        self.assertNotIn("BUS-004", auditor.audit_one("SELECT id FROM users WHERE id = #{item,jdbcType=BIGINT}"))
        self.assertNotIn("BUS-004", auditor.audit_one("SELECT id FROM users WHERE fault_id = #{faultId,jdbcType=VARCHAR}"))
        self.assertNotIn("BUS-004", auditor.audit_one("SELECT id FROM users WHERE fault_id = #{object.faultId}"))
        self.assertNotIn("BUS-004", auditor.audit_one("SELECT id FROM users WHERE id = :name"))
        self.assertIn("BUS-004", auditor.audit_one("SELECT id FROM users WHERE id = ${item}"))
        self.assertNotIn("BUS-003", auditor.audit_one("SELECT COUNT(*) FROM users WHERE id = #{id}"))
        self.assertNotIn("BUS-006", auditor.audit_one("SELECT id FROM users WHERE deleted_at IS NOT NULL"))
        self.assertIn("BUS-002", auditor.audit_one("SELECT * FROM users WHERE 1 = 1"))
        self.assertNotIn("BUS-002", auditor.audit_one("SELECT * FROM users WHERE 1 = 1 AND id = #{id}"))
        self.assertNotIn("BUS-002", auditor.audit_one("WITH active AS (SELECT id FROM users) SELECT id FROM active WHERE id = #{id}"))

    def test_bus004_excludes_ddl_and_structural_constants(self):
        self.assertNotIn("BUS-001", auditor.audit_one("CREATE TABLE users (status INT DEFAULT 0)"))
        self.assertNotIn("BUS-004", auditor.audit_one("CREATE TABLE users (status INT DEFAULT 0)"))
        self.assertIn("BUS-001", auditor.audit_one("CREATE VIEW active_users AS SELECT id FROM users"))
        self.assertIn("BUS-001", auditor.audit_one("ALTER TABLE users ADD COLUMN status INT"))
        self.assertIn("BUS-001", auditor.audit_one("DROP TABLE users"))
        self.assertNotIn("BUS-004", auditor.audit_one("RENAME TABLE old_users TO users"))
        self.assertNotIn(
            "BUS-004",
            auditor.audit_one(
                "SELECT DATE_FORMAT(FROM_UNIXTIME(event_time / 1000), '%Y-%m') "
                "FROM events WHERE event_id = #{eventId}"
            ),
        )
        self.assertNotIn(
            "BUS-004",
            auditor.audit_one("SELECT id FROM users WHERE name != '' AND id = #{id}"),
        )

    def test_bus006_only_checks_where_predicates(self):
        self.assertNotIn("BUS-006", auditor.audit_one("SELECT NOT NULL AS marker FROM users WHERE id = #{id}"))
        self.assertNotIn("BUS-006", auditor.audit_one("SELECT a.id FROM a JOIN b ON a.id != b.id WHERE a.id = #{id}"))
        self.assertIn("BUS-006", auditor.audit_one("SELECT id FROM users WHERE status NOT IN (#{status})"))
        self.assertIn("BUS-006", auditor.audit_one("SELECT id FROM users WHERE a != b"))
        self.assertIn("BUS-006", auditor.audit_one("SELECT id FROM users WHERE NOT EXISTS (SELECT 1 FROM roles WHERE roles.id = users.role_id)"))
        self.assertNotIn("BUS-006", auditor.audit_one("SELECT id FROM users WHERE deleted_at IS NOT NULL"))
        self.assertNotIn("BUS-006", auditor.audit_one("SELECT id FROM users WHERE note = 'NOT IN' -- !=\n"))

    def test_cdata_does_not_hide_mybatis_binding(self):
        sql = "SELECT id FROM users WHERE created_at <![CDATA[<]]> #{faultId}"
        tokens = auditor.tokenize(sql)
        self.assertIn("#{faultId}", [token.value for token in tokens if token.kind == "bound"])
        self.assertNotIn("BUS-004", auditor.audit_one(sql))

    def test_auditor_keeps_record_order_and_reports_bus014_without_guessing(self):
        payload = {
            "records": [
                {"source": "a.sql", "sql": "SELECT id FROM users WHERE id = #{id}"},
                {"source": "b.sql", "sql": "SELECT id FROM users WHERE status = #{status}"},
            ],
            "warnings": [],
        }
        result = auditor.audit_payload(payload)
        self.assertEqual(["a.sql", "b.sql"], [record["source"] for record in result["records"]])
        self.assertTrue(any(warning.get("rule") == "BUS-014" for warning in result["audit_warnings"]))
        schema = {"tables": {"users": {"indexes": [["id"]]}}}
        self.assertIn("BUS-014", auditor.audit_one("SELECT id FROM users WHERE status = #{status}", schema))
        self.assertNotIn("BUS-014", auditor.audit_one("SELECT id FROM users WHERE id = #{id}", schema))

    def make_archive(self, directory):
        nested = os.path.join(directory, "nested.zip")
        with zipfile.ZipFile(nested, "w") as archive:
            archive.writestr("mapper/Extra.sql", "SELECT id FROM audit_log WHERE actor_id = ?;")
        dependency = io.BytesIO()
        with zipfile.ZipFile(dependency, "w") as archive:
            archive.writestr("queries/Dependency.sql", "SELECT id FROM dependency_table WHERE id = ?;")
        jar_path = os.path.join(directory, "service.jar")
        with zipfile.ZipFile(jar_path, "w") as archive:
            archive.writestr(
                "mapper/UserMapper.xml",
                '<mapper><select id="find">SELECT * FROM users WHERE id = #{id}</select></mapper>',
            )
            archive.writestr(
                "src/Repository.java",
                '@Select("SELECT `id` FROM users WHERE name = ?")\nclass Repository {}',
            )
            archive.writestr(
                "db/migration/V001__init.sql",
                "CREATE TABLE users (id BIGINT PRIMARY KEY);\nINSERT INTO users (id) VALUES (?);",
            )
            archive.writestr("i18n/messages.properties", "button.select=Select user\nmenu.update=Update profile")
            archive.write(nested, "application/nested.zip")
            archive.writestr("BOOT-INF/lib/dependency.jar", dependency.getvalue())
            archive.writestr("src/Hidden.class", b"\xca\xfe\xba\xbeSELECT * FROM hidden")
        return jar_path

    def test_extracts_all_sql_without_class_binary_or_false_positives(self):
        with tempfile.TemporaryDirectory() as directory:
            result = extractor.extract(self.make_archive(directory), "Mysql")
        self.assertEqual(6, len(result["records"]))
        self.assertTrue(all(record["database_type"] == "Mysql" for record in result["records"]))
        self.assertTrue(any(record["source"].endswith("application/nested.zip/mapper/Extra.sql") for record in result["records"]))
        self.assertTrue(any("BOOT-INF/lib" in record["source"] for record in result["records"]))
        self.assertFalse(any(record["source"].endswith(".class") for record in result["records"]))
        migration = [record for record in result["records"] if "db/migration" in record["source"]]
        self.assertEqual(2, len(migration))
        self.assertTrue(any(record["sql"].upper().startswith("CREATE TABLE") for record in migration))
        self.assertFalse(any("i18n/messages.properties" in record["source"] for record in result["records"]))

    def test_database_type_is_inferred_when_evidence_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            result = extractor.extract(self.make_archive(directory))
        java_record = next(record for record in result["records"] if record["source"].endswith("Repository.java"))
        self.assertEqual("Mysql", java_record["database_type"])
        self.assertTrue(any(record["database_type"] == "" for record in result["records"]))

    def test_xml_include_fragments_are_expanded_without_emitting_fragment_rows(self):
        source = extractor.SourceText(
            "mapper/AlarmMapper.xml",
            """
            <mapper>
              <sql id="conditionSql">WHERE alarm_id = #{alarmId} AND status = #{status,jdbcType=VARCHAR}</sql>
              <update id="updateAlarm">
                UPDATE alarm SET alarm_count = alarm_count + 1
                <include refid="conditionSql"/>
              </update>
            </mapper>
            """,
            0,
        )
        records = list(extractor.extract_from_text(source))
        self.assertEqual(1, len(records))
        self.assertIn("WHERE alarm_id = #{alarmId}", records[0]["sql"])
        self.assertIn("status = #{status,jdbcType=VARCHAR}", records[0]["sql"])

    def test_mybatis_binding_placeholder_is_preserved_in_extracted_sql(self):
        source = extractor.SourceText(
            "mapper/UserMapper.xml",
            '<mapper><select id="find">SELECT id FROM users WHERE id = #{item}</select></mapper>',
            0,
        )
        records = list(extractor.extract_from_text(source))
        self.assertEqual(1, len(records))
        self.assertIn("#{item}", records[0]["sql"])

    def test_properties_and_comment_only_sql_are_not_extracted(self):
        source = extractor.SourceText(
            "i18n/messages.properties",
            "notice=Please UPDATE the profile WITH the latest value\n"
            "query=\"SELECT id FROM users WHERE id = ?\"\n",
            0,
        )
        records = list(extractor.extract_from_text(source))
        self.assertEqual(1, len(records))
        self.assertTrue(records[0]["sql"].startswith("SELECT id FROM users"))

        commented = extractor.SourceText(
            "db/migration/V001.sql",
            "-- UPDATE users SET status = 1 WHERE id = 2;\n",
            0,
        )
        self.assertEqual([], list(extractor.extract_from_text(commented)))

    def test_writer_preserves_contract(self):
        records = [
            {
                "source": "mapper/User.xml",
                "sql": "SELECT id FROM users WHERE id = ?",
                "database_type": "Mysql",
                "findings": [],
            },
            {
                "source": "src/Repository.java",
                "sql": "SELECT * FROM users WHERE id = ?",
                "database_type": "",
                "findings": [
                    {
                        "rule_id": "BUS-003",
                        "problem": "模型自行补充的错误问题文本",
                        "suggestion": "模型自行补充的错误建议文本",
                    },
                    {
                        "rule_id": "BUS-006",
                    },
                ],
            },
            {
                "source": "db/migration/V001.sql",
                "sql": "CREATE TABLE users (id BIGINT)",
                "database_type": "Mysql",
                "findings": [
                    {
                        "rule_id": "BUS-001",
                        "problem": "业务 SQL 中直接包含 DDL 语句。",
                        "suggestion": "将结构变更移交 DBA 或运维执行。",
                    },
                    {
                        "rule_id": "BUS-003",
                        "problem": "使用 SELECT * 未显式指定查询字段。",
                        "suggestion": "建议显式列出字段。",
                    },
                ],
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            audit_path = os.path.join(directory, "audit.json")
            output_path = os.path.join(directory, "result.xlsx")
            with open(audit_path, "w", encoding="utf-8") as handle:
                json.dump({"records": records}, handle, ensure_ascii=False)
            loaded = writer.load_records(audit_path)
            writer.render(os.path.join(ROOT, "assets", "应用代码扫描结果模板.xlsx"), output_path, loaded)
            writer.validate(output_path, 3)
            with zipfile.ZipFile(output_path) as archive:
                self.assertIsNone(archive.testzip())
                sheet = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
                summary_sheet = archive.read("xl/worksheets/sheet2.xml").decode("utf-8")
                rules_sheet = archive.read("xl/worksheets/sheet3.xml")
                shared = archive.read("xl/sharedStrings.xml").decode("utf-8")
                workbook = archive.read("xl/workbook.xml").decode("utf-8")
                app_properties = archive.read("docProps/app.xml").decode("utf-8")
            ElementTree.fromstring(summary_sheet)
            self.assertEqual(4, len(re.findall(r'<row\s+r="\d+"', sheet)))
            with zipfile.ZipFile(os.path.join(ROOT, "assets", "应用代码扫描结果模板.xlsx")) as template_archive:
                template_detail = template_archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
                template_summary = template_archive.read("xl/worksheets/sheet2.xml").decode("utf-8")
            manual_style = re.search(r'<c\s+r="G2"[^>]*\bs="(\d+)"', template_detail).group(1)
            summary_value_style = re.search(r'<c\s+r="B4"[^>]*\bs="(\d+)"', template_summary).group(1)
            for header in writer.HEADERS:
                self.assertIn(header, shared)
            self.assertIn("通过", shared)
            self.assertIn("建议", shared)
            self.assertIn("不通过", shared)
            for row_number in (2, 3, 4):
                self.assertIn(f'<c r="G{row_number}" s="{manual_style}"/>', sheet)
            self.assertIn(f'name="{writer.SHEET_NAME}"', workbook)
            self.assertIn(f'name="{writer.SUMMARY_SHEET_NAME}"', workbook)
            self.assertIn(f'name="{writer.RULES_SHEET_NAME}"', workbook)
            self.assertEqual(3, workbook.count("<sheet "))
            self.assertIn(writer.SUMMARY_TITLE, shared)
            self.assertIn(f'<c r="B4" s="{summary_value_style}"><v>3</v></c>', summary_sheet)
            self.assertIn(f'<c r="B5" s="{summary_value_style}"><v>1</v></c>', summary_sheet)
            self.assertIn(f'<c r="B6" s="{summary_value_style}"><v>1</v></c>', summary_sheet)
            self.assertIn(f'<c r="B7" s="{summary_value_style}"><v>1</v></c>', summary_sheet)
            self.assertIn("1. BUS-003【建议】使用 SELECT * 未显式指定查询字段，返回列不明确，可能包含不需要的列。；2. BUS-006【建议】使用负向查询可能导致SQL不走索引、全表扫描，影响查询性能。", shared)
            self.assertIn("1. 建议将 SELECT * 改为显式列出实际需要的字段名。\n2. 建议改写为正向条件，如使用 IN 替代 NOT IN（需注意 NULL 值处理），或使用 EXISTS 替代 NOT EXISTS 等。", shared)
            self.assertIn("1. BUS-001【硬性】业务 SQL 中直接包含 DDL 语句，属于高危操作，可能引发锁表、数据丢失或意外结构变更。；2. BUS-003【建议】使用 SELECT * 未显式指定查询字段，返回列不明确，可能包含不需要的列。", shared)
            self.assertIn("1. 去除 DDL 语句，将结构变更操作移交 DBA 或运维通过变更流程执行；如确需清理数据，改用 DELETE 并分批提交。\n2. 建议将 SELECT * 改为显式列出实际需要的字段名。", shared)
            self.assertIn("<vt:i4>3</vt:i4>", app_properties)
            self.assertIn(writer.SUMMARY_SHEET_NAME, app_properties)
            self.assertIn(writer.RULES_SHEET_NAME, app_properties)

            with zipfile.ZipFile(os.path.join(ROOT, "assets", "应用代码扫描结果模板.xlsx")) as template_archive:
                self.assertEqual(rules_sheet, template_archive.read("xl/worksheets/sheet3.xml"))

            template_xml = template_detail
            for row_number in (2, 3, 4):
                template_style = re.search(rf'<c\s+r="D{row_number}"[^>]*\bs="(\d+)"', template_xml).group(1)
                output_style = re.search(rf'<c\s+r="D{row_number}"[^>]*\bs="(\d+)"', sheet).group(1)
                self.assertEqual(template_style, output_style)

            strings = writer.read_shared_strings(shared)
            self.assertEqual("通过", writer.shared_cell_value(sheet, "D2", strings))
            self.assertEqual("建议", writer.shared_cell_value(sheet, "D3", strings))
            self.assertEqual("不通过", writer.shared_cell_value(sheet, "D4", strings))

    def test_writer_preserves_sql_source_line_in_code_file_cell(self):
        records = [{
            "source": "mapper/UserMapper.xml",
            "line": 42,
            "sql": "SELECT id FROM users WHERE id = #{id}",
            "findings": [],
        }]
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "result.xlsx")
            writer.render(
                os.path.join(ROOT, "assets", "应用代码扫描结果模板.xlsx"),
                output_path,
                records,
            )
            writer.validate(output_path, 1)
            with zipfile.ZipFile(output_path) as archive:
                sheet = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
                strings = writer.read_shared_strings(archive.read("xl/sharedStrings.xml").decode("utf-8"))
            self.assertEqual("mapper/UserMapper.xml（第42行）", writer.shared_cell_value(sheet, "A2", strings))

    def test_summary_counts_empty_results(self):
        summary = writer.build_summary([], {"BUS-001": {"level": "硬性", "problem": "x", "suggestion": "y", "order": 0}})
        self.assertEqual(
            [("SQL 总数", 0), ("通过数", 0), ("建议数", 0), ("不通过数", 0)],
            summary["metrics"],
        )
        self.assertEqual([], summary["rules"])

    def test_rule_levels_come_from_template(self):
        template = os.path.join(ROOT, "assets", "应用代码扫描结果模板.xlsx")
        with zipfile.ZipFile(template) as archive:
            levels = writer.read_rule_levels(
                archive.read("xl/worksheets/sheet3.xml").decode("utf-8"),
                archive.read("xl/sharedStrings.xml").decode("utf-8"),
            )
        self.assertEqual("硬性", levels["BUS-001"])
        self.assertEqual("建议", levels["BUS-003"])
        self.assertEqual("建议", levels["BUS-014"])

    def test_rule_catalog_contains_exact_output_text(self):
        template = os.path.join(ROOT, "assets", "应用代码扫描结果模板.xlsx")
        with zipfile.ZipFile(template) as archive:
            catalog = writer.read_rule_catalog(
                archive.read("xl/worksheets/sheet3.xml").decode("utf-8"),
                archive.read("xl/sharedStrings.xml").decode("utf-8"),
            )
        self.assertEqual(14, len(catalog))
        self.assertEqual(
            "使用 SELECT * 未显式指定查询字段，返回列不明确，可能包含不需要的列。",
            catalog["BUS-003"]["problem"],
        )
        self.assertIn("4、CREATE TABLE被允许，应判定为合法。", catalog["BUS-001"]["audit_method"])
        self.assertEqual(
            "使用负向查询可能导致SQL不走索引、全表扫描，影响查询性能。",
            catalog["BUS-006"]["problem"],
        )
        self.assertTrue(catalog["BUS-006"]["audit_method"].startswith("1、检查 WHERE 子句中"))
        self.assertEqual(
            "为条件列创建合适的索引，或调整查询条件以利用现有索引；若无法确认索引情况，请补充数据模型后重新审核。",
            catalog["BUS-014"]["suggestion"],
        )

    def test_writer_rejects_finding_absent_from_template(self):
        records = [{
            "source": "mapper/User.xml",
            "sql": "SELECT id FROM users",
            "findings": [{"rule_id": "BUS-999", "problem": "x", "suggestion": "y"}],
        }]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "BUS-999"):
                writer.render(
                    os.path.join(ROOT, "assets", "应用代码扫描结果模板.xlsx"),
                    os.path.join(directory, "result.xlsx"),
                    records,
                )

    def test_writer_orders_findings_and_prefers_hard_rule(self):
        records = [{
            "source": "mapper/User.xml",
            "sql": "SELECT * FROM users WHERE id != ?",
            "findings": [
                {"rule_id": "BUS-006", "problem": "wrong", "suggestion": "wrong"},
                {"rule_id": "BUS-001"},
            ],
        }]
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "result.xlsx")
            writer.render(
                os.path.join(ROOT, "assets", "应用代码扫描结果模板.xlsx"),
                output_path,
                records,
            )
            writer.validate(output_path, 1)
            with zipfile.ZipFile(output_path) as archive:
                sheet = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
                strings = writer.read_shared_strings(archive.read("xl/sharedStrings.xml").decode("utf-8"))
            self.assertEqual("不通过", writer.shared_cell_value(sheet, "D2", strings))
            self.assertEqual(
                "1. BUS-001【硬性】业务 SQL 中直接包含 DDL 语句，属于高危操作，可能引发锁表、数据丢失或意外结构变更。；2. BUS-006【建议】使用负向查询可能导致SQL不走索引、全表扫描，影响查询性能。",
                writer.shared_cell_value(sheet, "E2", strings),
            )
            self.assertEqual(
                "1. 去除 DDL 语句，将结构变更操作移交 DBA 或运维通过变更流程执行；如确需清理数据，改用 DELETE 并分批提交。\n2. 建议改写为正向条件，如使用 IN 替代 NOT IN（需注意 NULL 值处理），或使用 EXISTS 替代 NOT EXISTS 等。",
                writer.shared_cell_value(sheet, "F2", strings),
            )

    def test_bus002_template_text_supports_select_without_where(self):
        records = [{
            "source": "mapper/GroupMapper.xml",
            "sql": "SELECT * FROM snc_chat_group",
            "findings": [{"rule_id": "BUS-002"}, {"rule_id": "BUS-003"}],
        }]
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "result.xlsx")
            writer.render(
                os.path.join(ROOT, "assets", "应用代码扫描结果模板.xlsx"),
                output_path,
                records,
            )
            writer.validate(output_path, 1)
            with zipfile.ZipFile(output_path) as archive:
                sheet = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
                strings = writer.read_shared_strings(archive.read("xl/sharedStrings.xml").decode("utf-8"))
            self.assertEqual("不通过", writer.shared_cell_value(sheet, "D2", strings))
            self.assertEqual(
                "1. BUS-002【硬性】SELECT、DELETE/UPDATE 缺少有效 WHERE 条件，可能导致全表扫描或对全表执行删除、更新操作。；2. BUS-003【建议】使用 SELECT * 未显式指定查询字段，返回列不明确，可能包含不需要的列。",
                writer.shared_cell_value(sheet, "E2", strings),
            )

    def test_rule_reference_contains_fourteen_rules(self):
        with open(os.path.join(ROOT, "references", "rule.md"), encoding="utf-8") as handle:
            rules = [line for line in handle if line.strip()]
        self.assertEqual(14, len(rules))
        self.assertTrue(rules[-1].startswith("BUS-014\t"))

    def test_writer_supports_empty_results(self):
        with tempfile.TemporaryDirectory() as directory:
            audit_path = os.path.join(directory, "audit.json")
            output_path = os.path.join(directory, "result.xlsx")
            with open(audit_path, "w", encoding="utf-8") as handle:
                json.dump({"records": []}, handle)
            writer.render(os.path.join(ROOT, "assets", "应用代码扫描结果模板.xlsx"), output_path, writer.load_records(audit_path))
            writer.validate(output_path, 0)

    def test_default_template_is_the_bundled_approved_template(self):
        self.assertTrue(writer.DEFAULT_TEMPLATE.endswith(os.path.join("assets", "应用代码扫描结果模板.xlsx")))
        writer.validate_bundled_template(writer.DEFAULT_TEMPLATE)
        writer.validate_template_contract(writer.DEFAULT_TEMPLATE)

    def test_template_has_consistent_severity_styles_and_current_examples(self):
        template = os.path.join(ROOT, "assets", "应用代码扫描结果模板.xlsx")
        with zipfile.ZipFile(template) as archive:
            detail = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
            rules = archive.read("xl/worksheets/sheet3.xml").decode("utf-8")
            shared = archive.read("xl/sharedStrings.xml").decode("utf-8")
        strings = writer.read_shared_strings(shared)

        result_styles = {
            address: re.search(rf'<c\s+r="{address}"[^>]*\bs="(\d+)"', detail).group(1)
            for address in ("D2", "D3", "D4")
        }
        self.assertEqual(3, len(set(result_styles.values())))
        self.assertEqual("通过", writer.shared_cell_value(detail, "D2", strings))
        self.assertEqual("建议", writer.shared_cell_value(detail, "D3", strings))
        self.assertEqual("不通过", writer.shared_cell_value(detail, "D4", strings))
        self.assertEqual(
            "1. BUS-003【建议】使用 SELECT * 未显式指定查询字段，返回列不明确，可能包含不需要的列。",
            writer.shared_cell_value(detail, "E3", strings),
        )
        self.assertTrue(writer.shared_cell_value(detail, "E4", strings).startswith("1. BUS-002【硬性】"))
        self.assertIn("2. BUS-003【建议】", writer.shared_cell_value(detail, "E4", strings))

        level_styles = {
            address: re.search(rf'<c\s+r="{address}"[^>]*\bs="(\d+)"', rules).group(1)
            for address in ("C2", "C3", "C4", "C5", "C7", "C15")
        }
        hard_styles = {level_styles[address] for address in ("C2", "C3", "C5")}
        advisory_styles = {level_styles[address] for address in ("C4", "C7", "C15")}
        self.assertEqual(1, len(hard_styles))
        self.assertEqual(1, len(advisory_styles))
        self.assertNotEqual(hard_styles, advisory_styles)

    def test_template_validation_accepts_reencoded_xlsx_without_fixed_hash(self):
        source_path = os.path.join(ROOT, "assets", "应用代码扫描结果模板.xlsx")
        with tempfile.TemporaryDirectory() as directory:
            reencoded_path = os.path.join(directory, "template.xlsx")
            with zipfile.ZipFile(source_path) as source, zipfile.ZipFile(reencoded_path, "w") as target:
                for name in source.namelist():
                    target.writestr(name, source.read(name))
            with patch.object(writer, "DEFAULT_TEMPLATE", reencoded_path):
                writer.validate_bundled_template(reencoded_path)
                output_path = os.path.join(directory, "result.xlsx")
                writer.render(reencoded_path, output_path, [])
                writer.validate(output_path, 0, reencoded_path)

    def test_shared_string_counts_remain_valid_when_digit_width_changes(self):
        source = (
            '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'count="999" uniqueCount="999">'
            + '<si><t>x</t></si>' * 999
            + '</sst>'
        )
        updated, indices = writer.update_shared_strings(source, ["new"])
        ElementTree.fromstring(updated)
        opening = re.search(r"<sst\b[^>]*>", updated)
        self.assertIsNotNone(opening)
        self.assertIn('count="1000"', opening.group(0))
        self.assertIn('uniqueCount="1000"', opening.group(0))
        self.assertEqual([999], indices)

    def test_writer_rejects_an_alternate_template_path(self):
        with tempfile.TemporaryDirectory() as directory:
            template_copy = os.path.join(directory, "template.xlsx")
            with open(writer.DEFAULT_TEMPLATE, "rb") as source, open(template_copy, "wb") as target:
                target.write(source.read())
            with self.assertRaisesRegex(ValueError, "only the bundled approved template"):
                writer.render(template_copy, os.path.join(directory, "result.xlsx"), [])


if __name__ == "__main__":
    unittest.main()
