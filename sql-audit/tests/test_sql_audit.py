import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest
import zipfile
from xml.etree import ElementTree


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


extractor = load_module("sql_audit_extractor", os.path.join(ROOT, "scripts", "extract_sql.py"))
writer = load_module("sql_audit_writer", os.path.join(ROOT, "scripts", "write_report.py"))


class SqlAuditTests(unittest.TestCase):
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
                        "problem": "使用SELECT *：未明确列出所需字段。",
                        "suggestion": "只列出业务实际需要的字段。",
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
            for header in writer.HEADERS:
                self.assertIn(header, shared)
            self.assertIn("通过", shared)
            self.assertIn("建议", shared)
            self.assertIn("不通过", shared)
            self.assertIn('<c r="G2" s="7"/>', sheet)
            self.assertIn('<c r="G3" s="7"/>', sheet)
            self.assertIn('<c r="G4" s="7"/>', sheet)
            self.assertIn(f'name="{writer.SHEET_NAME}"', workbook)
            self.assertIn(f'name="{writer.SUMMARY_SHEET_NAME}"', workbook)
            self.assertIn(f'name="{writer.RULES_SHEET_NAME}"', workbook)
            self.assertEqual(3, workbook.count("<sheet "))
            self.assertIn(writer.SUMMARY_TITLE, shared)
            self.assertIn('<c r="B4" s="6"><v>3</v></c>', summary_sheet)
            self.assertIn('<c r="B5" s="6"><v>1</v></c>', summary_sheet)
            self.assertIn('<c r="B6" s="6"><v>1</v></c>', summary_sheet)
            self.assertIn('<c r="B7" s="6"><v>1</v></c>', summary_sheet)
            self.assertIn("BUS-003", shared)
            self.assertIn("BUS-001", shared)
            self.assertIn("<vt:i4>3</vt:i4>", app_properties)
            self.assertIn(writer.SUMMARY_SHEET_NAME, app_properties)
            self.assertIn(writer.RULES_SHEET_NAME, app_properties)

            with zipfile.ZipFile(os.path.join(ROOT, "assets", "应用代码扫描结果模板.xlsx")) as template_archive:
                self.assertEqual(rules_sheet, template_archive.read("xl/worksheets/sheet3.xml"))

            template_xml = zipfile.ZipFile(os.path.join(ROOT, "assets", "应用代码扫描结果模板.xlsx")).read(
                "xl/worksheets/sheet1.xml"
            ).decode("utf-8")
            for row_number in (2, 3, 4):
                template_style = re.search(rf'<c\s+r="D{row_number}"[^>]*\bs="(\d+)"', template_xml).group(1)
                output_style = re.search(rf'<c\s+r="D{row_number}"[^>]*\bs="(\d+)"', sheet).group(1)
                self.assertEqual(template_style, output_style)

            strings = writer.read_shared_strings(shared)
            self.assertEqual("通过", writer.shared_cell_value(sheet, "D2", strings))
            self.assertEqual("建议", writer.shared_cell_value(sheet, "D3", strings))
            self.assertEqual("不通过", writer.shared_cell_value(sheet, "D4", strings))

    def test_summary_counts_empty_results(self):
        summary = writer.build_summary([], {"BUS-001": "硬性"})
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

    def test_rule_reference_contains_thirteen_rules(self):
        with open(os.path.join(ROOT, "references", "rule.md"), encoding="utf-8") as handle:
            rules = [line for line in handle if line.strip()]
        self.assertEqual(13, len(rules))
        self.assertTrue(rules[-1].startswith("BUS-013\t"))

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


if __name__ == "__main__":
    unittest.main()
