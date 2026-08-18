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
                    {
                        "rule_id": "BUS-006",
                        "problem": "负向查询风险：使用了NOT，可能导致索引利用不足；位置：WHERE条件。",
                        "suggestion": "优先改写为正向条件。",
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
            writer.render(os.path.join(ROOT, "assets", "SQL审核结果模板.xlsx"), output_path, loaded)
            writer.validate(output_path, 2)
            with zipfile.ZipFile(output_path) as archive:
                self.assertIsNone(archive.testzip())
                sheet = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
                summary_sheet = archive.read("xl/worksheets/sheet2.xml").decode("utf-8")
                shared = archive.read("xl/sharedStrings.xml").decode("utf-8")
                workbook = archive.read("xl/workbook.xml").decode("utf-8")
                relationships = archive.read("xl/_rels/workbook.xml.rels").decode("utf-8")
                content_types = archive.read("[Content_Types].xml").decode("utf-8")
                app_properties = archive.read("docProps/app.xml").decode("utf-8")
            ElementTree.fromstring(summary_sheet)
            self.assertEqual(3, len(re.findall(r'<row\s+r="\d+"', sheet)))
            for header in writer.HEADERS:
                self.assertIn(header, shared)
            self.assertIn("不通过", shared)
            self.assertIn('<c r="G2"/>', sheet)
            self.assertIn('<c r="G3"/>', sheet)
            self.assertIn(f'name="{writer.SHEET_NAME}"', workbook)
            self.assertIn(f'name="{writer.SUMMARY_SHEET_NAME}"', workbook)
            self.assertIn(writer.SUMMARY_TITLE, shared)
            self.assertIn('<c r="B4" s="4"><v>2</v></c>', summary_sheet)
            self.assertIn('<c r="B5" s="4"><v>1</v></c>', summary_sheet)
            self.assertIn('<c r="B6" s="4"><v>1</v></c>', summary_sheet)
            self.assertIn("Mysql", shared)
            self.assertIn("未识别", shared)
            self.assertIn("BUS-003", shared)
            self.assertIn("BUS-006", shared)
            self.assertIn('Target="worksheets/sheet2.xml"', relationships)
            self.assertIn('PartName="/xl/worksheets/sheet2.xml"', content_types)
            self.assertIn("<vt:i4>2</vt:i4>", app_properties)
            self.assertIn(writer.SUMMARY_SHEET_NAME, app_properties)

    def test_summary_counts_empty_results(self):
        summary = writer.build_summary([])
        self.assertEqual([("SQL 总数", 0), ("通过数", 0), ("不通过数", 0)], summary["metrics"])
        self.assertEqual([], summary["database_types"])
        self.assertEqual([], summary["rules"])

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
            writer.render(os.path.join(ROOT, "assets", "SQL审核结果模板.xlsx"), output_path, writer.load_records(audit_path))
            writer.validate(output_path, 0)


if __name__ == "__main__":
    unittest.main()
