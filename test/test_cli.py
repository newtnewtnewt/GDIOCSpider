import io
import json
import os
import tempfile
import unittest
from argparse import Namespace
from unittest.mock import patch

from gdiocspider.cli import parse_cli_args, run_type
from gdiocspider.data_exporter import export_all_indicator_data_to_json
from gdiocspider.settings import settings_store


class TestParseCliArgs(unittest.TestCase):
    def test_legacy_two_flag_path_is_csv_scan(self):
        args = parse_cli_args(
            ["--config_file", "/tmp/config.json", "--output_file", "/tmp/out.csv"]
        )
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.format, "csv")
        self.assertEqual(args.config_file, "/tmp/config.json")
        self.assertEqual(args.output_file, "/tmp/out.csv")

    def test_scan_subcommand_json_format(self):
        args = parse_cli_args(
            [
                "scan",
                "--config_file",
                "/tmp/config.json",
                "--output_file",
                "/tmp/out.json",
                "--format",
                "json",
            ]
        )
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.format, "json")
        self.assertEqual(args.output_file, "/tmp/out.json")

    def test_list_files_subcommand(self):
        args = parse_cli_args(["list-files", "--config_file", "/tmp/config.json"])
        self.assertEqual(args.command, "list-files")
        self.assertEqual(args.format, "json")

    def test_type_subcommand(self):
        args = parse_cli_args(["type", "--value", "1.1.1.1", "--no-strict"])
        self.assertEqual(args.command, "type")
        self.assertEqual(args.value, "1.1.1.1")
        self.assertFalse(args.strict)
        self.assertEqual(args.format, "json")

    def test_legacy_missing_flags_exits(self):
        with self.assertRaises(SystemExit):
            parse_cli_args([])


class TestTypeCommand(unittest.TestCase):
    def test_type_returns_json_ioc_fields(self):
        args = Namespace(value="1.1.1.1", strict=True, format="json")
        stdout = io.StringIO()
        with patch("sys.stdout", stdout):
            payload = run_type(args)
        self.assertEqual(payload["ioc_type"], "IPv4")
        self.assertEqual(payload["ioc_value"], "1[.]1[.]1[.]1")
        printed = json.loads(stdout.getvalue())
        self.assertEqual(printed["ioc_type"], "IPv4")
        self.assertEqual(printed["ioc_value"], "1[.]1[.]1[.]1")


class TestJsonExporter(unittest.TestCase):
    def test_export_writes_nested_records(self):
        records = [
            {
                "file_type": "Text File",
                "file_metadata": {
                    "name": "notes.txt",
                    "path": "/notes.txt",
                    "id": "abc",
                    "size": "12",
                },
                "all_indicators": [
                    {"value": "1[.]1[.]1[.]1", "type": "IPv4", "count": 2}
                ],
            }
        ]
        handle = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        path = handle.name
        handle.close()
        previous_output = settings_store.output_file_path
        try:
            settings_store.update_output_file_path(path)
            returned = export_all_indicator_data_to_json(records)
            self.assertEqual(returned, records)
            with open(path, encoding="utf-8") as exported:
                loaded = json.load(exported)
            self.assertEqual(loaded[0]["file_metadata"]["name"], "notes.txt")
            self.assertEqual(loaded[0]["all_indicators"][0]["type"], "IPv4")
        finally:
            settings_store.update_output_file_path(previous_output)
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
