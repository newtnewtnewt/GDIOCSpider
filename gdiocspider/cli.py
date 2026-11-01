import argparse
import json
import os
import sys
from contextlib import contextmanager

from gdiocspider.ioc_flagger import IOCTyper
from gdiocspider.settings import settings_store


class CLIError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message


@contextmanager
def redirect_progress_to_stderr(enabled):
    if not enabled:
        yield
        return
    real_stdout = sys.stdout
    sys.stdout = sys.stderr
    try:
        yield
    finally:
        sys.stdout = real_stdout


def emit_json(payload):
    print(json.dumps(payload, indent=2))


def fail(message, as_json=False):
    if as_json:
        emit_json({"error": message})
    else:
        print(message, file=sys.stderr)
    raise SystemExit(1)


def parse_cli_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Google Drive Crawler Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Classic usage (no subcommand, CSV scan):\n"
            "  gdiocspider --config_file PATH --output_file PATH\n"
        ),
    )
    parser.add_argument(
        "--config_file",
        type=str,
        help="Absolute path to the configuration file: /gdiocspider/config.json",
    )
    parser.add_argument(
        "--output_file",
        type=str,
        help="Absolute path to where the output file will be output: /gdiocspider/indicator_data.csv",
    )

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser(
        "scan", help="Crawl Google Drive and extract IOCs"
    )
    scan_parser.add_argument(
        "--config_file",
        type=str,
        required=True,
        help="Absolute path to the configuration file",
    )
    scan_parser.add_argument(
        "--output_file",
        type=str,
        required=True,
        help="Absolute path to the output CSV or JSON file",
    )
    scan_parser.add_argument(
        "--format",
        choices=["csv", "json"],
        default="csv",
        help="Output format (default: csv)",
    )

    list_parser = subparsers.add_parser(
        "list-files",
        help="List Drive files that would be scanned without extracting IOCs",
    )
    list_parser.add_argument(
        "--config_file",
        type=str,
        required=True,
        help="Absolute path to the configuration file",
    )
    list_parser.add_argument(
        "--format",
        choices=["json"],
        default="json",
        help="Output format (default: json)",
    )

    type_parser = subparsers.add_parser(
        "type", help="Classify a single IOC string with IOCFlagger"
    )
    type_parser.add_argument(
        "--value",
        type=str,
        required=True,
        help="IOC string to classify",
    )
    type_parser.add_argument(
        "--strict",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use regex fullmatch (default). --no-strict uses search.",
    )
    type_parser.add_argument(
        "--format",
        choices=["json"],
        default="json",
        help="Output format (default: json)",
    )

    args = parser.parse_args(argv)

    if not args.command:
        if not args.config_file or not args.output_file:
            parser.error(
                "the following arguments are required: --config_file, --output_file"
            )
        args.command = "scan"
        args.format = "csv"

    return args


def load_settings(config_file, output_file=None, as_json=False):
    if not os.path.exists(config_file):
        fail(
            f"Couldn't find config file at the specified path {config_file}, exiting.",
            as_json=as_json,
        )
    settings_store.update_file_path(config_file)
    if output_file:
        settings_store.update_output_file_path(output_file)
    settings_store.initialize_settings()


def run_scan(args):
    from gdiocspider.gdrive_crawler import execute_gdrive_crawler

    as_json = getattr(args, "format", "csv") == "json"
    load_settings(args.config_file, args.output_file, as_json=as_json)
    print(
        f"Beginning GDIOCSpider with {args.config_file}, {args.output_file}\n\n",
        file=sys.stderr if as_json else sys.stdout,
    )
    with redirect_progress_to_stderr(as_json):
        processed = execute_gdrive_crawler(output_format=args.format)
    if processed is None:
        fail(
            f"Was unable to authenticate with Google Drive at path {settings_store.GCP_TOKEN_FILE_PATH}, if an old token.json is present, delete and re-run",
            as_json=as_json,
        )
    if as_json:
        emit_json(processed)
    return processed


def run_list_files(args):
    from gdiocspider.gdrive_crawler import execute_list_files

    as_json = True
    load_settings(args.config_file, as_json=as_json)
    with redirect_progress_to_stderr(True):
        files = execute_list_files()
    if files is None:
        fail(
            f"Was unable to authenticate with Google Drive at path {settings_store.GCP_TOKEN_FILE_PATH}, if an old token.json is present, delete and re-run",
            as_json=as_json,
        )
    total = sum(len(items) for items in files.values())
    emit_json({"files": files, "total": total})
    return files


def run_type(args):
    as_json = getattr(args, "format", "json") == "json"
    try:
        typed = IOCTyper(args.value, strict_mode=args.strict)
    except Exception as exc:
        fail(str(exc), as_json=as_json)
    payload = {"ioc_value": typed.ioc_value, "ioc_type": typed.ioc_type}
    emit_json(payload)
    return payload


def dispatch(args):
    if args.command == "scan":
        return run_scan(args)
    if args.command == "list-files":
        return run_list_files(args)
    if args.command == "type":
        return run_type(args)
    fail(f"Unknown command: {args.command}")


def main(argv=None):
    args = parse_cli_args(argv)
    try:
        dispatch(args)
    except CLIError as exc:
        fail(exc.message, as_json=getattr(args, "format", "csv") == "json")
