"""CLI Subcommands for Multi-Language Discovery and Inspection."""

import argparse
from python_hunter.application.services.security_app_service import SecurityApplicationService


def register_languages_command(subparsers: argparse._SubParsersAction) -> None:
    """Register the 'languages' command group in the CLI parser."""
    lang_parser = subparsers.add_parser(
        "languages",
        help="Inspect supported languages, capabilities, and framework adapters",
    )
    lang_subparsers = lang_parser.add_subparsers(dest="languages_subcommand")

    # python-hunter languages list
    list_parser = lang_subparsers.add_parser("list", help="List all supported languages and metadata")
    list_parser.add_argument("--language", help="Filter by specific language identifier (e.g. java, go, rust)")

    # python-hunter languages profile <path>
    profile_parser = lang_subparsers.add_parser("profile", help="Show language distribution profile for a workspace")
    profile_parser.add_argument("path", nargs="?", default=".", help="Path to workspace directory")

    lang_parser.set_defaults(func=handle_languages_command)


def handle_languages_command(args: argparse.Namespace) -> None:
    """Execute 'languages' CLI commands."""
    service = SecurityApplicationService()
    subcommand = getattr(args, "languages_subcommand", "list") or "list"

    if subcommand == "list":
        language_filter = getattr(args, "language", None)
        languages = service.list_languages(language_filter)
        print(f"\n=== Python Hunter Supported Multi-Language Platform ({len(languages)}) ===")
        for lang in languages:
            caps = ", ".join([k for k, v in lang["capabilities"].items() if v])
            fws = ", ".join(lang["framework_adapters"])
            print(f"\n🔹 {lang['display_name']} ({lang['language']}) v{lang['version']}")
            print(f"   Parser / Analyzer: {lang['parser']} / {lang['analyzer']}")
            print(f"   Ecosystem:        {lang['dependency_ecosystem']}")
            print(f"   Capabilities:     {caps}")
            print(f"   Frameworks:       {fws}")
        print("\n")

    elif subcommand == "profile":
        path = getattr(args, "path", ".")
        profile = service.get_repository_language_profile(path)
        print(f"\n=== Polyglot Repository Language Profile: {path} ===")
        print(f"Total Files: {profile['total_files']} | Total Lines: {profile['total_lines']}")
        print("Language Breakdown (by lines of code):")
        for lang, pct in profile["percentage_by_lines"].items():
            print(f"  • {lang.capitalize()}: {pct}%")
        if profile["detected_manifests"]:
            print(f"Manifest Files: {', '.join(profile['detected_manifests'])}")
        print("\n")
