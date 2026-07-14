"""
Command line interface for PiHole-AI.
"""

from __future__ import annotations

import argparse

from pihole_ai.version import get_version


def build_parser() -> argparse.ArgumentParser:
    """
    Build the PiHole-AI CLI parser.
    """

    parser = argparse.ArgumentParser(
        prog="pihole-ai",
        description="Run PiHole-AI services and maintenance tasks.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {get_version()}",
    )
    subcommands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    subcommands.add_parser(
        "collect",
        help="Run the continuous Pi-hole query collector.",
    )
    subcommands.add_parser(
        "collector",
        help="Run the continuous Pi-hole query collector.",
    )
    subcommands.add_parser(
        "run-engine",
        help="Run the continuous analysis engine.",
    )
    subcommands.add_parser(
        "engine",
        help="Run the continuous analysis engine.",
    )
    subcommands.add_parser(
        "engine-once",
        help="Run one analysis engine cycle.",
    )
    subcommands.add_parser(
        "config-path",
        help="Print the PiHole-AI runtime config file path.",
    )
    subcommands.add_parser(
        "data-path",
        help="Print the PiHole-AI events database path.",
    )
    subcommands.add_parser(
        "log-path",
        help="Print the PiHole-AI log file path.",
    )
    dashboard = subcommands.add_parser(
        "dashboard",
        help="Run the dashboard web server.",
    )
    dashboard.add_argument(
        "--host",
        default="0.0.0.0",
        help="Dashboard host address.",
    )
    dashboard.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Dashboard port.",
    )
    dashboard_commands = dashboard.add_subparsers(
        dest="dashboard_command",
    )
    dashboard_auth = dashboard_commands.add_parser(
        "auth",
        help="Manage dashboard authentication.",
    )
    dashboard_auth_commands = dashboard_auth.add_subparsers(
        dest="dashboard_auth_command",
        required=True,
    )
    dashboard_auth_status = dashboard_auth_commands.add_parser(
        "status",
        help="Show dashboard authentication status.",
    )
    dashboard_auth_status.add_argument(
        "--json",
        action="store_true",
        help="Print status as JSON.",
    )
    dashboard_auth_set_password = dashboard_auth_commands.add_parser(
        "set-password",
        help="Set the dashboard administrator password.",
    )
    dashboard_auth_set_password.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read the new password from stdin.",
    )
    dashboard_auth_set_password.add_argument(
        "--json",
        action="store_true",
        help="Print result as JSON.",
    )
    for auth_command in ("enable", "disable"):
        auth_toggle = dashboard_auth_commands.add_parser(
            auth_command,
            help=f"{auth_command.title()} dashboard authentication.",
        )
        auth_toggle.add_argument(
            "--json",
            action="store_true",
            help="Print result as JSON.",
        )
        if auth_command == "disable":
            auth_toggle.add_argument(
                "--confirm-disable-auth",
                action="store_true",
                help="Confirm disabling dashboard authentication.",
            )
    status = subcommands.add_parser(
        "status",
        help="Print runtime status.",
    )
    status.add_argument(
        "--no-ollama",
        action="store_true",
        help="Deprecated: Ollama checks are skipped by default.",
    )
    status.add_argument(
        "--ollama",
        action="store_true",
        help="Include Ollama health check.",
    )
    status.add_argument(
        "--dry-run",
        action="store_true",
        help="Print service status commands without running them.",
    )
    health = subcommands.add_parser(
        "health",
        help="Run unified PiHole-AI health checks.",
    )
    health.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable health JSON.",
    )

    config = subcommands.add_parser(
        "config",
        help="Inspect and validate PiHole-AI configuration.",
    )
    config_commands = config.add_subparsers(
        dest="config_command",
        required=True,
    )
    config_check = config_commands.add_parser(
        "check",
        help="Validate PiHole-AI configuration.",
    )
    config_check.add_argument(
        "--mode",
        choices=[
            "syntax",
            "install",
            "runtime",
        ],
        default="runtime",
        help="Validation mode.",
    )
    config_check.add_argument(
        "--json",
        action="store_true",
        help="Print validation result as JSON.",
    )
    config_show = config_commands.add_parser(
        "show",
        help="Print safe effective configuration.",
    )
    config_show.add_argument(
        "--json",
        action="store_true",
        help="Print effective configuration as JSON.",
    )

    doctor = subcommands.add_parser(
        "doctor",
        help="Run read-only appliance diagnostics.",
    )
    doctor.add_argument(
        "--json",
        action="store_true",
        help="Print diagnostics as JSON.",
    )

    setup = subcommands.add_parser(
        "setup",
        help="Run first-run setup guidance.",
    )
    setup.add_argument(
        "setup_command",
        nargs="?",
        choices=["status"],
        help="Use 'status' to print read-only setup state.",
    )
    setup.add_argument(
        "--json",
        action="store_true",
        help="Print setup report as JSON.",
    )
    setup.add_argument(
        "--non-interactive",
        action="store_true",
        help="Never prompt; mutate only when explicit flags are supplied.",
    )
    setup.add_argument(
        "--dry-run",
        action="store_true",
        help="Show setup plan without making changes.",
    )
    setup.add_argument(
        "--install",
        action="store_true",
        help="Install or refresh appliance services during setup.",
    )
    setup.add_argument(
        "--start",
        action="store_true",
        help="Start PiHole-AI services during setup.",
    )
    setup.add_argument(
        "--enable",
        action="store_true",
        help="Enable PiHole-AI services at boot during setup.",
    )
    setup.add_argument(
        "--skip-ollama-check",
        action="store_true",
        help="Skip Ollama availability check.",
    )

    explain = subcommands.add_parser(
        "explain",
        help="Explain local evidence for a domain.",
    )
    explain.add_argument(
        "domain",
        help="Domain to explain.",
    )
    explain.add_argument(
        "--json",
        action="store_true",
        help="Print explanation as JSON.",
    )
    explain.add_argument(
        "--history",
        action="store_true",
        help="Show recent immutable decision history for the domain.",
    )
    explain.add_argument(
        "--decision",
        default=None,
        help="Show one immutable decision by decision ID.",
    )
    explain.add_argument(
        "--compare",
        nargs=2,
        metavar=("OLDER_ID", "NEWER_ID"),
        help="Compare two immutable decision IDs for the domain.",
    )

    feedback = subcommands.add_parser(
        "feedback",
        help="Record human feedback for a domain.",
    )
    feedback.add_argument(
        "domain",
        help="Domain to annotate.",
    )
    feedback.add_argument(
        "verdict",
        choices=[
            "safe",
            "bad",
            "false-positive",
            "false-negative",
            "noisy",
        ],
        help="Feedback verdict.",
    )
    feedback.add_argument(
        "--reason",
        default="",
        help="Reason for the feedback.",
    )
    feedback.add_argument(
        "--promote",
        action="store_true",
        help="Promote feedback into an allow/block rule when applicable.",
    )
    feedback.add_argument(
        "--apply",
        action="store_true",
        help="When promoting a block rule, also write to blocklist helper.",
    )

    evaluate = subcommands.add_parser(
        "evaluate",
        help="Benchmark classifiers against a labeled fixture.",
    )
    evaluate.add_argument(
        "path",
        help="Path to a JSON or CSV benchmark fixture.",
    )
    evaluate.add_argument(
        "--risk-tolerance",
        type=int,
        default=15,
        help="Allowed risk-score error for a risk match.",
    )
    evaluate.add_argument(
        "--include-ai",
        action="store_true",
        help="Include the Ollama AI fallback in the benchmark.",
    )
    evaluate.add_argument(
        "--json",
        action="store_true",
        help="Print benchmark results as JSON.",
    )

    service = subcommands.add_parser(
        "service",
        help="Install or uninstall Linux systemd services.",
    )
    service_commands = service.add_subparsers(
        dest="service_command",
        required=True,
    )

    for name in ("install", "uninstall"):
        service_command = service_commands.add_parser(
            name,
            help=f"{name.title()} PiHole-AI systemd services.",
        )
        service_command.add_argument(
            "--dry-run",
            action="store_true",
            help="Print planned files and commands without changing systemd.",
        )

    db = subcommands.add_parser(
        "db",
        help="Inspect or migrate the PiHole-AI events database.",
    )
    db_commands = db.add_subparsers(
        dest="db_command",
        required=True,
    )
    db_status = db_commands.add_parser(
        "status",
        help="Print database schema status.",
    )
    db_status.add_argument(
        "--json",
        action="store_true",
        help="Print status as JSON.",
    )
    db_migrate = db_commands.add_parser(
        "migrate",
        help="Apply pending database migrations.",
    )
    db_migrate.add_argument(
        "--json",
        action="store_true",
        help="Print migration result as JSON.",
    )

    for name in ("install", "uninstall", "enable", "disable", "start", "stop", "restart"):
        command = subcommands.add_parser(
            name,
            help=f"{name.title()} PiHole-AI systemd services.",
        )
        if name == "install":
            command.add_argument(
                "install_command",
                nargs="?",
                choices=["status"],
                help="Use 'status' to inspect installation state.",
            )
        command.add_argument(
            "--dry-run",
            action="store_true",
            help="Print planned systemd actions without changing services.",
        )
        if name in {"install", "uninstall"}:
            command.add_argument(
                "--json",
                action="store_true",
                help="Print lifecycle result as JSON.",
            )
        if name == "install":
            command.add_argument(
                "--no-enable",
                action="store_true",
                help="Do not enable services at boot after install.",
            )
            command.add_argument(
                "--no-start",
                action="store_true",
                help="Do not start services after install.",
            )
        if name == "uninstall":
            command.add_argument(
                "--purge",
                action="store_true",
                help="Remove runtime-only files in addition to services.",
            )
            command.add_argument(
                "--confirm-purge",
                action="store_true",
                help="Confirm destructive purge behavior.",
            )

    upgrade = subcommands.add_parser(
        "upgrade",
        help="Safely refresh managed PiHole-AI appliance files.",
    )
    upgrade.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned upgrade actions without changing files.",
    )
    upgrade.add_argument(
        "--json",
        action="store_true",
        help="Print upgrade result as JSON.",
    )

    logs = subcommands.add_parser(
        "logs",
        help="Show PiHole-AI systemd service logs.",
    )
    logs.add_argument(
        "--lines",
        type=int,
        default=80,
        help="Number of journal lines to show.",
    )
    logs.add_argument(
        "--follow",
        "-f",
        action="store_true",
        help="Follow logs.",
    )
    logs.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the journalctl command without running it.",
    )

    export = subcommands.add_parser(
        "export",
        help="Export events, analyses, actions, or reputations.",
    )
    export.add_argument(
        "dataset",
        choices=[
            "analysis",
            "events",
            "actions",
            "reputations",
        ],
        help="Dataset to export.",
    )
    export.add_argument(
        "--format",
        choices=[
            "json",
            "csv",
        ],
        default="json",
        help="Export format.",
    )
    export.add_argument(
        "--output",
        default=None,
        help="Output file. Defaults to stdout.",
    )
    export.add_argument(
        "--limit",
        type=int,
        default=500,
        help="Maximum rows to export.",
    )
    export.add_argument(
        "--q",
        default="",
        help="Search domains or devices.",
    )
    export.add_argument(
        "--min-risk",
        type=int,
        default=0,
        help="Minimum risk for analysis exports.",
    )
    export.add_argument(
        "--category",
        default="",
        help="Category filter for analysis exports.",
    )

    maintenance = subcommands.add_parser(
        "maintenance",
        help="Run database maintenance.",
    )
    maintenance.add_argument(
        "maintenance_command",
        nargs="?",
        choices=["decision-history"],
        help="Optional maintenance task.",
    )
    maintenance.add_argument(
        "--keep-latest",
        type=int,
        default=None,
        help="Number of newest events to keep.",
    )
    maintenance.add_argument(
        "--vacuum",
        action="store_true",
        help="Run SQLite VACUUM after cleanup.",
    )
    maintenance.add_argument(
        "--dry-run",
        action="store_true",
        help="Show maintenance changes without deleting history.",
    )
    maintenance.add_argument(
        "--json",
        action="store_true",
        help="Print maintenance result as JSON.",
    )

    learn = subcommands.add_parser(
        "learn",
        help="Update local domain reputation from observed history.",
    )
    learn.add_argument(
        "--limit",
        type=int,
        default=500,
        help="Maximum domains to score.",
    )
    learn.add_argument(
        "--min-score",
        type=int,
        default=50,
        help="Minimum score to print and audit.",
    )
    learn.add_argument(
        "--no-audit",
        action="store_true",
        help="Do not create learned alert/suggest-block audit records.",
    )

    intel = subcommands.add_parser(
        "intel",
        help="Manage local threat-intelligence feeds.",
    )
    intel_commands = intel.add_subparsers(
        dest="intel_command",
        required=True,
    )

    intel_import = intel_commands.add_parser(
        "import-hosts",
        help="Import a local hosts-style threat-intel file.",
    )
    intel_import.add_argument(
        "path",
        help="Path to a hosts-style or plain-domain feed file.",
    )
    intel_import.add_argument(
        "--source",
        required=True,
        help="Source name for imported indicators.",
    )
    intel_import.add_argument(
        "--category",
        default="malware",
        help="Category assigned to imported indicators.",
    )
    intel_import.add_argument(
        "--confidence",
        type=int,
        default=90,
        help="Confidence assigned to imported indicators.",
    )

    intel_list = intel_commands.add_parser(
        "list",
        help="List imported threat-intel rows.",
    )
    intel_list.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum rows to show.",
    )
    intel_list.add_argument(
        "--q",
        default="",
        help="Search domains.",
    )
    intel_list.add_argument(
        "--source",
        default="",
        help="Filter by source.",
    )
    intel_list.add_argument(
        "--category",
        default="",
        help="Filter by category.",
    )
    intel_list.add_argument(
        "--json",
        action="store_true",
        help="Print rows as JSON.",
    )

    intel_source = intel_commands.add_parser(
        "source",
        help="Manage configured threat-intel feed sources.",
    )
    intel_source_commands = intel_source.add_subparsers(
        dest="intel_source_command",
        required=True,
    )
    intel_source_list = intel_source_commands.add_parser("list", help="List feed sources.")
    intel_source_list.add_argument("--json", action="store_true", help="Print JSON.")
    intel_source_show = intel_source_commands.add_parser("show", help="Show one feed source.")
    intel_source_show.add_argument("source_id")
    intel_source_show.add_argument("--json", action="store_true", help="Print JSON.")
    intel_source_add = intel_source_commands.add_parser("add", help="Add or update a feed source.")
    intel_source_add.add_argument("source_id")
    intel_source_add.add_argument("--name", required=True)
    intel_source_add.add_argument("--url", required=True)
    intel_source_add.add_argument("--format", choices=["hosts", "domains", "text"], default="hosts")
    intel_source_add.add_argument("--category", default="malware")
    intel_source_add.add_argument("--confidence", type=int, default=90)
    intel_source_add.add_argument("--disabled", action="store_true")
    intel_source_add.add_argument("--allow-http", action="store_true")
    intel_source_add.add_argument("--json", action="store_true", help="Print JSON.")
    for source_action in ("remove", "enable", "disable"):
        parser_source_action = intel_source_commands.add_parser(
            source_action,
            help=f"{source_action.title()} a feed source.",
        )
        parser_source_action.add_argument("source_id")
        parser_source_action.add_argument("--json", action="store_true", help="Print JSON.")

    intel_update = intel_commands.add_parser("update", help="Fetch and activate configured feeds.")
    intel_update.add_argument("--source", default="")
    intel_update.add_argument("--all", action="store_true")
    intel_update.add_argument("--dry-run", action="store_true")
    intel_update.add_argument("--non-interactive", action="store_true")
    intel_update.add_argument("--json", action="store_true", help="Print JSON.")

    intel_status = intel_commands.add_parser("status", help="Show feed source status.")
    intel_status.add_argument("--json", action="store_true", help="Print JSON.")

    intel_rollback = intel_commands.add_parser("rollback", help="Rollback a source to the previous generation.")
    intel_rollback.add_argument("--source", required=True)
    intel_rollback.add_argument("--json", action="store_true", help="Print JSON.")

    intel_audit = intel_commands.add_parser("audit", help="List feed update audit records.")
    intel_audit.add_argument("--source", default="")
    intel_audit.add_argument("--limit", type=int, default=100)
    intel_audit.add_argument("--json", action="store_true", help="Print JSON.")

    rules = subcommands.add_parser(
        "rules",
        help="Manage manual allow/block domain rules.",
    )
    rule_commands = rules.add_subparsers(
        dest="rule_command",
        required=True,
    )

    rule_list = rule_commands.add_parser(
        "list",
        help="List active domain rules.",
    )
    rule_list.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum rules to show.",
    )
    rule_list.add_argument(
        "--q",
        default="",
        help="Search domains, sources, or reasons.",
    )
    rule_list.add_argument(
        "--decision",
        choices=[
            "allow",
            "block",
        ],
        default="",
        help="Filter by rule decision.",
    )

    for name in ("allow", "block"):
        rule_add = rule_commands.add_parser(
            name,
            help=f"Add or update a {name} rule.",
        )
        rule_add.add_argument(
            "domain",
            help="Domain to manage.",
        )
        rule_add.add_argument(
            "--reason",
            default="",
            help="Reason for the rule.",
        )

        if name == "block":
            rule_add.add_argument(
                "--apply",
                action="store_true",
                help="Also write the domain to the local blocklist helper.",
            )

    rule_remove = rule_commands.add_parser(
        "remove",
        help="Remove a domain rule.",
    )
    rule_remove.add_argument(
        "domain",
        help="Domain rule to remove.",
    )

    return parser


def main(
    argv: list[str] | None = None,
) -> int:
    """
    Run the requested PiHole-AI command.
    """

    args = build_parser().parse_args(argv)

    from core.logger import configure_logging

    configure_logging()

    if args.command in {"collect", "collector"}:
        from collector.scan import main as collector_main

        collector_main()
        return 0

    if args.command in {"run-engine", "engine"}:
        from engine.engine import AnalysisEngine

        AnalysisEngine().run_loop()
        return 0

    if args.command == "engine-once":
        from engine.run_engine import run as run_engine_once

        run_engine_once()
        return 0

    if args.command in {"config-path", "data-path", "log-path"}:
        from core.config import settings

        paths = {
            "config-path": settings.config_file,
            "data-path": settings.events_db,
            "log-path": settings.log_file,
        }
        print(paths[args.command])
        return 0

    if args.command == "dashboard":
        if args.dashboard_command == "auth":
            from pihole_ai.dashboard_auth import (
                DashboardAuthError,
                print_auth_status,
                set_auth_enabled,
                set_password,
            )

            try:
                if args.dashboard_auth_command == "status":
                    return print_auth_status(as_json=args.json)
                if args.dashboard_auth_command == "set-password":
                    return set_password(
                        password_stdin=args.password_stdin,
                        as_json=args.json,
                    )
                if args.dashboard_auth_command == "enable":
                    return set_auth_enabled(
                        enabled=True,
                        as_json=args.json,
                    )
                if args.dashboard_auth_command == "disable":
                    return set_auth_enabled(
                        enabled=False,
                        confirm_disable_auth=args.confirm_disable_auth,
                        as_json=args.json,
                    )
            except DashboardAuthError as exc:
                print(str(exc))
                return 1

        from ui.dashboard import main as dashboard_main

        dashboard_main(
            host=args.host,
            port=args.port,
        )
        return 0

    if args.command == "status":
        from pihole_ai.service import service_status

        service_status(
            include_ollama=args.ollama and not args.no_ollama,
            dry_run=args.dry_run,
        )
        return 0

    if args.command == "health":
        from pihole_ai.health import (
            exit_code_for_status,
            print_report,
            report_to_json,
            run_health_checks,
        )

        try:
            report = run_health_checks()

        except Exception as exc:
            if args.json:
                import json
                from pihole_ai.version import get_version

                print(
                    json.dumps(
                        {
                            "overall_status": "unknown",
                            "checks": [],
                            "version": get_version(),
                            "error": exc.__class__.__name__,
                        },
                        sort_keys=True,
                    )
                )
            else:
                print(f"PiHole-AI health: unknown ({exc.__class__.__name__})")

            return 3

        if args.json:
            print(report_to_json(report))
        else:
            print_report(report)

        return exit_code_for_status(report.overall_status)

    if args.command == "config":
        from pihole_ai.config_cli import print_config_check, print_config_show

        if args.config_command == "check":
            return print_config_check(
                mode=args.mode,
                as_json=args.json,
            )

        if args.config_command == "show":
            return print_config_show(
                as_json=args.json,
            )

    if args.command == "doctor":
        from pihole_ai.doctor import print_doctor

        return print_doctor(
            as_json=args.json,
        )

    if args.command == "setup":
        from pihole_ai.setup import print_setup_status, run_setup

        if args.setup_command == "status":
            return print_setup_status(
                as_json=args.json,
                skip_ollama_check=args.skip_ollama_check,
            )

        return run_setup(
            non_interactive=args.non_interactive,
            dry_run=args.dry_run,
            as_json=args.json,
            install=args.install,
            start=args.start,
            enable=args.enable,
            skip_ollama_check=args.skip_ollama_check,
        )

    if args.command == "db":
        import json
        from dataclasses import asdict

        from core.config import settings
        from core.migrations import (
            IncompatibleSchema,
            MigrationError,
            UnsupportedSchemaVersion,
            database_status,
            migrate_database,
        )

        if args.db_command == "status":
            try:
                status = database_status(settings.events_db)

            except (IncompatibleSchema, UnsupportedSchemaVersion) as exc:
                if args.json:
                    print(
                        json.dumps(
                            {
                                "compatible": False,
                                "database_path": str(settings.events_db),
                                "error": exc.__class__.__name__,
                            },
                            sort_keys=True,
                        )
                    )
                else:
                    print(f"Database schema is not compatible: {exc}")

                return 2

            except OSError as exc:
                if args.json:
                    print(
                        json.dumps(
                            {
                                "database_path": str(settings.events_db),
                                "error": exc.__class__.__name__,
                            },
                            sort_keys=True,
                        )
                    )
                else:
                    print(f"Database could not be accessed: {exc}")

                return 3

            if args.json:
                print(json.dumps(asdict(status), sort_keys=True))
            else:
                print(f"database_path: {status.database_path}")
                print(f"current_schema_version: {status.current_schema_version}")
                print(
                    "latest_supported_schema_version: "
                    f"{status.latest_supported_schema_version}"
                )
                print(f"pending_migration_count: {status.pending_migration_count}")
                print(f"database_file_size: {status.database_file_size}")
                print(f"compatible: {str(status.compatible).lower()}")

            return 0

        if args.db_command == "migrate":
            try:
                result = migrate_database(settings.events_db)

            except (IncompatibleSchema, UnsupportedSchemaVersion) as exc:
                if args.json:
                    print(
                        json.dumps(
                            {
                                "database_path": str(settings.events_db),
                                "error": exc.__class__.__name__,
                            },
                            sort_keys=True,
                        )
                    )
                else:
                    print(f"Database schema is not compatible: {exc}")

                return 2

            except OSError as exc:
                if args.json:
                    print(
                        json.dumps(
                            {
                                "database_path": str(settings.events_db),
                                "error": exc.__class__.__name__,
                            },
                            sort_keys=True,
                        )
                    )
                else:
                    print(f"Database could not be accessed: {exc}")

                return 3

            except MigrationError as exc:
                if args.json:
                    print(
                        json.dumps(
                            {
                                "database_path": str(settings.events_db),
                                "error": exc.__class__.__name__,
                            },
                            sort_keys=True,
                        )
                    )
                else:
                    print(f"Database migration failed: {exc}")

                return 1

            if args.json:
                print(json.dumps(asdict(result), sort_keys=True))
            elif result.changed:
                applied = ", ".join(
                    f"{migration.version}:{migration.name}"
                    for migration in result.applied_migrations
                )
                print(
                    "Applied database migrations: "
                    f"{applied} "
                    f"({result.version_before} -> {result.version_after})."
                )
            else:
                print(
                    "Database schema is current "
                    f"(version {result.version_after})."
                )

            return 0

    if args.command == "explain":
        from pihole_ai.explain import print_explanation

        print_explanation(
            domain=args.domain,
            as_json=args.json,
            history=args.history,
            decision_id=args.decision,
            compare=tuple(args.compare) if args.compare else None,
        )
        return 0

    if args.command == "feedback":
        from pihole_ai.feedback import print_feedback

        print_feedback(
            domain=args.domain,
            verdict=args.verdict,
            reason=args.reason,
            promote=args.promote,
            apply_block=args.apply,
        )
        return 0

    if args.command == "evaluate":
        from pihole_ai.evaluate import print_benchmark

        print_benchmark(
            path=args.path,
            risk_tolerance=args.risk_tolerance,
            include_ai=args.include_ai,
            as_json=args.json,
        )
        return 0

    if args.command == "service":
        from pihole_ai.service import ServiceError, service_install, service_uninstall

        try:
            if args.service_command == "install":
                service_install(
                    dry_run=args.dry_run,
                )
                return 0

            if args.service_command == "uninstall":
                service_uninstall(
                    dry_run=args.dry_run,
                )
                return 0

        except ServiceError as exc:
            print(str(exc))
            return 1

    if args.command in {"install", "uninstall", "upgrade"}:
        import io
        import json
        import sys
        from contextlib import redirect_stdout

        from pihole_ai.service import (
            ServiceError,
            print_installation_status,
            service_install,
            service_uninstall,
            service_upgrade,
        )

        def run_json_service_command(command):
            captured = io.StringIO()
            with redirect_stdout(captured):
                result = command()
            human_output = captured.getvalue()
            if human_output:
                print(human_output, end="", file=sys.stderr)
            print(json.dumps(result.to_dict(), sort_keys=True))

        try:
            if args.command == "install":
                if getattr(args, "install_command", None) == "status":
                    return print_installation_status(
                        as_json=args.json,
                    )

                install_kwargs = {"dry_run": args.dry_run}
                if args.no_enable:
                    install_kwargs["enable_services"] = False
                if args.no_start:
                    install_kwargs["start_services"] = False

                if args.json:
                    run_json_service_command(lambda: service_install(**install_kwargs))
                else:
                    service_install(**install_kwargs)
                return 0

            if args.command == "uninstall":
                uninstall_kwargs = {"dry_run": args.dry_run}
                if args.purge:
                    uninstall_kwargs["purge"] = True
                if args.confirm_purge:
                    uninstall_kwargs["confirm_purge"] = True

                if args.json:
                    run_json_service_command(lambda: service_uninstall(**uninstall_kwargs))
                else:
                    service_uninstall(**uninstall_kwargs)
                return 0

            if args.json:
                run_json_service_command(
                    lambda: service_upgrade(
                        dry_run=args.dry_run,
                        as_json=False,
                    )
                )
            else:
                service_upgrade(
                    dry_run=args.dry_run,
                    as_json=False,
                )
            return 0

        except ServiceError as exc:
            print(str(exc))
            return 1

    if args.command in {"enable", "disable"}:
        from pihole_ai.service import ServiceError, service_disable, service_enable

        try:
            if args.command == "enable":
                service_enable(
                    dry_run=args.dry_run,
                )
                return 0

            service_disable(
                dry_run=args.dry_run,
            )
            return 0

        except ServiceError as exc:
            print(str(exc))
            return 1

    if args.command in {"start", "stop", "restart"}:
        from pihole_ai.service import ServiceError, service_action

        try:
            service_action(
                action=args.command,
                dry_run=args.dry_run,
            )
            return 0

        except ServiceError as exc:
            print(str(exc))
            return 1

    if args.command == "logs":
        from pihole_ai.service import ServiceError, service_logs

        try:
            service_logs(
                lines=args.lines,
                follow=args.follow,
                dry_run=args.dry_run,
            )
            return 0

        except ServiceError as exc:
            print(str(exc))
            return 1

    if args.command == "export":
        from pihole_ai.export import export_rows

        count = export_rows(
            dataset=args.dataset,
            export_format=args.format,
            path=args.output,
            limit=args.limit,
            search=args.q,
            min_risk=args.min_risk,
            category=args.category,
        )

        if args.output is not None:
            print(
                f"Exported {count} row(s) to {args.output}."
            )

        return 0

    if args.command == "maintenance":
        import json

        from core.maintenance import run_decision_history_maintenance, run_maintenance

        if args.maintenance_command == "decision-history":
            result = run_decision_history_maintenance(
                dry_run=args.dry_run,
            )
            if args.json:
                print(json.dumps(result.to_dict(), sort_keys=True))
            else:
                print(
                    "Decision-history maintenance complete: "
                    f"domains_inspected={result.domains_inspected}, "
                    f"decisions_inspected={result.decisions_inspected}, "
                    f"decisions_eligible={result.decisions_eligible}, "
                    f"decisions_deleted={result.decisions_deleted}, "
                    f"evidence_rows_deleted={result.evidence_rows_deleted}, "
                    f"dry_run={result.dry_run}"
                )
            return 0

        result = run_maintenance(
            keep_latest=args.keep_latest,
            vacuum_db=args.vacuum,
        )
        print(
            "Maintenance complete: "
            f"deleted_events={result.deleted_events}, "
            f"events_before={result.before['events']}, "
            f"events_after={result.after['events']}, "
            f"vacuumed={result.vacuumed}"
        )
        return 0

    if args.command == "learn":
        from pihole_ai.learn import print_learned

        print_learned(
            limit=args.limit,
            min_score=args.min_score,
            audit=not args.no_audit,
        )
        return 0

    if args.command == "intel":
        import json

        from core.db import (
            get_intel_source,
            list_intel_sources,
            list_intel_update_audit,
            remove_intel_source,
            set_intel_source_enabled,
        )
        from pihole_ai.intel import (
            add_source,
            get_intel_rows,
            import_hosts_file,
            print_intel,
            rollback_source,
            source_status,
            update_sources,
        )

        if args.intel_command == "import-hosts":
            count = import_hosts_file(
                path=args.path,
                source=args.source,
                category=args.category,
                confidence=args.confidence,
            )
            print(
                f"Imported {count} threat-intel domain(s) from {args.path}."
            )
            return 0

        if args.intel_command == "list":
            if args.json:
                print(json.dumps(get_intel_rows(args.limit, args.q, args.source, args.category), sort_keys=True))
            else:
                print_intel(
                    limit=args.limit,
                    search=args.q,
                    source=args.source,
                    category=args.category,
                )
            return 0

        if args.intel_command == "source":
            if args.intel_source_command == "list":
                rows = list_intel_sources()
                if args.json:
                    print(json.dumps(rows, sort_keys=True))
                else:
                    for row in rows:
                        enabled = "enabled" if row["enabled"] else "disabled"
                        print(f"{row['source_id']} {enabled} {row['format']} {row['url']}")
                return 0
            if args.intel_source_command == "show":
                row = get_intel_source(args.source_id)
                if row is None:
                    print("Feed source not found.")
                    return 1
                if args.json:
                    print(json.dumps(row, sort_keys=True))
                else:
                    for key, value in row.items():
                        print(f"{key}: {value}")
                return 0
            if args.intel_source_command == "add":
                source = add_source(
                    source_id=args.source_id,
                    name=args.name,
                    url=args.url,
                    feed_format=args.format,
                    category=args.category,
                    confidence=args.confidence,
                    enabled=not args.disabled,
                    allow_http=args.allow_http,
                )
                if args.json:
                    print(json.dumps(source.to_dict(), sort_keys=True))
                else:
                    print(f"Saved feed source {source.source_id}.")
                return 0
            if args.intel_source_command == "remove":
                removed = remove_intel_source(args.source_id)
                if args.json:
                    print(json.dumps({"removed": removed}, sort_keys=True))
                else:
                    print("Removed feed source." if removed else "Feed source not found.")
                return 0 if removed else 1
            if args.intel_source_command in {"enable", "disable"}:
                enabled = args.intel_source_command == "enable"
                set_intel_source_enabled(args.source_id, enabled)
                if args.json:
                    print(json.dumps({"source_id": args.source_id, "enabled": enabled}, sort_keys=True))
                else:
                    print(f"{'Enabled' if enabled else 'Disabled'} feed source {args.source_id}.")
                return 0

        if args.intel_command == "update":
            try:
                results = update_sources(
                    source_id=args.source or None,
                    all_sources=args.all,
                    dry_run=args.dry_run,
                )
            except RuntimeError as exc:
                print(str(exc))
                return 1
            payload = [result.to_dict() for result in results]
            if args.json:
                print(json.dumps(payload, sort_keys=True))
            else:
                for result in results:
                    status = "ok" if result.success else result.error_code
                    print(
                        f"{result.source_id}: {status} changed={result.changed} "
                        f"accepted={result.accepted_entries} active={result.active_generation}"
                    )
            return 0 if all(result.success for result in results) else 1

        if args.intel_command == "status":
            rows = source_status()
            if args.json:
                print(json.dumps(rows, sort_keys=True))
            else:
                if not rows:
                    print("No feed sources configured.")
                for row in rows:
                    print(
                        f"{row['source_id']} status={row.get('status') or 'unknown'} "
                        f"enabled={bool(row['enabled'])} entries={row.get('entry_count') or 0} "
                        f"active={row.get('active_generation') or ''}"
                    )
            return 0

        if args.intel_command == "rollback":
            generation = rollback_source(args.source)
            if generation is None:
                if args.json:
                    print(json.dumps({"rolled_back": False, "error": "intel.rollback.unavailable"}, sort_keys=True))
                else:
                    print("Rollback unavailable.")
                return 1
            if args.json:
                print(json.dumps({"rolled_back": True, "active_generation": generation}, sort_keys=True))
            else:
                print(f"Rolled back {args.source} to {generation}.")
            return 0

        if args.intel_command == "audit":
            rows = list_intel_update_audit(limit=args.limit, source_id=args.source)
            if args.json:
                print(json.dumps(rows, sort_keys=True))
            else:
                if not rows:
                    print("No feed update audit records.")
                for row in rows:
                    print(
                        f"{row['source_id']} result={row['result']} "
                        f"changed={row['changed']} accepted={row['accepted_entries']} "
                        f"error={row['error_code']}"
                    )
            return 0

    if args.command == "rules":
        from pihole_ai.rules import add_rule, print_rules, remove_rule

        if args.rule_command == "list":
            print_rules(
                limit=args.limit,
                search=args.q,
                decision=args.decision,
            )
            return 0

        if args.rule_command in {"allow", "block"}:
            add_rule(
                domain=args.domain,
                decision=args.rule_command,
                reason=args.reason,
                apply_block=getattr(args, "apply", False),
            )
            print(
                f"Saved {args.rule_command} rule for {args.domain}."
            )
            return 0

        if args.rule_command == "remove":
            removed = remove_rule(
                args.domain,
            )

            if removed:
                print(
                    f"Removed rule for {args.domain}."
                )
            else:
                print(
                    f"No rule found for {args.domain}."
                )

            return 0

    raise RuntimeError(
        f"Unknown command: {args.command}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
