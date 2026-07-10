"""
Command line interface for PiHole-AI.
"""

from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    """
    Build the PiHole-AI CLI parser.
    """

    parser = argparse.ArgumentParser(
        prog="pihole-ai",
        description="Run PiHole-AI services and maintenance tasks.",
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
        from pihole_ai.service import (
            ServiceError,
            print_installation_status,
            service_install,
            service_uninstall,
            service_upgrade,
        )

        try:
            if args.command == "install":
                if getattr(args, "install_command", None) == "status":
                    return print_installation_status(
                        as_json=args.json,
                    )

                install_kwargs = {"dry_run": args.dry_run}
                if args.json:
                    install_kwargs["as_json"] = True
                if args.no_enable:
                    install_kwargs["enable_services"] = False
                if args.no_start:
                    install_kwargs["start_services"] = False

                service_install(**install_kwargs)
                return 0

            if args.command == "uninstall":
                uninstall_kwargs = {"dry_run": args.dry_run}
                if args.json:
                    uninstall_kwargs["as_json"] = True
                if args.purge:
                    uninstall_kwargs["purge"] = True
                if args.confirm_purge:
                    uninstall_kwargs["confirm_purge"] = True

                service_uninstall(**uninstall_kwargs)
                return 0

            service_upgrade(
                dry_run=args.dry_run,
                as_json=args.json,
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
        from core.maintenance import run_maintenance

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
        from pihole_ai.intel import import_hosts_file, print_intel

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
            print_intel(
                limit=args.limit,
                search=args.q,
                source=args.source,
                category=args.category,
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
