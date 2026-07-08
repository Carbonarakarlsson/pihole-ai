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
        "collector",
        help="Run the continuous Pi-hole query collector.",
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
        "dashboard",
        help="Run the dashboard web server.",
    )
    status = subcommands.add_parser(
        "status",
        help="Print runtime status.",
    )
    status.add_argument(
        "--no-ollama",
        action="store_true",
        help="Skip Ollama health check.",
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

    if args.command == "collector":
        from collector.scan import main as collector_main

        collector_main()
        return 0

    if args.command == "engine":
        from engine.engine import AnalysisEngine

        AnalysisEngine().run_loop()
        return 0

    if args.command == "engine-once":
        from engine.run_engine import run as run_engine_once

        run_engine_once()
        return 0

    if args.command == "dashboard":
        from ui.dashboard import main as dashboard_main

        dashboard_main()
        return 0

    if args.command == "status":
        from pihole_ai.status import print_status

        print_status(
            include_ollama=not args.no_ollama,
        )
        return 0

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
