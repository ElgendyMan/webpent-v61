"""bbscout command-line interface.

The CLI deliberately has no scan, crawl, exploit, report-submission, or token CLI
argument. It is a catalog and authorization-package tool only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .errors import BBScoutError
from .integrity import read_json, write_json
from .models import CapabilityProfile, dataclass_to_dict
from .packages import build_target_package, verify_target_package
from .providers.hackerone import HackerOneProvider
from .providers.hackerone_fixture import HackerOneFixtureProvider
from .scope import compile_scope
from .scoring import score_program

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FIXTURES = PROJECT_ROOT / "fixtures" / "hackerone"


def _table(headers: list[str], rows: list[list[object]]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(str(value)))
    separator = "+" + "+".join("-" * (width + 2) for width in widths) + "+"
    output = [
        separator,
        "|"
        + "|".join(f" {headers[index]:<{widths[index]}} " for index in range(len(headers)))
        + "|",
        separator,
    ]
    for row in rows:
        output.append(
            "|"
            + "|".join(f" {str(row[index]):<{widths[index]}} " for index in range(len(headers)))
            + "|"
        )
    output.append(separator)
    return "\n".join(output)


def _emit(value: Any, fmt: str = "json") -> None:
    if fmt == "json":
        print(json.dumps(dataclass_to_dict(value), indent=2, ensure_ascii=False, sort_keys=True))
    else:
        if isinstance(value, list):
            print(
                _table(
                    ["provider", "handle", "status", "visibility"],
                    [[item.provider, item.handle, item.status, item.visibility] for item in value],
                )
            )
        else:
            print(
                json.dumps(dataclass_to_dict(value), indent=2, ensure_ascii=False, sort_keys=True)
            )


def _provider(args: argparse.Namespace):
    if args.provider != "hackerone":
        raise BBScoutError(f"Provider '{args.provider}' لسه مش متنفذ في الـ MVP.")
    if args.mode == "fixture":
        return HackerOneFixtureProvider(Path(args.fixture_dir))
    return HackerOneProvider()


def _program_and_scope(args: argparse.Namespace):
    provider = _provider(args)
    program = provider.get_program(args.program_id)
    scope = compile_scope(provider.get_scope(args.program_id), max_age_days=args.max_scope_age_days)
    return provider, program, scope


def cmd_providers_list(_: argparse.Namespace) -> int:
    rows = [
        ["hackerone", "implemented", "fixture + live read-only", "GET only"],
        ["bugcrowd", "planned", "not enabled", "no API calls"],
        ["intigriti", "planned", "not enabled", "no API calls"],
        ["yeswehack", "planned", "not enabled", "no API calls"],
    ]
    print(_table(["provider", "status", "mode", "write operations"], rows))
    return 0


def cmd_auth_login(args: argparse.Namespace) -> int:
    if args.provider != "hackerone":
        raise BBScoutError("في النسخة دي، login متاح كتعليمات لـ HackerOne فقط.")
    print(
        "bbscout لا يستقبل token كـ argument ولا يخزنه في المشروع. "
        "اضبط BBSCOUT_HACKERONE_TOKEN_ID وBBSCOUT_HACKERONE_TOKEN في "
        "session environment أو secret manager، "
        "ثم استخدم --mode live مع auth status."
    )
    return 0


def cmd_auth_status(args: argparse.Namespace) -> int:
    if args.mode == "fixture":
        print(
            _table(
                ["provider", "authenticated", "detail"],
                [["hackerone", "n/a", "fixture mode; no network and no credential"]],
            )
        )
        return 0
    provider = HackerOneProvider()
    health = provider.health_check()
    print(
        _table(
            ["provider", "healthy", "detail"], [[health.provider, health.healthy, health.detail]]
        )
    )
    return 0


def cmd_discover(args: argparse.Namespace) -> int:
    programs = _provider(args).list_accessible_programs()
    _emit(programs, args.format)
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    provider, program, scope = _program_and_scope(args)
    output: dict[str, Any] = {
        "program": dataclass_to_dict(program),
        "scope_assessment": dataclass_to_dict(scope),
    }
    if args.policy:
        output["policy"] = provider.get_policy(args.program_id)
    if args.scope:
        output["scope_assets"] = [
            dataclass_to_dict(item) for item in provider.get_scope(args.program_id)
        ]
    _emit(output, "json")
    return 0


def _load_profile(path: str) -> CapabilityProfile:
    return CapabilityProfile.from_dict(read_json(path))


def _score_all(args: argparse.Namespace) -> list[dict[str, Any]]:
    provider = _provider(args)
    profile = _load_profile(args.webpent_profile)
    results: list[dict[str, Any]] = []
    for program in provider.list_accessible_programs():
        scope = compile_scope(
            provider.get_scope(program.handle), max_age_days=args.max_scope_age_days
        )
        score = score_program(program, scope, profile)
        results.append(
            {
                "program": dataclass_to_dict(program),
                "scope": dataclass_to_dict(scope),
                "score": dataclass_to_dict(score),
            }
        )
    return sorted(
        results,
        key=lambda item: (item["score"]["score"] is not None, item["score"]["score"] or -1),
        reverse=True,
    )


def cmd_score(args: argparse.Namespace) -> int:
    results = _score_all(args)
    if args.format == "table":
        rows = []
        for item in results:
            score = item["score"]
            rows.append(
                [
                    item["program"]["handle"],
                    score["eligibility"],
                    "--" if score["score"] is None else score["score"],
                    score["confidence"],
                    (score["reasons"] or score["blockers"] or ["no reason"])[0],
                ]
            )
        print(_table(["program", "eligibility", "score", "confidence", "primary reason"], rows))
    else:
        _emit(results, "json")
    return 0


def cmd_recommend(args: argparse.Namespace) -> int:
    results = _score_all(args)
    eligible = [item for item in results if item["score"]["eligibility"] == "eligible"]
    chosen = eligible[: args.top]
    if not chosen:
        print("لا توجد برامج مؤهلة. راجع blockers في programs score.")
        return 2
    rows = []
    for item in chosen:
        score = item["score"]
        rows.append(
            [
                item["program"]["provider"],
                item["program"]["handle"],
                score["score"],
                score["confidence"],
                (score["reasons"] or ["سبب غير متاح"])[0],
            ]
        )
    print(_table(["provider", "program", "score", "confidence", "why selected"], rows))
    print(
        "لا يتم تشغيل WebPent تلقائيًا. لازم تبني package باستخدام --confirm "
        "بعد مراجعة الـ scope والـ policy."
    )
    return 0


def cmd_package_build(args: argparse.Namespace) -> int:
    provider, program, scope = _program_and_scope(args)
    profile = _load_profile(args.webpent_profile)
    score = score_program(program, scope, profile)
    raw_sources = (
        provider.raw_bundle(args.program_id)
        if hasattr(provider, "raw_bundle")
        else {
            "adapter_version": provider.adapter_version,
            "program": dataclass_to_dict(program),
            "structured_scopes": [
                dataclass_to_dict(item) for item in provider.get_scope(args.program_id)
            ],
        }
    )
    package = build_target_package(
        program=program,
        scope=scope,
        score=score,
        profile=profile,
        raw_sources=raw_sources,
        confirmed_by_user=args.confirm,
        expires_in_hours=args.expires_in_hours,
    )
    write_json(args.output, package)
    print(
        json.dumps(
            {
                "built": args.output,
                "sha256": package["integrity"]["content_sha256"],
                "expires_at": package["authorization"]["package_expires_at"],
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


def cmd_package_verify(args: argparse.Namespace) -> int:
    result = verify_target_package(read_json(args.package))
    _emit(result, "json")
    return 0


def cmd_scope_validate(args: argparse.Namespace) -> int:
    package = read_json(args.package)
    result = verify_target_package(package)
    print(
        json.dumps(
            {
                "scope_status": package["scope"]["status"],
                "include_count": package["scope"]["include_count"],
                "exclusion_count": package["scope"]["exclusion_count"],
                "package": result,
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    checks = [
        ["fixture directory", Path(args.fixture_dir).exists(), str(Path(args.fixture_dir))],
        [
            "HackerOne token id",
            bool(os.environ.get("BBSCOUT_HACKERONE_TOKEN_ID")),
            "environment reference only",
        ],
        [
            "HackerOne token",
            bool(os.environ.get("BBSCOUT_HACKERONE_TOKEN")),
            "environment reference only",
        ],
        ["write operations", True, "not implemented"],
    ]
    print(_table(["check", "status", "detail"], checks))
    return 0


def _add_provider_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--provider",
        default="hackerone",
        choices=["hackerone", "bugcrowd", "intigriti", "yeswehack"],
    )
    parser.add_argument("--mode", default="fixture", choices=["fixture", "live"])
    parser.add_argument("--fixture-dir", default=str(DEFAULT_FIXTURES))
    parser.add_argument("--max-scope-age-days", type=int, default=90)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bbscout", description="Read-only, fail-closed bug-bounty program selector"
    )
    root = parser.add_subparsers(dest="root", required=True)

    providers = root.add_parser("providers")
    providers_sub = providers.add_subparsers(dest="providers_command", required=True)
    providers_sub.add_parser("list").set_defaults(func=cmd_providers_list)

    auth = root.add_parser("auth")
    auth_sub = auth.add_subparsers(dest="auth_command", required=True)
    login = auth_sub.add_parser("login")
    login.add_argument(
        "--provider", required=True, choices=["hackerone", "bugcrowd", "intigriti", "yeswehack"]
    )
    login.set_defaults(func=cmd_auth_login)
    status = auth_sub.add_parser("status")
    status.add_argument("--all", action="store_true")
    status.add_argument("--mode", default="fixture", choices=["fixture", "live"])
    status.set_defaults(func=cmd_auth_status)

    programs = root.add_parser("programs")
    programs_sub = programs.add_subparsers(dest="programs_command", required=True)
    discover = programs_sub.add_parser("discover")
    _add_provider_options(discover)
    discover.add_argument("--format", default="table", choices=["table", "json"])
    discover.set_defaults(func=cmd_discover)

    inspect = programs_sub.add_parser("inspect")
    _add_provider_options(inspect)
    inspect.add_argument("program_id")
    inspect.add_argument("--policy", action="store_true")
    inspect.add_argument("--scope", action="store_true")
    inspect.set_defaults(func=cmd_inspect)

    score = programs_sub.add_parser("score")
    _add_provider_options(score)
    score.add_argument("--webpent-profile", required=True)
    score.add_argument("--format", default="table", choices=["table", "json"])
    score.set_defaults(func=cmd_score)

    recommend = programs_sub.add_parser("recommend")
    _add_provider_options(recommend)
    recommend.add_argument("--webpent-profile", required=True)
    recommend.add_argument("--top", type=int, default=5)
    recommend.add_argument("--explain", action="store_true")
    recommend.set_defaults(func=cmd_recommend)

    package = root.add_parser("package")
    package_sub = package.add_subparsers(dest="package_command", required=True)
    package_build = package_sub.add_parser("build")
    _add_provider_options(package_build)
    package_build.add_argument("program_id")
    package_build.add_argument("--webpent-profile", required=True)
    package_build.add_argument("--output", required=True)
    package_build.add_argument("--confirm", action="store_true")
    package_build.add_argument("--expires-in-hours", type=int, default=168)
    package_build.set_defaults(func=cmd_package_build)
    package_verify = package_sub.add_parser("verify")
    package_verify.add_argument("package")
    package_verify.set_defaults(func=cmd_package_verify)

    scope = root.add_parser("scope")
    scope_sub = scope.add_subparsers(dest="scope_command", required=True)
    scope_validate = scope_sub.add_parser("validate")
    scope_validate.add_argument("package")
    scope_validate.set_defaults(func=cmd_scope_validate)

    doctor = root.add_parser("doctor")
    doctor.add_argument("--redacted", action="store_true")
    doctor.add_argument("--fixture-dir", default=str(DEFAULT_FIXTURES))
    doctor.set_defaults(func=cmd_doctor)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except BBScoutError as exc:
        print(json.dumps({"error": exc.to_dict()}, ensure_ascii=False), file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(
            json.dumps(
                {"error": {"code": "file_not_found", "message": str(exc)}}, ensure_ascii=False
            ),
            file=sys.stderr,
        )
        return 2
    except Exception as exc:  # Final fail-closed boundary; no credentials are printed.
        print(
            json.dumps(
                {"error": {"code": "unexpected_error", "message": str(exc)}}, ensure_ascii=False
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
