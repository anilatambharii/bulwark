"""Bulwark command-line interface.

A minimal CLI for inspecting configuration and running smoke tests against
the security pipeline. Designed to be invoked as ``bulwark <subcommand>``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Sequence

from bulwark import __version__
from bulwark.core.detector import DetectorConfig, InjectionDetector
from bulwark.core.sanitizer import InputSanitizer, SanitizerConfig
from bulwark.utils.crypto import generate_audit_key


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bulwark",
        description="Bulwark Agent Security Framework — CLI utilities.",
    )
    parser.add_argument("--version", action="version", version=f"bulwark {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan text for prompt injection signals.")
    p_scan.add_argument("text", nargs="?", help="Text to scan (omit to read from stdin).")
    p_scan.add_argument("--threshold", type=float, default=0.7)
    p_scan.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")

    p_sanitize = sub.add_parser("sanitize", help="Sanitize text and print the cleaned form.")
    p_sanitize.add_argument("text", nargs="?", help="Text to sanitize (omit to read from stdin).")
    p_sanitize.add_argument("--json", action="store_true")

    sub.add_parser("genkey", help="Generate a fresh audit-trail encryption key.")

    return parser


async def _run_scan(text: str, threshold: float, as_json: bool) -> int:
    detector = InjectionDetector(DetectorConfig(threshold=threshold))
    result = await detector.detect(text)
    if as_json:
        sys.stdout.write(result.model_dump_json() + "\n")
    else:
        verdict = "INJECTION" if result.is_injection else "clean"
        sys.stdout.write(f"[{verdict}] score={result.score:.2f} "
                         f"patterns={result.patterns} "
                         f"explanation={result.explanation}\n")
    return 1 if result.is_injection else 0


async def _run_sanitize(text: str, as_json: bool) -> int:
    sanitizer = InputSanitizer(SanitizerConfig())
    result = await sanitizer.sanitize(text)
    if as_json:
        sys.stdout.write(result.model_dump_json() + "\n")
    else:
        sys.stdout.write(result.filtered_text + "\n")
        sys.stderr.write(
            f"# risk={result.risk_score:.2f} bytes_removed={result.bytes_removed} "
            f"patterns={result.detected_patterns}\n"
        )
    return 0


def _read_text(arg: str | None) -> str:
    if arg is not None:
        return arg
    return sys.stdin.read()


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return asyncio.run(_run_scan(_read_text(args.text), args.threshold, args.json))
    if args.command == "sanitize":
        return asyncio.run(_run_sanitize(_read_text(args.text), args.json))
    if args.command == "genkey":
        sys.stdout.write(generate_audit_key() + "\n")
        return 0
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
