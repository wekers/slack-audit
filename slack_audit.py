#!/usr/bin/env python3
"""slack-audit: read-only Slackware security-advisory checker.

Version 0.1.0. Uses only the Python standard library.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

VERSION = "0.1.0"
DEFAULT_PACKAGES_DIR = Path("/var/log/packages")
DEFAULT_CHANGELOG = Path("/var/lib/slackpkg/ChangeLog.txt")
PACKAGE_SUFFIXES = (".txz", ".tgz", ".tbz", ".tlz")

# Slackware ChangeLog package entries look like:
#   n/openssl-3.5.4-x86_64-1_slack15.0.txz: Upgraded.
CHANGELOG_PACKAGE_RE = re.compile(
    r"^\s*(?P<path>[^\s:]+\.(?:txz|tgz|tbz|tlz)):\s*(?P<action>.*)$",
    re.IGNORECASE,
)
DATE_HEADER_RE = re.compile(
    r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\d{4}$"
)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s)<>]+", re.IGNORECASE)
SECURITY_RE = re.compile(
    r"\(\*\s*security\s+fix\s*\*\)|"
    r"\bsecurity\s+(?:fix|issues?|update|vulnerabilit(?:y|ies))\b|"
    r"\bvulnerabilit(?:y|ies)\b|"
    r"\bCVE-\d{4}-\d{4,}\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    arch: str
    build: str
    raw: str
    source: str = ""

    @property
    def version_build(self) -> str:
        return f"{self.version}-{self.build}"


@dataclass(frozen=True)
class SecurityEntry:
    package: Package
    date: str
    action: str
    details: str
    cves: tuple[str, ...]
    urls: tuple[str, ...]


@dataclass(frozen=True)
class Finding:
    status: str
    installed: Package
    fixed: Package
    date: str
    cves: tuple[str, ...]
    urls: tuple[str, ...]
    details: str


def parse_package_name(raw_name: str, source: str = "") -> Package | None:
    """Parse PRGNAM-VERSION-ARCH-BUILD from an installed record/txz name.

    The package name can itself contain hyphens. Slackware's conventional
    filename layout puts VERSION, ARCH and BUILD in the final three fields.
    """
    raw = Path(raw_name).name
    for suffix in PACKAGE_SUFFIXES:
        if raw.lower().endswith(suffix):
            raw = raw[: -len(suffix)]
            break
    fields = raw.rsplit("-", 3)
    if len(fields) != 4 or not all(fields):
        return None
    name, version, arch, build = fields
    # Official and common Slackware architectures. Also accept future/custom
    # architecture labels containing a digit (e.g. riscv64, armv7hl).
    known_arches = {"noarch", "arm", "ppc", "powerpc"}
    if not (arch.lower() in known_arches or re.search(r"\d", arch)):
        return None
    # Build/revision labels conventionally begin with a number (1, 2alien,
    # 1_SBo, 1_slack15.0, ...). This rejects arbitrary hyphenated text.
    if not build[0].isdigit():
        return None
    if not re.fullmatch(r"[A-Za-z0-9_.+]+", arch):
        return None
    return Package(name=name, version=version, arch=arch, build=build,
                   raw=Path(raw_name).name, source=source)


def load_installed_packages(packages_dir: Path) -> tuple[list[Package], list[str]]:
    """Read the Slackware pkgtools database in /var/log/packages."""
    if not packages_dir.is_dir():
        raise FileNotFoundError(f"package database directory not found: {packages_dir}")
    packages: list[Package] = []
    skipped: list[str] = []
    for item in sorted(packages_dir.iterdir(), key=lambda p: p.name.lower()):
        if not item.is_file() or item.name.startswith("."):
            continue
        parsed = parse_package_name(item.name, source=str(item))
        if parsed is None:
            skipped.append(item.name)
        else:
            packages.append(parsed)
    return packages, skipped


def _flush_changelog_entry(current: dict | None, entries: list[SecurityEntry]) -> None:
    if not current:
        return
    details = "\n".join(current["details"]).strip()
    evidence = "\n".join((current["action"], details))
    if not SECURITY_RE.search(evidence):
        return
    cves = tuple(sorted({match.upper() for match in CVE_RE.findall(evidence)}))
    urls = tuple(dict.fromkeys(URL_RE.findall(evidence)))
    entries.append(
        SecurityEntry(
            package=current["package"],
            date=current["date"],
            action=current["action"].strip(),
            details=details,
            cves=cves,
            urls=urls,
        )
    )


def parse_changelog(text: str) -> list[SecurityEntry]:
    """Extract security-marked package records from Slackware ChangeLog.txt.

    Slackware ChangeLog files are newest-first. A security marker/CVE is
    associated with the immediately preceding package record, ending at the
    next package record, date header, or ChangeLog separator. This deliberately
    favors precision over guessing when a description is ambiguous.
    """
    entries: list[SecurityEntry] = []
    current_date = "unknown"
    current: dict | None = None

    for line in text.splitlines():
        stripped = line.strip()
        if DATE_HEADER_RE.match(stripped):
            _flush_changelog_entry(current, entries)
            current = None
            current_date = stripped
            continue
        if stripped.startswith("+---"):
            _flush_changelog_entry(current, entries)
            current = None
            continue

        match = CHANGELOG_PACKAGE_RE.match(line)
        if match:
            _flush_changelog_entry(current, entries)
            current = None
            parsed = parse_package_name(match.group("path"))
            if parsed is not None:
                current = {
                    "package": parsed,
                    "date": current_date,
                    "action": match.group("action"),
                    "details": [],
                }
            continue

        if current is not None and stripped:
            current["details"].append(stripped)

    _flush_changelog_entry(current, entries)
    return entries


def _sort_version_compare(left: str, right: str) -> int:
    """Best-effort GNU sort -V comparison, with a stdlib fallback.

    This is a practical natural-version ordering, not a claim to reproduce all
    pkgtools/slackpkg decisions. In ambiguous/custom-tag cases, operators
    should review the package manually.
    """
    if left == right:
        return 0
    try:
        proc = subprocess.run(
            ["sort", "-V"], input=f"{left}\n{right}\n", text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )
        ordered = proc.stdout.splitlines()
        if len(ordered) >= 2:
            if ordered[0] == left and ordered[-1] == right:
                return -1
            if ordered[0] == right and ordered[-1] == left:
                return 1
    except (OSError, subprocess.SubprocessError):
        pass

    def key(value: str) -> tuple:
        parts = re.findall(r"\d+|[A-Za-z]+", value)
        return tuple((0, int(part)) if part.isdigit() else (1, part.lower())
                     for part in parts)

    a, b = key(left), key(right)
    return (a > b) - (a < b)


def compare_package_versions(installed: Package, fixed: Package) -> int:
    """Compare installed vs fixed release (-1 older, 0 same, 1 newer)."""
    return _sort_version_compare(installed.version_build, fixed.version_build)


def _arch_matches(installed_arch: str, fixed_arch: str) -> bool:
    # A noarch advisory package applies to all installed architectures. The
    # reverse is not assumed: an x86_64 fix is not automatically a fix for a
    # separately-built noarch/custom package.
    return installed_arch == fixed_arch or fixed_arch == "noarch"


def audit_packages(installed: Iterable[Package], security_entries: Iterable[SecurityEntry]) -> tuple[list[Finding], int]:
    """Correlate installed packages with the newest security entry per name."""
    installed_by_name: dict[str, list[Package]] = {}
    for package in installed:
        installed_by_name.setdefault(package.name, []).append(package)

    # ChangeLog.txt is newest-first. Keep the first security entry per package.
    latest_security: dict[str, SecurityEntry] = {}
    for entry in security_entries:
        latest_security.setdefault(entry.package.name, entry)

    findings: list[Finding] = []
    matched_names = 0

    for name, entry in latest_security.items():
        local = installed_by_name.get(name, [])
        if not local:
            continue
        arch_candidates = [p for p in local if _arch_matches(p.arch, entry.package.arch)]
        if not arch_candidates:
            continue
        matched_names += 1
        # Check every installed record independently. Slackware can retain
        # multiple kernel package versions side by side; an older installed
        # record should not be hidden merely because a newer one also exists.
        comparisons = [(pkg, compare_package_versions(pkg, entry.package))
                       for pkg in arch_candidates]
        for pkg, result in comparisons:
            if result >= 0:
                continue
            findings.append(
                Finding(
                    status="NEEDS_UPDATE",
                    installed=pkg,
                    fixed=entry.package,
                    date=entry.date,
                    cves=entry.cves,
                    urls=entry.urls,
                    details=entry.details,
                )
            )

    return findings, matched_names


def _color(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def format_human_report(
    packages_dir: Path,
    changelog_path: Path,
    packages: list[Package],
    skipped: list[str],
    entries: list[SecurityEntry],
    findings: list[Finding],
    matched_names: int,
) -> str:
    use_color = sys.stdout.isatty()
    lines = [
        f"slack-audit {VERSION} — Slackware security advisory audit",
        f"Package database : {packages_dir}",
        f"ChangeLog        : {changelog_path}",
        "",
        f"Packages scanned : {len(packages)}",
        f"Unparsed records : {len(skipped)}",
        f"Security entries : {len(entries)}",
        f"Installed names matched to advisories: {matched_names}",
        f"Pending security updates: {len(findings)}",
        "",
    ]
    if not entries:
        lines.append(_color("[?] No security-marked package entries were recognized in this ChangeLog.", "1;33", use_color))
        lines.append("    Verify the file path, mirror branch, and ChangeLog format before interpreting this as clean.")
        lines.append("")

    if findings:
        lines.append(_color("[!] SECURITY UPDATE CANDIDATES", "1;31", use_color))
        for finding in findings:
            lines.append(
                f"  {finding.installed.name}: installed "
                f"{finding.installed.version_build} ({finding.installed.arch})"
            )
            lines.append(
                f"    Fixed in : {finding.fixed.version_build} ({finding.fixed.arch})"
            )
            lines.append(f"    Advisory : ChangeLog entry dated {finding.date}")
            if finding.cves:
                lines.append(f"    CVEs     : {', '.join(finding.cves)}")
            else:
                lines.append("    CVEs     : none listed in this ChangeLog entry")
            if finding.urls:
                lines.append(f"    References: {'; '.join(finding.urls)}")
            if finding.details:
                detail = " ".join(finding.details.split())
                lines.append(f"    Details  : {detail[:500]}")
            lines.append("")
    else:
        if matched_names:
            lines.append(_color("[OK] No pending update candidate among the matched installed packages.", "1;32", use_color))
        else:
            lines.append(_color("[?] No installed package matched the security entries; no package was assessed.", "1;33", use_color))
        lines.append("")

    if skipped:
        lines.append("Records skipped because the Slackware filename could not be parsed:")
        lines.extend(f"  - {name}" for name in skipped[:20])
        if len(skipped) > 20:
            lines.append(f"  ... and {len(skipped) - 20} more")
        lines.append("")

    lines.extend([
        "Important limitations:",
        "  - This checks only security-marked package entries in the selected ChangeLog.",
        "  - It is not a complete CVE database and does not audit third-party software or source builds.",
        "  - Version ordering is best-effort; review custom package tags and nonstandard builds.",
        "  - No packages are installed, removed, upgraded, or modified by this tool.",
    ])
    return "\n".join(lines)


def command_audit(args: argparse.Namespace) -> int:
    packages, skipped = load_installed_packages(args.packages_dir)
    if not args.changelog.is_file():
        raise FileNotFoundError(
            f"ChangeLog not found: {args.changelog}\n"
            "Run 'slackpkg update' and confirm the configured mirror matches this Slackware release, "
            "or pass --changelog PATH."
        )
    changelog_text = args.changelog.read_text(encoding="utf-8", errors="replace")
    entries = parse_changelog(changelog_text)
    findings, matched = audit_packages(packages, entries)

    if args.json:
        payload = {
            "tool": "slack-audit",
            "version": VERSION,
            "packages_dir": str(args.packages_dir),
            "changelog": str(args.changelog),
            "packages_scanned": len(packages),
            "unparsed_records": skipped,
            "security_entries_parsed": len(entries),
            "installed_package_names_matched": matched,
            "pending_security_updates": [asdict(finding) for finding in findings],
            "limitations": [
                "Only security-marked entries in the selected ChangeLog are assessed.",
                "This is not a complete CVE database.",
                "Version comparison is best-effort.",
                "No system changes are made.",
            ],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(format_human_report(args.packages_dir, args.changelog, packages,
                                  skipped, entries, findings, matched))

    return 1 if findings else 0


def command_inventory(args: argparse.Namespace) -> int:
    packages, skipped = load_installed_packages(args.packages_dir)
    if args.json:
        print(json.dumps({"packages_scanned": len(packages),
                          "unparsed_records": skipped,
                          "packages": [asdict(pkg) for pkg in packages]},
                         indent=2, ensure_ascii=False))
        return 0
    print(f"Slackware package inventory: {len(packages)} packages")
    for pkg in packages:
        print(f"{pkg.name:32} {pkg.version:20} {pkg.arch:10} {pkg.build}")
    if skipped:
        print(f"\nSkipped {len(skipped)} records that did not match package naming convention.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="slack-audit",
        description="Read-only security advisory checker for Slackware package records.",
        epilog="This tool does not install or upgrade packages. Refresh the local ChangeLog with slackpkg first.",
    )
    parser.add_argument("--version", action="version", version=f"slack-audit {VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit = subparsers.add_parser("audit", help="match installed packages against security entries in ChangeLog.txt")
    audit.add_argument("--packages-dir", type=Path, default=DEFAULT_PACKAGES_DIR)
    audit.add_argument("--changelog", type=Path, default=DEFAULT_CHANGELOG)
    audit.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    audit.set_defaults(func=command_audit)

    inventory = subparsers.add_parser("inventory", help="list installed package records")
    inventory.add_argument("--packages-dir", type=Path, default=DEFAULT_PACKAGES_DIR)
    inventory.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    inventory.set_defaults(func=command_inventory)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, UnicodeError) as exc:
        print(f"slack-audit: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
