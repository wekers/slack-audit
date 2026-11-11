# slack-audit

**slack-audit 0.1.0** is a read-only first iteration of a Slackware security-advisory checker. It borrows the workflow idea of FreeBSD `pkg audit`: inventory installed packages and compare them with published security fixes.

It uses only Python's standard library and the native Slackware package database in `/var/log/packages`.

## What this version does

- Reads installed package records from `/var/log/packages`.
- Parses package entries in the local Slackware `ChangeLog.txt`.
- Recognizes explicit `(* Security fix *)` markers, CVE identifiers, and common security-fix wording.
- Matches security-fix package names/architectures against the installed inventory.
- Reports installed package versions that appear older than the fixed package version.
- Supports human-readable and JSON output.

## What it does not do (yet)

- It is **not** a complete CVE database or a replacement for vendor advisories.
- It only evaluates security entries represented in the selected ChangeLog. Third-party packages, locally compiled software, and vulnerabilities not represented there are outside its coverage.
- It does not download advisories itself. Refresh the configured Slackware mirror metadata with `slackpkg update` first.
- It does not install, remove, upgrade, or modify packages or system configuration.
- Version ordering is best-effort (`sort -V` where available). Review custom build tags and unusual version strings manually.
- The parser associates a security marker/CVE with the immediately preceding package record. Ambiguous multi-package changelog sections should be reviewed manually.

## Requirements

- Slackware Linux with `pkgtools` package records.
- Python 3.10 or newer (tested here with Python 3.12).
- GNU `sort -V` is used for natural version ordering when available; a Python fallback exists.

## Run from the project directory

```sh
python3 ./slack-audit --help
python3 ./slack-audit inventory
python3 ./slack-audit audit
python3 ./slack-audit audit --json
```

Default paths:

- Package database: `/var/log/packages`
- ChangeLog: `/var/lib/slackpkg/ChangeLog.txt`

If the ChangeLog is stored elsewhere:

```sh
python3 ./slack-audit audit --changelog /path/to/ChangeLog.txt
```

Refresh the local ChangeLog before auditing:

```sh
slackpkg update
python3 ./slack-audit audit
```

Confirm that `/etc/slackpkg/mirrors` points to the intended Slackware release/branch before using the result. A ChangeLog from the wrong branch can lead to misleading comparisons.

## Install system-wide

From this directory, as root:

```sh
install -D -m 0755 ./slack-audit /usr/local/bin/slack-audit
install -D -m 0644 ./slack_audit.py /usr/local/bin/slack_audit.py
```

Then:

```sh
slack-audit inventory
slack-audit audit
```

## Exit codes

- `0`: no pending security update candidate found in the parsed ChangeLog.
- `1`: one or more installed packages appear older than a security fix.
- `2`: input/configuration/runtime error.

An exit code of `0` does **not** prove the system has no vulnerabilities; it only means this local ChangeLog scan found no pending match.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

The fixture includes an ordinary update and a marked security update with a sample CVE, to verify that ordinary updates are not reported as security findings.

## Roadmap

1. Add a curated structured advisory feed with SSA identifier, date, CVEs, fixed package builds, and official reference URLs.
2. Add explicit branch/release detection and reject mismatched feeds.
3. Add advisory-feed refresh with checksum/signature validation.
4. Add `--explain` output, history, and machine-readable JSON schema versioning.
5. Add regression tests against actual Slackware stable/current ChangeLogs and packages with custom build tags.
