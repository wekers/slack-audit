from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import slack_audit


class PackageParsingTests(unittest.TestCase):
    def test_name_with_hyphens(self):
        package = slack_audit.parse_package_name("libXfont2-2.0.9-x86_64-1_slack15.0.txz")
        self.assertIsNotNone(package)
        self.assertEqual(package.name, "libXfont2")
        self.assertEqual(package.version, "2.0.9")
        self.assertEqual(package.arch, "x86_64")
        self.assertEqual(package.build, "1_slack15.0")

    def test_package_name_with_hyphenated_project_name(self):
        package = slack_audit.parse_package_name("kernel-firmware-20261106_6d6bffb-noarch-1.txz")
        self.assertIsNotNone(package)
        self.assertEqual(package.name, "kernel-firmware")
        self.assertEqual(package.version, "20261106_6d6bffb")

    def test_invalid_name(self):
        self.assertIsNone(slack_audit.parse_package_name("not-a-slackware-package"))


class ChangelogTests(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / "tests" / "fixtures" / "ChangeLog.txt").read_text()

    def test_only_security_entries_are_returned(self):
        entries = slack_audit.parse_changelog(self.text)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].package.name, "httpd")
        self.assertEqual(entries[0].cves, ("CVE-2026-12345",))
        self.assertEqual(entries[0].date, "Fri Nov  6 23:52:17 UTC 2026")

    def test_non_security_update_is_not_returned(self):
        entries = slack_audit.parse_changelog(self.text)
        self.assertNotIn("openssl", [entry.package.name for entry in entries])

    def test_security_marker_without_cve_is_supported(self):
        text = """Wed Nov  4 10:00:00 UTC 2026
n/foo-1.2-x86_64-1.txz: Upgraded.
  Fixes a security issue.
  (* Security fix *)
+--------------------------+
"""
        entries = slack_audit.parse_changelog(text)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].cves, ())


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.changelog = (ROOT / "tests" / "fixtures" / "ChangeLog.txt").read_text()
        self.entries = slack_audit.parse_changelog(self.changelog)

    def test_older_installed_version_is_flagged(self):
        installed = [slack_audit.Package("httpd", "2.4.68", "x86_64", "1", "httpd-2.4.68-x86_64-1")]
        findings, matched = slack_audit.audit_packages(installed, self.entries)
        self.assertEqual(matched, 1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "NEEDS_UPDATE")

    def test_fixed_installed_version_is_not_flagged(self):
        installed = [slack_audit.Package("httpd", "2.4.70", "x86_64", "1", "httpd-2.4.70-x86_64-1")]
        findings, matched = slack_audit.audit_packages(installed, self.entries)
        self.assertEqual(matched, 1)
        self.assertEqual(findings, [])

    def test_architecture_mismatch_is_not_claimed_as_match(self):
        installed = [slack_audit.Package("httpd", "2.4.68", "i586", "1", "httpd-2.4.68-i586-1")]
        findings, matched = slack_audit.audit_packages(installed, self.entries)
        self.assertEqual(matched, 0)
        self.assertEqual(findings, [])

    def test_old_parallel_install_is_not_hidden_by_newer_record(self):
        installed = [
            slack_audit.Package("httpd", "2.4.68", "x86_64", "1", "httpd-2.4.68-x86_64-1"),
            slack_audit.Package("httpd", "2.4.70", "x86_64", "1", "httpd-2.4.70-x86_64-1"),
        ]
        findings, matched = slack_audit.audit_packages(installed, self.entries)
        self.assertEqual(matched, 1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].installed.version, "2.4.68")

    def test_inventory_reads_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / "bash-5.2.037-x86_64-1").write_text("PACKAGE NAME: bash-5.2.037-x86_64-1\n")
            (path / "bad-entry").write_text("dummy\n")
            packages, skipped = slack_audit.load_installed_packages(path)
            self.assertEqual(len(packages), 1)
            self.assertEqual(packages[0].name, "bash")
            self.assertEqual(skipped, ["bad-entry"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
