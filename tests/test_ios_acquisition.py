from __future__ import annotations

import hashlib
import json
import plistlib
import struct
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from mobile_audit.cli import main
from mobile_audit.ios_acquisition import acquire_ios_app


def _ipa(path: Path, *, bundle_id: str = "com.example.acquired", version: str = "2.1") -> None:
    command = struct.pack("<6I", 0x2C, 24, 0x1000, 0x200, 1, 0)
    executable = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(command), 0, 0) + command
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Payload/Acquired.app/Info.plist", plistlib.dumps({
            "CFBundleIdentifier": bundle_id, "CFBundleShortVersionString": version,
            "CFBundleVersion": "42", "CFBundleExecutable": "Acquired",
        }))
        archive.writestr("Payload/Acquired.app/Acquired", executable)


def _fake_backend(path: Path, source: Path, *, exit_status: int = 0) -> None:
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import shutil, sys\n"
        "from pathlib import Path\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    print('ipatool version test')\n"
        "    raise SystemExit(0)\n"
        f"status = {exit_status}\n"
        "if status:\n"
        "    raise SystemExit(status)\n"
        f"shutil.copyfile(Path({str(source)!r}), Path(sys.argv[sys.argv.index('--output') + 1]))\n",
        encoding="utf-8",
    )
    path.chmod(0o700)


class IOSAcquisitionTests(unittest.TestCase):
    def test_download_validates_and_scans_ipa(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "fixture.ipa"
            backend = root / "fake-ipatool"
            output = root / "acquired"
            _ipa(source)
            _fake_backend(backend, source)
            with redirect_stdout(StringIO()):
                status = main(["acquire-ios", "download", "--bundle-id", "com.example.acquired",
                               "--phone-version", "2.0", "--output", str(output),
                               "--backend", str(backend)])
            self.assertEqual(0, status)
            record = json.loads((output / "acquisition.json").read_text())
            report = json.loads((output / "scan" / "report.json").read_text())
            self.assertEqual("app_store_download", record["method"])
            self.assertEqual("2.1", record["package"]["version"])
            self.assertEqual("42", record["package"]["build"])
            self.assertEqual("mismatch", record["version_match"])
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), record["package"]["sha256"])
            self.assertEqual(1, record["package"]["binary_visibility"]["encrypted"])
            self.assertEqual("com.example.acquired", report["target"]["identifier"])
            self.assertEqual("app_store_download", report["package_profile"]["acquisition"]["method"])
            self.assertTrue((output / "scan" / "report.html").is_file())
            self.assertIn("Package acquisition", (output / "scan" / "report.html").read_text())
            self.assertNotIn(str(root), (output / "scan" / "report.json").read_text())
            with self.assertRaisesRegex(ValueError, "new output directory"):
                acquire_ios_app(output=output, bundle_id="com.example.acquired", backend=str(backend))

    def test_identity_mismatch_and_invalid_archive_leave_no_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "fixture.ipa"
            backend = root / "fake-ipatool"
            _ipa(source)
            _fake_backend(backend, source)
            with self.assertRaisesRegex(ValueError, "does not match"):
                acquire_ios_app(output=root / "wrong-app", bundle_id="com.other.app", backend=str(backend))
            self.assertFalse((root / "wrong-app").exists())
            source.write_bytes(b"not a zip archive")
            with self.assertRaises(zipfile.BadZipFile):
                acquire_ios_app(output=root / "bad-zip", bundle_id="com.example.acquired", backend=str(backend))
            self.assertFalse((root / "bad-zip").exists())

    def test_download_failure_leaves_no_package_or_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "fixture.ipa"
            backend = root / "fake-ipatool"
            _fake_backend(backend, source, exit_status=1)
            with self.assertRaisesRegex(RuntimeError, "download failed"):
                acquire_ios_app(output=root / "failed", app_id=12345, backend=str(backend))
            self.assertFalse((root / "failed").exists())


if __name__ == "__main__":
    unittest.main()
