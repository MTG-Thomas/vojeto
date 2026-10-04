"""Synthetic license-inventory fixtures; none are redistribution grants."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class DependencyNotices(unittest.TestCase):
    def inventory(self, root, packages):
        goroot = root / "go"
        goroot.mkdir()
        (goroot / "LICENSE").write_text("synthetic Go license fixture")
        output = root / "bundle"
        result = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("dependency-notices.py")),
             "--output", str(output), "--goroot", str(goroot)],
            input="\n".join(json.dumps(package) for package in packages),
            text=True, capture_output=True,
        )
        return result, output, json.loads((output / "inventory.json").read_text())

    def test_collects_replaced_module_once_and_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "patched-module"
            source.mkdir()
            for name in ("LICENSE", "NOTICE", "PATENTS"):
                (source / name).write_text("synthetic " + name)
            module = {"Path": "example.invalid/dependency", "Version": "v1.2.3",
                      "Dir": str(root / "unused"), "Replace": {"Dir": str(source)}}
            result, output, manifest = self.inventory(root, [
                {"Module": module}, {"Module": module}, {},
                {"Module": {"Main": True, "Path": "example.invalid/main"}},
            ])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(manifest["missing_license"], [])
            self.assertEqual(len(manifest["notices"]), 3)
            for entry in manifest["notices"]:
                self.assertEqual(entry["module"], module["Path"])
                self.assertEqual(entry["version"], module["Version"])
                self.assertEqual((output / entry["notice"]).read_text(),
                                 "synthetic " + entry["notice"][4:])
            self.assertEqual((output / "GO_LICENSE").read_text(), "synthetic Go license fixture")

    def test_notice_alone_does_not_authorize_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "unlicensed-module"
            source.mkdir()
            (source / "NOTICE").write_text("synthetic attribution only")
            module = {"Path": "example.invalid/unlicensed", "Version": "v0.1.0", "Dir": str(source)}
            result, _, manifest = self.inventory(root, [{"Module": module}])
            self.assertEqual(result.returncode, 1)
            self.assertEqual(manifest["missing_license"], [module["Path"] + "@v0.1.0"])
            self.assertIn("Missing dependency license", result.stderr)
            self.assertEqual(len(manifest["notices"]), 1)


if __name__ == "__main__":
    unittest.main()
