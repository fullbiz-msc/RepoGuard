import hashlib
import importlib.util
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest

spec = importlib.util.spec_from_file_location('audit', Path(__file__).resolve().parents[1] / 'project_audit.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class AuditTests(unittest.TestCase):
    def test_cli_output_boundary_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / 'project'
            root.mkdir()
            (root / 'app.py').write_text('eval(user_input)\n')
            command = [sys.executable, str(Path(audit.__file__)), str(root), '--output']
            denied = subprocess.run(command + [str(root / 'reports')], capture_output=True)
            self.assertEqual(denied.returncode, 2)
            self.assertFalse((root / 'reports').exists())
            output = base / 'report'
            result = subprocess.run(command + [str(output)], capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertTrue((output / 'SECURITY-REPORT.md').is_file())
            original = (output / 'report.json').read_bytes()
            repeated = subprocess.run(command + [str(output)], capture_output=True)
            self.assertEqual(repeated.returncode, 2)
            self.assertEqual(original, (output / 'report.json').read_bytes())

    def test_candidates_redaction_and_no_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / 'executed'
            content = f'import pathlib\npathlib.Path({str(marker)!r}).touch()\npassword = "sensitive-test-value"\ncursor.execute(f"SELECT * FROM users WHERE id={{user}}")\n'
            source = root / 'app.py'
            source.write_text(content)
            before = hashlib.sha256(source.read_bytes()).hexdigest()
            report = audit.scan(root)
            self.assertEqual({f['rule'] for f in report['findings']}, {'SECRET', 'SQL-DYNAMIC'})
            self.assertFalse(marker.exists())
            self.assertEqual(before, hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertNotIn('sensitive-test-value', audit.markdown(report))
            self.assertNotIn('sensitive-test-value', str(report))

    def test_parameterized_sql_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            (root / 'safe.py').write_text('cursor.execute("SELECT * FROM users WHERE id=?", (user,))\n')
            target = Path(outside) / 'outside.py'
            target.write_text('eval(payload)\n')
            (root / 'linked.py').symlink_to(target)
            report = audit.scan(root)
            self.assertEqual(report['findings'], [])
            self.assertEqual(len(report['files']), 1)
            self.assertTrue(any(s['reason'] == 'symlink' for s in report['skipped']))

    def test_size_limit_and_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'large.py').write_bytes(b'a' * (audit.MAX_BYTES + 1))
            (root / 'bad.py').write_bytes(b'\xff')
            report = audit.scan(root)
            self.assertEqual(report['files'], [])
            self.assertEqual(len(report['errors']), 1)
            self.assertEqual(report['skipped'][0]['reason'], 'size limit')


if __name__ == '__main__':
    unittest.main()
