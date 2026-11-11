import hashlib
import importlib.util
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('audit', Path(__file__).resolve().parents[1] / 'project_audit.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class AuditTests(unittest.TestCase):
    def test_env_is_not_opened_without_consent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('.env', '.env.production', '.env.example', 'service.env', '.ENV.local'):
                (root / name).write_text('password = "sensitive-env-value"\n')
            with patch.object(audit.os, 'open', side_effect=AssertionError('File opened without consent')):
                report = audit.scan(root)
            self.assertEqual(report['files'], [])
            self.assertEqual(len(report['env_access']), 5)
            self.assertTrue(all(not entry['approved'] for entry in report['env_access']))
            self.assertEqual(len(report['skipped']), 5)

    def test_env_consent_is_per_file_and_secrets_are_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / '.env').write_text('password = "sensitive-env-value"\n')
            (root / '.env.production').write_text('password = "private-production-value"\n')
            requested = []
            def consent(path):
                requested.append(path)
                return path == '.env'
            report = audit.scan(root, env_approval=consent)
            self.assertEqual(requested, ['.env', '.env.production'])
            self.assertEqual([item['path'] for item in report['files']], ['.env'])
            self.assertEqual([item['path'] for item in report['findings']], ['.env'])
            self.assertNotIn('sensitive-env-value', str(report))
            self.assertNotIn('private-production-value', audit.markdown(report))

    def test_terminal_confirmation_requires_explicit_yes(self):
        for answer, expected in (('да', True), ('yes', True), ('нет', False), ('', False), ('maybe', False)):
            with self.subTest(answer=answer), patch.object(audit.sys.stdin, 'isatty', return_value=True), patch('builtins.input', return_value=answer):
                self.assertEqual(audit.request_env_access('.env'), expected)
        with patch.object(audit.sys.stdin, 'isatty', return_value=False), patch('builtins.input', side_effect=AssertionError('Must not prompt')):
            self.assertFalse(audit.request_env_access('.env'))
        with patch.object(audit.sys.stdin, 'isatty', return_value=True), patch('builtins.input', side_effect=EOFError):
            self.assertFalse(audit.request_env_access('.env'))

    def test_noninteractive_cli_reports_unchecked_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'project'
            root.mkdir()
            (root / '.env').write_text('password = "sensitive-env-value"\n')
            result = subprocess.run([sys.executable, str(Path(audit.__file__)), str(root), '--output', str(Path(tmp) / 'report')], input=b'', capture_output=True)
            self.assertEqual(result.returncode, 0)
            report = (Path(tmp) / 'report/SECURITY-REPORT.md').read_text()
            self.assertIn('env access not approved', report)
            self.assertNotIn('sensitive-env-value', report)
            self.assertIn('env без согласия: 1', result.stdout.decode())

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
