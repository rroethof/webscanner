import json, pathlib, subprocess, sys, tempfile, unittest
SCRIPT=pathlib.Path(__file__).resolve().parents[1]/'reporting'/'generate.py'
class ReportingSmoke(unittest.TestCase):
    def test_empty_scan_is_not_success(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.run([sys.executable,str(SCRIPT),'--out',d,'--target','https://example.org','--profile','baseline','--skipped','zap'],check=True,stdout=subprocess.DEVNULL)
            m=json.loads((pathlib.Path(d)/'scan-manifest.json').read_text())
            self.assertEqual(m['target'],'https://example.org')
            self.assertIn('UNVERIFIED',[x['status'] for x in m['scanners']])
            self.assertEqual([x for x in m['scanners'] if x['name']=='zap'][0]['status'],'SKIPPED')
            page=(pathlib.Path(d)/'report.html').read_text()
            self.assertNotIn('cdnjs.cloudflare.com',page)
    def test_execution_log_is_summarized(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)
            (p/'events.jsonl').write_text(
                '{"timestamp":"2026-11-25T08:00:00Z","scanner":"nuclei","event":"started"}\\n'
                '{"timestamp":"2026-11-25T08:00:05Z","scanner":"nuclei","event":"failed","exit_code":2,"duration_seconds":5}\\n'
            )
            subprocess.run([sys.executable,str(SCRIPT),'--out',d,'--target','https://example.org'],
                           check=True,stdout=subprocess.DEVNULL)
            m=json.loads((p/'scan-manifest.json').read_text())
            self.assertEqual(m['execution_log']['events'],2)
            self.assertEqual(m['execution_log']['failed_stages'],1)
            self.assertIn('events.jsonl',(p/'report.html').read_text())

    def test_empty_output_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            run=subprocess.run([sys.executable,str(SCRIPT),'--out','','--target','https://example.org'],
                               cwd=d,capture_output=True,text=True)
            self.assertNotEqual(run.returncode,0)
            self.assertIn('non-empty',run.stderr)
            self.assertFalse((pathlib.Path(d)/'scan-manifest.json').exists())

    def test_missing_output_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            missing=pathlib.Path(d)/'deleted-scan'
            run=subprocess.run([sys.executable,str(SCRIPT),'--out',str(missing),'--target','https://example.org'],
                               cwd=d,capture_output=True,text=True)
            self.assertNotEqual(run.returncode,0)
            self.assertFalse(missing.exists())
            self.assertFalse((pathlib.Path(d)/'scan-manifest.json').exists())

    def test_nuclei_jsonl_and_exitcode(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)
            (p/'nuclei.json').write_text(json.dumps({'template-id':'test','matched-at':'https://example.org','info':{'name':'Example','severity':'medium'}})+'\n')
            (p/'scanner-exitcodes.tsv').write_text('nuclei\t0\n')
            (p/'nuclei_console.txt').write_text('[0:00:10] | Templates: 5 | Hosts: 1 | RPS: 1 | Matched: 1 | Errors: 0 | Requests: 10/10 (100%)\n')
            subprocess.run([sys.executable,str(SCRIPT),'--out',d,'--target','https://example.org'],check=True,stdout=subprocess.DEVNULL)
            m=json.loads((p/'scan-manifest.json').read_text())
            self.assertEqual([x for x in m['scanners'] if x['name']=='nuclei'][0]['status'],'COMPLETED')
            self.assertEqual(len(json.loads((p/'findings.json').read_text())['findings']),1)
if __name__=='__main__':unittest.main()
