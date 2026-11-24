import json, pathlib, subprocess, sys, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
GEN=ROOT/'reporting'/'generate.py'
class IncompleteCoverageTests(unittest.TestCase):
    def produce(self,out,stats='[0:01:17] | Templates: 7246 | Hosts: 1 | RPS: 169 | Matched: 0 | Errors: 148 | Requests: 13057/17546 (74%)'):
        out.mkdir(exist_ok=True)
        (out/'scanner-exitcodes.tsv').write_text('nuclei\t0\nnikto\t0\n')
        (out/'nuclei_console.txt').write_text(stats+'\n')
        (out/'nikto_console.txt').write_text('ERROR: *** Error limit (20) reached for host, giving up. ***\n')
        subprocess.run([sys.executable,str(GEN),'--out',str(out),'--target','https://example.org','--profile','webapp'],check=True,stdout=subprocess.DEVNULL)
        return json.loads((out/'scan-manifest.json').read_text())
    def test_bw02_nuclei_and_nikto_partial(self):
        with tempfile.TemporaryDirectory() as d:
            out=pathlib.Path(d)/'run';m=self.produce(out)
            statuses={x['name']:x['status'] for x in m['scanners']}
            self.assertEqual(statuses['nuclei'],'PARTIAL')
            self.assertEqual(statuses['nikto'],'PARTIAL')
            self.assertEqual(m['metrics']['nuclei_coverage']['request_errors'],148)
            self.assertEqual(m['metrics']['nuclei_coverage']['coverage_percent'],74.4)
            self.assertIn('148', (out/'report.html').read_text())
            self.assertIn('Controledekking', (out/'report.dokuwiki.txt').read_text())
    def test_unverified_nuclei_does_not_close_findings(self):
        with tempfile.TemporaryDirectory() as d:
            base=pathlib.Path(d); old=base/'old'; new=base/'new'
            old.mkdir();(old/'scanner-exitcodes.tsv').write_text('nuclei\t0\n')
            (old/'nuclei_console.txt').write_text('[0:00:10] | Errors: 0 | Requests: 10/10 (100%)\n')
            (old/'nuclei.json').write_text(json.dumps({'template-id':'x','matched-at':'https://example.org','info':{'severity':'high'}})+'\n')
            subprocess.run([sys.executable,str(GEN),'--out',str(old),'--target','https://example.org','--profile','webapp'],check=True,stdout=subprocess.DEVNULL)
            self.produce(new)
            from importlib.util import spec_from_file_location,module_from_spec
            spec=spec_from_file_location('comparer',ROOT/'reporting'/'compare.py');mod=module_from_spec(spec);spec.loader.exec_module(mod)
            self.assertEqual(mod.compare_scans(old,new)['status'],'NOT_COMPARABLE')
    def test_not_applicable_override(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)
            (p/'scanner-status.tsv').write_text('dalfox\tNOT_APPLICABLE\tNo query parameters\n')
            subprocess.run([sys.executable,str(GEN),'--out',d,'--target','https://example.org'],check=True,stdout=subprocess.DEVNULL)
            m=json.loads((p/'scan-manifest.json').read_text())
            self.assertEqual(next(x for x in m['scanners'] if x['name']=='dalfox')['status'],'NOT_APPLICABLE')
if __name__=='__main__':unittest.main()
