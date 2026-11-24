import json, pathlib, subprocess, sys, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
GEN=ROOT/'reporting'/'generate.py'

class ComparisonTests(unittest.TestCase):
    def produce(self, path, findings, status='COMPLETED', profile='baseline', target='https://example.org', previous=None):
        path.mkdir(exist_ok=True)
        if status=='COMPLETED':(path/'scanner-exitcodes.tsv').write_text('nuclei\t0\n')
        else:(path/'scanner-exitcodes.tsv').write_text('nuclei\t124\n')
        if status=='COMPLETED':(path/'nuclei_console.txt').write_text('[0:00:10] | Templates: 5 | Hosts: 1 | RPS: 1 | Matched: 0 | Errors: 0 | Requests: 10/10 (100%)\n')
        if findings is not None:
            (path/'nuclei.json').write_text(''.join(json.dumps({'template-id':tid,'matched-at':target,'info':{'name':tid,'severity':'medium'}})+'\n' for tid in findings))
        cmd=[sys.executable,str(GEN),'--out',str(path),'--target',target,'--profile',profile]
        if previous:cmd.extend(['--previous',str(previous)])
        subprocess.run(cmd,check=True,stdout=subprocess.DEVNULL)
    def test_valid_comparison_and_dokuwiki(self):
        with tempfile.TemporaryDirectory() as d:
            old=pathlib.Path(d)/'old'; new=pathlib.Path(d)/'new'
            self.produce(old,['x','y']);self.produce(new,['y','z'],previous=old)
            result=json.loads((new/'comparison.json').read_text())
            self.assertEqual(result['status'],'COMPARABLE')
            self.assertEqual(result['summary'],{'new':1,'resolved':1,'unchanged':1})
            wiki=(new/'report.dokuwiki.txt').read_text()
            self.assertIn('Kevin Pirnie',wiki)
            self.assertIn('ISO/IEC 27001',wiki)
            self.assertIn('niet meer gedetecteerd: 1',wiki)
            page=(new/'report.html').read_text()
            self.assertIn('comparison.json',page)
            self.assertIn('report.dokuwiki.txt',page)
            self.assertNotIn('cdnjs.cloudflare',page)
    def test_clean_nuclei_run_can_close_previous_detection(self):
        with tempfile.TemporaryDirectory() as d:
            old=pathlib.Path(d)/'old'; new=pathlib.Path(d)/'new'
            self.produce(old,['x']);self.produce(new,[],previous=old)
            result=json.loads((new/'comparison.json').read_text())
            self.assertEqual(result['status'],'COMPARABLE')
            self.assertEqual(result['summary']['resolved'],1)
    def test_failed_nuclei_not_comparable(self):
        with tempfile.TemporaryDirectory() as d:
            old=pathlib.Path(d)/'old'; new=pathlib.Path(d)/'new'
            self.produce(old,['x']);self.produce(new,[],status='FAILED',previous=old)
            result=json.loads((new/'comparison.json').read_text())
            self.assertEqual(result['status'],'NOT_COMPARABLE')
    def test_different_targets_not_comparable(self):
        with tempfile.TemporaryDirectory() as d:
            old=pathlib.Path(d)/'old'; new=pathlib.Path(d)/'new'
            self.produce(old,['x']);self.produce(new,['x'],target='https://different.org',previous=old)
            result=json.loads((new/'comparison.json').read_text())
            self.assertEqual(result['status'],'NOT_COMPARABLE')
if __name__=='__main__':unittest.main()
