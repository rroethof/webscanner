#!/usr/bin/env python3
"""Ronny WebScanner offline report. Fork of KP WebScanner by Kevin Pirnie (MIT)."""
import argparse, datetime, html, json, pathlib, re, hashlib
from urllib.parse import urlparse

TOOLS = [
 ('whatweb','Fingerprint','fingerprint',['whatweb.txt','whatweb_console.txt']),
 ('httpx','HTTP probe','fingerprint',['httpx.txt','httpx_console.txt']),
 ('shodan','Shodan','recon',['shodan.txt']),
 ('censys','Censys','recon',['censys.txt']),
 ('subfinder','Subdomains','subdomains',['subdomains.txt','subfinder_console.txt']),
 ('dnsx','DNS','dns',['dns.txt','dnsx_console.txt']),
 ('naabu','Ports','ports',['ports.txt','naabu_console.txt']),
 ('nmap','Nmap','nmap',['nmap.txt','nmap_console.txt']),
 ('testssl.sh','TLS','ssl',['testssl.txt','testssl_console.txt']),
 ('observatory','Headers','headers',['observatory.json','observatory_error.txt']),
 ('nikto','Nikto','nikto',['nikto.txt','nikto_console.txt']),
 ('wpscan','WPScan','cms',['wpscan.json','wpscan_console.txt']),
 ('katana','Crawling','crawl',['endpoints.txt','katana_console.txt']),
 ('gobuster','Gobuster','brute',['gobuster.txt','gobuster_console.txt']),
 ('ffuf','ffuf','brute',['ffuf.json','ffuf_console.txt']),
 ('arjun','Arjun','arjun',['arjun.json','arjun_console.txt']),
 ('dalfox','Dalfox','xss',['dalfox.txt','dalfox_console.txt']),
 ('sqlmap','SQLMap','sqlmap',['sqlmap_console.txt']),
 ('osv-scanner','OSV-Scanner','osv',['osv_scanner.json','osv_scanner.txt']),
 ('nuclei','Nuclei','nuclei',['nuclei.json','nuclei.txt','nuclei_console.txt']),
 ('botblocker','Bot Blocker','botblocker',['botblocker_test.txt']),
 ('zap','OWASP ZAP','zap',['zap_report.html','zap_console.txt']),
 ('wafw00f','WAF detector',None,['wafw00f.txt'])
]
ERROR_PATTERN = re.compile(r'(^|\s)(fatal|traceback|connection reset by peer|command not found|timed out|timeout reached|no such file or directory)(\s|:|$)',re.I)

def load_nuclei(out):
    f=out/'nuclei.json'; findings=[]
    if not f.exists(): return findings
    for line in f.read_text(errors='replace').splitlines():
        try: obj=json.loads(line)
        except json.JSONDecodeError: continue
        if not isinstance(obj,dict): continue
        info=obj.get('info',{}) if isinstance(obj.get('info'),dict) else {}
        name=info.get('name') or obj.get('template-id') or 'Nuclei finding'
        severity=str(info.get('severity') or 'unknown').lower()
        matched=str(obj.get('matched-at') or obj.get('host') or '')
        template=str(obj.get('template-id') or '')
        fingerprint=hashlib.sha256(f'{template}|{matched}'.encode()).hexdigest()[:16]
        findings.append({'id':fingerprint,'scanner':'nuclei','title':str(name),'severity':severity,'target':matched,'template':template})
    return findings

def nuclei_coverage(out):
    """Parse LAST Nuclei stats record, ignoring terminal colors and control characters.

    100% requests is not automatically full test coverage: template failures may still exist.
    """
    path=out/'nuclei_console.txt'
    if not path.exists(): return {'observed':False,'complete':False,'reason':'No Nuclei console statistics'}
    content=path.read_text(errors='replace')
    content=re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', content)
    records=re.findall(r'Errors:\s*(\d+)\s*\|\s*Requests:\s*(\d+)\s*/\s*(\d+)', content, re.I)
    if not records:
        return {'observed':False,'complete':False,'reason':'Nuclei request coverage cannot be verified'}
    errors,done,total=map(int,records[-1])
    ratio=round(done*100/total,1) if total else 0.0
    stopped=bool(re.search(r'target.*(?:unreachable|unresponsive)|host.*(?:unreachable|unresponsive)|stopping scan|scan cancelled',content,re.I))
    complete=bool(total>0 and done>=total and errors==0 and not stopped)
    reason=('All scheduled requests processed without reported errors' if complete else
            f'Incomplete Nuclei execution: {done}/{total} requests, {errors} errors' + ('; unreachable target' if stopped else ''))
    return {'observed':True,'complete':complete,'requests_completed':done,'requests_expected':total,
            'request_errors':errors,'coverage_percent':ratio,'unreachable':stopped,'reason':reason}

def load_status_overrides(out):
    result={}
    path=out/'scanner-status.tsv'
    if path.exists():
        for line in path.read_text(errors='replace').splitlines():
            parts=line.split('\t',2)
            if len(parts)==3 and parts[1] in ('PARTIAL','FAILED','NOT_APPLICABLE'):
                result[parts[0]]=(parts[1],parts[2])
    return result

def status_for(out, name, group, paths, skipped, exitcodes, overrides, coverage):
    if group in skipped:return 'SKIPPED','Uitgeschakeld via profiel of CLI'
    if name in overrides:return overrides[name]
    if name=='nuclei' and exitcodes.get('nuclei')==0 and not coverage['complete']:
        return 'PARTIAL',coverage['reason']
    if name=='nuclei' and exitcodes.get('nuclei')==0 and coverage['complete']:
        return 'COMPLETED','Nuclei processed all scheduled requests without reported errors'
    if name=='nikto':
        combined='\n'.join((out/f).read_text(errors='replace') for f in ('nikto_console.txt','nikto.txt') if (out/f).exists())
        if re.search(r'Error limit \(\d+\) reached|Scan terminated: [1-9]\d* errors|giving up',combined,re.I):
            return 'PARTIAL','Nikto stopped after reaching HTTP error limit'
    if name=='wpscan' and not (out/'wpscan_console.txt').exists() and not (out/'wpscan.json').exists():
        return 'NOT_APPLICABLE','WordPress was not detected; WPScan not executed'
    if name in exitcodes and exitcodes[name] != 0:return 'FAILED','Tool gaf foutcode of timeout; controleer console-uitvoer'
    if name=='wafw00f' and not (out/'wafw00f.txt').exists():return 'SKIPPED','Optionele scanner niet aanwezig'
    exists=[x for x in paths if (out/x).is_file() and (out/x).stat().st_size>0]
    if name=='nuclei' and exitcodes.get('nuclei') == 0 and not exists:
        return 'COMPLETED','Nuclei eindigde met exitcode 0; geen bevindingenbestand geproduceerd'
    if not exists:return 'UNVERIFIED','Geen uitvoer, scannerresultaat niet bevestigd'
    evidence=[x for x in exists if not x.endswith('_console.txt') and not x.endswith('_error.txt')]
    logs=[x for x in exists if x.endswith('_console.txt') or x.endswith('_error.txt')]
    for path in logs:
        log=(out/path).read_text(errors='replace')[-12000:]
        if ERROR_PATTERN.search(log):return 'PARTIAL','Log bevat mogelijke uitvoeringsfout; controleer bewijs'
    if not evidence:return 'UNVERIFIED','Alleen console-uitvoer; succesvolle scan niet bevestigd'
    if name in exitcodes:return 'COMPLETED','Tool gaf exitcode 0 en bewijs is aanwezig'
    return 'OUTPUT_PRESENT','Bewijs aanwezig; exitstatus niet beschikbaar in dit script'

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',required=True);ap.add_argument('--target',required=True)
    ap.add_argument('--profile',default='extended');ap.add_argument('--version',default='dev')
    ap.add_argument('--skipped',action='append',default=[]);ap.add_argument('--previous',default=None)
    ap.add_argument('--waf-evidence',default=None,help='JSON with manually correlated CrowdSec and proxy log evidence')
    args=ap.parse_args();out=pathlib.Path(args.out);out.mkdir(parents=True,exist_ok=True)
    skipped=set(args.skipped)
    exitcodes={}
    exit_file=out/'scanner-exitcodes.tsv'
    if exit_file.exists():
        for line in exit_file.read_text().splitlines():
            parts=line.split('\t')
            if len(parts)==2 and parts[1].isdigit():exitcodes[parts[0]]=int(parts[1])
    coverage=nuclei_coverage(out) if 'nuclei' not in skipped else {'observed':False,'complete':False,'reason':'Nuclei skipped'}
    overrides=load_status_overrides(out)
    scans=[]
    for name,display,group,files in TOOLS:
        status,detail=status_for(out,name,group,files,skipped,exitcodes,overrides,coverage)
        scans.append({'name':name,'title':display,'status':status,'note':detail,'files':[x for x in files if (out/x).is_file()]})
    findings=load_nuclei(out)
    from security_controls import classify_evidence
    waf=classify_evidence(args.waf_evidence or out/'waf-evidence.json',args.target)
    manifest={
      'product':'Ronny WebScanner','upstream':{'name':'KP WebScanner','author':'Kevin Pirnie','repository':'https://github.com/kpirnie/webscanner','license':'MIT'},'version':args.version,'target':args.target,
      'profile':args.profile,'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
       'security_controls':{'crowdsec_appsec':waf},
       'assessment_dimensions':{'execution':'SEE_SCANNERS','coverage':'SEE_NUCLEI_COVERAGE','security_control':waf['status']},
      'skipped_groups':sorted(skipped),'scanners':scans,'metrics':{
        'open_ports_lines': count_lines(out/'ports.txt'),
        'subdomain_lines': count_lines(out/'subdomains.txt'),
        'crawler_lines_not_validated':count_lines(out/'endpoints.txt'),
        'nuclei_findings':len(findings),
        'nuclei_coverage':coverage
      },'limitations':['Exit codes are captured for Nmap, testssl.sh, Nuclei, and ZAP; other tools are not yet tracked consistently.',
       'OUTPUT_PRESENT does not mean a tool finished successfully.',
       'Nuclei scan comparison requires verified full coverage (no request errors).',
       'Nuclei is the only scanner parsed into normalized findings in this development release.',
       'Crawler URLs are unvalidated discoveries, not confirmed reachable endpoints.',
       'Port findings are IP-level and may not be services of the HTTP vhost.']}
    (out/'scan-manifest.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n')
    (out/'findings.json').write_text(json.dumps({'findings':findings},indent=2,ensure_ascii=False)+'\n')
    comparison=None
    if args.previous:
        from compare import compare_scans
        previous=pathlib.Path(args.previous)
        comparison=compare_scans(previous,out)
        (out/'comparison.json').write_text(json.dumps(comparison,ensure_ascii=False,indent=2)+'\n')
    from dokuwiki import export_report
    export_report(out,manifest,findings,comparison)
    statuses={x:sum(s['status']==x for s in scans) for x in ('COMPLETED','OUTPUT_PRESENT','PARTIAL','SKIPPED','NOT_APPLICABLE','UNVERIFIED','FAILED')}
    esc=html.escape
    styles='''
    :root{color-scheme:dark;--bg:#080f1e;--surface:#111d30;--surface2:#17273f;--border:#253e5a;--txt:#e5eefb;--muted:#94a8c2;--blue:#64c8ff;--good:#58d4a0;--warn:#ffc76b;--bad:#ff7f8c}
    *{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% 0%,#16365d 0,transparent 37%),var(--bg);color:var(--txt);font:15px/1.6 system-ui,-apple-system,Segoe UI,sans-serif}
    .wrap{max-width:1250px;margin:auto;padding:32px 28px}.nav{position:sticky;top:0;background:#0b1426ed;backdrop-filter:blur(15px);border-bottom:1px solid var(--border);z-index:5;padding:12px 28px;display:flex;align-items:center;gap:20px;flex-wrap:wrap}
    .nav a{color:var(--muted);text-decoration:none;font-size:13px}.nav a:hover{color:var(--blue)}h1{font-size:35px;margin:4px 0 4px;letter-spacing:-.04em}h2{font-size:19px;margin:33px 0 16px}.muted{color:var(--muted)}.eyebrow{color:var(--blue);letter-spacing:.15em;text-transform:uppercase;font-size:12px;font-weight:700}
    .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px;margin:25px 0}.card{background:linear-gradient(135deg,var(--surface),var(--surface2));border:1px solid var(--border);border-radius:15px;padding:21px}.card strong{font-size:29px;display:block;line-height:1.15}.card span{color:var(--muted);font-size:12px}.panel{background:var(--surface);border:1px solid var(--border);border-radius:16px;overflow:hidden;margin:15px 0}.panel header{padding:17px 21px;border-bottom:1px solid var(--border);font-weight:650}.panel .inside{padding:18px 22px}.chip{border:1px solid var(--border);border-radius:30px;font-size:11px;letter-spacing:.03em;padding:4px 10px;white-space:nowrap}.COMPLETED{color:var(--good)}.FAILED{color:var(--bad)}.OUTPUT_PRESENT{color:var(--blue)}.PARTIAL{color:var(--warn)}.SKIPPED{color:var(--muted)}.NOT_APPLICABLE{color:var(--muted)}.UNVERIFIED{color:var(--bad)}
    .scanner{display:grid;grid-template-columns:minmax(150px,1fr) 140px minmax(240px,2fr);gap:14px;align-items:center;padding:15px 21px;border-bottom:1px solid var(--border)}.scanner:last-child{border-bottom:none}.scanner small{color:var(--muted)}.scanner .links a{color:var(--blue);margin-right:12px;font-size:12px;overflow-wrap:anywhere}a{color:var(--blue)}
    .finding{padding:15px 20px;border-bottom:1px solid var(--border)}.finding:last-child{border:0}.finding b{font-size:14px}.finding code{display:block;color:var(--muted);font-size:12px;overflow-wrap:anywhere}.tabs{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}.tabs button,.search{background:var(--surface2);border:1px solid var(--border);color:var(--txt);border-radius:9px;padding:10px 13px}.tabs button{cursor:pointer}.tabs button.active{border-color:var(--blue);color:var(--blue)}.search{width:min(100%,400px)}.note{border-left:3px solid var(--warn);padding:13px 17px;background:#31291d5c;border-radius:5px}footer{margin:35px 0;color:var(--muted);font-size:12px}@media(max-width:720px){.wrap{padding:20px 13px}.scanner{grid-template-columns:1fr;gap:6px}h1{font-size:26px}}@media print{.nav,.tabs,.search{display:none}.wrap{max-width:none}.panel{break-inside:avoid}}
    '''
    icons={'brand':'🛡️','target':'🎯','ok':'✓','warn':'⚠','scan':'🔎','evidence':'📁','clock':'🕒','settings':'⚙️'}
    def icon(x):return icons.get(x,'•')
    cards=[('Nuclei findings',len(findings)),('Open port lines',manifest['metrics']['open_ports_lines']),('Subdomain lines',manifest['metrics']['subdomain_lines']),('Completed',statuses['COMPLETED']),('Needs review',statuses['FAILED']+statuses['PARTIAL']+statuses['UNVERIFIED']),('Skipped',statuses['SKIPPED']),('Not applicable',statuses['NOT_APPLICABLE'])]
    html_head=f'''<!doctype html><html lang="nl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ronny WebScanner | {esc(args.target)}</title><style>{styles}</style></head><body><nav class="nav"><b>{icon('brand')} Ronny WebScanner</b><a href="#overview">Overzicht</a><a href="#tools">Scanners</a><a href="#findings">Bevindingen</a><a href="#evidence">Bewijs</a></nav><main class="wrap"><div class="eyebrow">Security assessment • {esc(args.version)}</div><h1>{icon('target')} {esc(args.target)}</h1><div class="muted">Profiel: {esc(args.profile)} | Aangemaakt: {esc(manifest['created_at'])}</div><section id="overview"><h2>Assessment overview</h2><div class="cards">'''
    blocks=''.join(f'<div class="card"><strong>{value}</strong><span>{esc(label)}</span></div>' for label,value in cards)
    body='</div><p class="note">⚠ Deze ontwikkelversie toont bewijsaanwezigheid, niet automatisch een geslaagde scan. Niet-uitgevoerde en mislukte stappen mogen niet worden gelezen als 0 bevindingen.</p></section>'
    if coverage.get('observed'):
        body+=f'<p class="note">Nuclei-dekking: {coverage["requests_completed"]}/{coverage["requests_expected"]} requests ({coverage["coverage_percent"]}%), fouten: {coverage["request_errors"]}. {esc(coverage["reason"])}</p>'
    body+='<section id="controls"><h2>🛡️ Security controls</h2><div class="panel"><div class="inside"><strong>CrowdSec AppSec: '+esc(waf['status'])+'</strong><p>'+esc(waf['note'])+'</p><p>HTTP 403 alone never proves CrowdSec enforcement. Scanner execution and coverage remain independent.</p></div></div></section>'
    body+='<section id="tools"><h2>🔎 Scannerstatussen</h2><input class="search" id="filter" placeholder="Zoek scanner of status..." aria-label="Zoek scanners"><div class="tabs"><button data-status="all" class="active">Alles</button><button data-status="COMPLETED">Completed</button><button data-status="OUTPUT_PRESENT">Bewijs</button><button data-status="FAILED">Failed</button><button data-status="PARTIAL">Review</button><button data-status="SKIPPED">Skipped</button><button data-status="NOT_APPLICABLE">N.v.t.</button><button data-status="UNVERIFIED">Onbevestigd</button></div><div class="panel" id="scanner-list">'
    for s in scans:
        links=''.join(f'<a href="{esc(n,quote=True)}">{esc(n)}</a>' for n in s['files'] if n not in {'scan.log'})
        body+=f'''<div class="scanner" data-status="{esc(s['status'])}" data-search="{esc((s['title']+' '+s['status']).lower(),quote=True)}"><div><strong>{esc(s['title'])}</strong><div><small>{esc(s['note'])}</small></div></div><div><span class="chip {esc(s['status'])}">{esc(s['status'])}</span></div><div class="links">{links or '<small>Geen bewijsbestand</small>'}</div></div>'''
    body+='</div></section><section id="findings"><h2>🛡️ Nuclei bevindingen</h2><div class="panel">'
    if findings:
        for x in findings:
            body+=f'<div class="finding"><span class="chip">{esc(x["severity"])}</span> <b>{esc(x["title"])}</b><code>{esc(x["target"])} | {esc(x["id"])}</code></div>'
    else:body+='<div class="inside muted">Geen geparste Nuclei-bevindingen in dit rapport. Controleer eerst of Nuclei daadwerkelijk heeft gedraaid.</div>'
    body+='</div></section>'
    if comparison:
        state=comparison['status']
        if state == 'COMPARABLE':
            summary=comparison['summary']
            body+=f'<section id="comparison"><h2>📊 Vergelijking vorige scan</h2><div class="cards"><div class="card"><strong>{summary["new"]}</strong><span>Nieuw</span></div><div class="card"><strong>{summary["resolved"]}</strong><span>Niet meer gedetecteerd</span></div><div class="card"><strong>{summary["unchanged"]}</strong><span>Ongewijzigd</span></div></div><p><a href="comparison.json">Bekijk vergelijking als JSON</a></p></section>'
        else:
            body+=f'<section id="comparison"><h2>📊 Vergelijking vorige scan</h2><p class="note">Niet betrouwbaar vergelijkbaar: {esc(comparison["reason"])}</p></section>'
    body+='<section id="evidence"><h2>📁 Audit evidence</h2><div class="panel"><div class="inside"><p><a href="scan-manifest.json">scan-manifest.json</a> | <a href="findings.json">findings.json</a> | <a href="report.dokuwiki.txt">DokuWiki-export</a> | <a href="report-legacy.html">Legacy report</a></p><p class="muted">Een scan met 0 bevindingen is niet automatisch een veilige website. Het manifest beschrijft onvolledige controles en beperkingen.</p></div></div></section>'
    js='''<script>const buttons=[...document.querySelectorAll('[data-status]')].filter(e=>e.tagName==='BUTTON'), rows=[...document.querySelectorAll('.scanner')],filter=document.getElementById('filter');let selected='all';function update(){const q=filter.value.toLowerCase();rows.forEach(r=>r.hidden=!(selected==='all'||r.dataset.status===selected)||!r.dataset.search.includes(q))}buttons.forEach(b=>b.addEventListener('click',()=>{selected=b.dataset.status;buttons.forEach(x=>x.classList.toggle('active',x===b));update()}));filter.addEventListener('input',update);</script>'''
    (out/'report.html').write_text(html_head+blocks+body+f'<footer>{esc(args.version)} | Ronny WebScanner · Based on <a href="https://github.com/kpirnie/webscanner" rel="noopener noreferrer">KP WebScanner by Kevin Pirnie</a> (MIT) · Offline report.</footer></main>{js}</body></html>')
    print('Offline report created:',out/'report.html')

def count_lines(f):
    try:return sum(bool(x.strip()) for x in f.read_text(errors='replace').splitlines())
    except FileNotFoundError:return 0

if __name__=='__main__':main()
