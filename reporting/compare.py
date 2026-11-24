#!/usr/bin/env python3
"""Compare normalized Nuclei results without interpreting failed scans as remediation."""
import json
from pathlib import Path

def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))

def compare_scans(previous: Path, current: Path):
    try:
        a=read_json(previous/'scan-manifest.json')
        b=read_json(current/'scan-manifest.json')
        af=read_json(previous/'findings.json')
        bf=read_json(current/'findings.json')
    except (OSError,ValueError,TypeError) as exc:
        return {'status':'NOT_COMPARABLE','reason':f'Ontbrekend of ongeldig bewijs: {exc}'}
    if a.get('target') != b.get('target'):
        return {'status':'NOT_COMPARABLE','reason':'De targets verschillen'}
    if a.get('profile') != b.get('profile'):
        return {'status':'NOT_COMPARABLE','reason':'De scanprofielen verschillen'}
    def scanner_status(manifest,scanner):
        return next((s.get('status') for s in manifest.get('scanners',[]) if s.get('name')==scanner),None)
    for side,manifest in (('vorige',a),('huidige',b)):
        if scanner_status(manifest,'nuclei') != 'COMPLETED':
            return {'status':'NOT_COMPARABLE','reason':f'Nuclei in de {side} scan is niet aantoonbaar voltooid'}
    old={f['id']:f for f in af.get('findings',[]) if isinstance(f,dict) and f.get('id')}
    new={f['id']:f for f in bf.get('findings',[]) if isinstance(f,dict) and f.get('id')}
    return {'status':'COMPARABLE','previous':str(previous),'current':str(current),
            'summary':{'new':len(new.keys()-old.keys()),'resolved':len(old.keys()-new.keys()),'unchanged':len(old.keys()&new.keys())},
            'new':[new[k] for k in sorted(new.keys()-old.keys())],
            'resolved':[old[k] for k in sorted(old.keys()-new.keys())],
            'unchanged':[new[k] for k in sorted(old.keys()&new.keys())],
            'limitations':['Alleen Nuclei-bevindingen worden vergeleken','Verschillende Nuclei-templateversies kunnen vergelijkbaarheid beperken','Een verdwenen finding vereist handmatige validatie']}
