#!/usr/bin/env python3
"""Generate DokuWiki assessment overview with conservative ISO 27001 references."""
from pathlib import Path
from urllib.parse import urlsplit

def clean(v):
    return str(v).replace('|','/').replace('\n',' ').replace('\r',' ').replace('\\','')

def export_report(out:Path, manifest:dict, findings:list, comparison=None):
    target=manifest['target']
    host=urlsplit(target).hostname or target
    rows=['====== Ronny WebScanner | '+clean(host)+' ======',
          '===== Technisch security assessment =====','',
          '^ Eigenschap ^ Waarde ^',
          '| Platform | Ronny WebScanner |',
          '| Versie | '+clean(manifest['version'])+' |',
          '| Doel | '+clean(target)+' |',
          '| Scanprofiel | '+clean(manifest['profile'])+' |',
          '| Uitgevoerd (UTC) | '+clean(manifest['created_at'])+' |',
          '| Broncode | [[https://github.com/rroethof/webscanner|Ronny WebScanner]] |',
          '| Herkomst | [[https://github.com/kpirnie/webscanner|KP WebScanner]] door Kevin Pirnie (MIT) |',
          '', '===== Samenvatting =====',
          'Dit overzicht is technische scanregistratie. Bevindingen zijn niet automatisch bevestigde kwetsbaarheden.',
          'Geen bevindingen is niet hetzelfde als een aantoonbaar veilige configuratie.',
          '', '^ Scanner ^ Status ^ Toelichting ^']
    for s in manifest['scanners']:
        rows.append('| '+clean(s['title'])+' | '+clean(s['status'])+' | '+clean(s['note'])+' |')
    waf=manifest.get('security_controls',{}).get('crowdsec_appsec',{})
    rows.extend(['', '===== Security controls (afzonderlijke beoordeling) =====',
                 'Scanneruitvoering en testdekking blijven onafhankelijk van de beveiligingscontrole.',
                 '^ Controle ^ Status ^ Toelichting ^',
                 '| CrowdSec AppSec | '+clean(waf.get('status','UNVERIFIED'))+' | '+clean(waf.get('note','Geen gecorreleerd bewijs aangeleverd'))+' |'])
    for event in waf.get('events', []):
        rows.append('  * Alert '+clean(event.get('crowdsec_alert_id',''))+
                    ', regel '+clean(event.get('crowdsec_rule',''))+
                    ', CrowdSec-bewijs: '+clean(event.get('crowdsec_alert_reference',''))+
                    ', proxybewijs: '+clean(event.get('proxy_log_reference','')))
    rows.append('Een HTTP 403 zonder gekoppeld CrowdSec-alert en reverse-proxybewijs is geen bewezen CrowdSec-blokkering.')
    execution=manifest.get('execution_log',{})
    rows.extend(['', '===== Uitvoeringslogging =====',
                 'Gestructureerde gebeurtenissen: '+clean(execution.get('events',0))+'.',
                 'Afgeronde scanners: '+clean(execution.get('finished_stages',0))+'.',
                 'Scanners met foutcode: '+clean(execution.get('failed_stages',0))+'.',
                 'Voor volledige uitvoer: scan.log, events.jsonl, logs/ en de originele scanneroutput.'])
    rows.extend(['','===== Nuclei-bevindingen =====','',
                 '^ Severity ^ Omschrijving ^ Getroffen URL ^ Referentie ^'])
    for f in findings:
        rows.append('| '+clean(f.get('severity','unknown'))+' | '+clean(f.get('title',''))+' | '+clean(f.get('target',''))+' | '+clean(f.get('id',''))+' |')
    if not findings:rows.append('Geen geparste Nuclei-bevindingen; controleer de scannerstatus.')
    coverage=manifest.get('metrics',{}).get('nuclei_coverage',{})
    rows.extend(['','===== Controledekking ====='])
    if coverage.get('observed'):
        rows.append('Nuclei: '+str(coverage.get('requests_completed'))+'/'+str(coverage.get('requests_expected'))+' requests ('+str(coverage.get('coverage_percent'))+'%), requestfouten: '+str(coverage.get('request_errors'))+'.')
        rows.append('Volledig en zonder fouten: '+('ja' if coverage.get('complete') else 'nee')+'.')
        rows.append(clean(coverage.get('reason','')))
    else:rows.append('Nuclei-dekking niet aantoonbaar of scanner uitgeschakeld.')
    diagnosis=manifest.get('metrics',{}).get('nuclei_error_diagnostics',{})
    rows.extend(['','===== Nuclei-foutdiagnose =====',
                 'Classificatie: '+clean(diagnosis.get('classification','UNKNOWN'))+'.',
                 'Niet-toegewezen requestfouten: '+clean(diagnosis.get('unattributed_request_errors','onbekend'))+'.',
                 'Logsignalen (geen per-request telling): '+clean(', '.join(diagnosis.get('observed_log_signals',[])) or 'geen')+'.',
                 clean(diagnosis.get('note','Geen betrouwbare foutattributie mogelijk.'))])
    rows.extend(['','===== Positieve controles en beperkingen ====='])
    rows.append('Voltooide technische controles: '+', '.join(clean(x['title']) for x in manifest['scanners'] if x['status']=='COMPLETED')+'.')
    for x in manifest['scanners']:
        if x['status'] in ('PARTIAL','FAILED','UNVERIFIED'):
            rows.append('  * '+clean(x['title'])+': '+clean(x['status'])+' - '+clean(x['note']))
    rows.extend(['','===== Openstaande acties =====',
                 '  * Controleer onvolledige of foutief afgesloten scanners tegen de ruwe logs.',
                 '  * Valideer bevindingen handmatig voordat een incident of kwetsbaarheid wordt geregistreerd.',
                 '  * Leg eigenaar, datum en eventuele remediation vast op de hostpagina.'])
    if comparison:
        rows.extend(['','===== Verschillen met vorige scan ====='])
        if comparison['status']=='COMPARABLE':
            summary=comparison['summary']
            rows.append('Nieuwe: '+str(summary['new'])+', niet meer gedetecteerd: '+str(summary['resolved'])+', ongewijzigd: '+str(summary['unchanged'])+'.')
            rows.append('Verdwenen bevindingen vereisen handmatige verificatie voordat ze als opgelost gelden.')
        else:rows.append('Geen betrouwbare vergelijking mogelijk: '+clean(comparison['reason']))
    rows.extend(['','===== ISO/IEC 27001:2022 =====',
                 'Mogelijk relevante Annex A-controls: 8.8 Management of technical vulnerabilities en 8.9 Configuration management.',
                 'Toepasselijkheid en formele controlmapping moeten per systeem worden beoordeeld. ISOPlanner blijft leidend voor het ISMS.',
                 '', '===== Auditbewijs =====',
                 'De gegenereerde bestanden bevinden zich in dezelfde scanmap:',
                 '  * scan-manifest.json (scannerstatussen en scope)',
                 '  * findings.json (genormaliseerde Nuclei-bevindingen)',
                 '  * report.html (offline dashboard)',
                 '  * events.jsonl (uitvoeringsgebeurtenissen, exitcodes en duur)',
                 '  * scan.log en logs/ (volledige logging, waar beschikbaar)',
                 '  * originele scanneroutputs (onbewerkte technische resultaten)',
                 '', '===== Beperkingen ====='])
    for item in manifest.get('limitations',[]):rows.append('  * '+clean(item))
    rows.extend(['','===== Opvolging =====','Status: te beoordelen. Technische validatie, eigenaar en eventuele acties moeten handmatig worden geregistreerd.',''])
    (out/'report.dokuwiki.txt').write_text('\n'.join(rows),encoding='utf-8')
