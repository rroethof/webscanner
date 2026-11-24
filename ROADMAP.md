# Uitbreidingsplan Ronny WebScanner

## Eerst: betrouwbaarheid
- Exitcodes voor alle scanners en expliciete scanner-versies in manifest.
- Standaard inputvalidatie en allowlist voor host/port/scope, crawl-scope enforcement.
- Nmap-XML poorten dedupliceren op IP en protocol, niet vhost.
- Scanresultaten onderscheiden van HTTP/CDN/WAF-bescherming.
- Veilige outputpad-validatie en secrets redigeren uit logs.
- Botcheck vanuit echte bron-IP's, controles tegen false positives en 5xx/timeouts.
- Strikte parsing van Nikto, ZAP, testssl.sh en WhatWeb JSON/XML naar findings.

## Dashboard
- Severity- en statusfilters, iconen, offline SVG-assets.
- Screenshots via optionele Playwright browser, geen externe CDN.
- Nuclei-vergelijking new/not-detected/unchanged: eerste versie aanwezig. Uitbreiden naar andere scanners, confidence en reopened lifecycle.
- False positive, accepted risk en evidence-review workflow.

## Extra scanners, per profiel
- Wafw00f: toegevoegd in v1.1-dev.
- SSLyze: TLS tweede mening, geen dubbel tellen.
- Feroxbuster: optionele content discovery, limieten en scope.
- Trivy + Syft: aparte local/image scanmodus voor eigen artifacts.
- Interactsh: optionele OAST, bij voorkeur self-hosted en alleen expliciet geactiveerd.
- ZAP Automation Framework: YAML scanplannen met optionele auth.

## Compliance en integratie
- DokuWiki technisch assessment: eerste export aanwezig, daarna uitbreiden met het volledige vaste template en formele review. ISO controls blijven suggesties tot validatie.
- ISOPlanner blijft ISMS-bron, DokuWiki technische evidence.
- Forgejo CI, geplande scans en gecontroleerde retentie.
- SBOM met exacte scanner- en templateversies, vastgepinde dependencies.

### Follow-up after fixpack

- Record exit status for **all** scanner subprocesses, not only the tools covered by this fixpack.
- Preserve stage start/end time, measured request counts and full errors in a structured manifest.
- Restrict parameter scanning to confirmed reachable HTML/API routes using HEAD/GET content types.
- Normalize and classify Nikto, Arjun and Dalfox findings separately from process errors.
- Improve Nuclei comparability using template-set fingerprints rather than matching profile alone.
- Add locally bundled terminal recording/player (asciinema) in a later release, with token redaction.
