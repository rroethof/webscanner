# Ronny WebScanner v1.1.0-dev

Werkversie op basis van de bevroren v1.0.0. Dit is **ontwikkelcode**, geen productiegevalideerde release.

Gebaseerd op KP WebScanner (https://github.com/kpirnie/webscanner). Controleer en behoud de upstream licentie en attributie.

## Nieuw

- `--profile baseline|webapp|extended`, standaard `extended` voor terugwaartse compatibiliteit.
- `--check-deps` om toolbeschikbaarheid te controleren.
- Wafw00f als extra fingerprinttool (`pip install wafw00f` in de image).
- Nmap met beperkte serviceanalyse en gerichte NSE, zonder brede broadcast-/vulnselectie.
- Nuclei-template-updates niet meer tijdens iedere scan.
- Nmap, testssl.sh, Nuclei en ZAP hebben vastgelegde processtatussen (`scanner-exitcodes.tsv`).
- Bad Bot Blocker controle presenteert geen gespoofte X-Forwarded-For-headers meer als bewijs van bron-IP-blokkering.
- Nieuw **volledig offline** `report.html` met ingebouwde CSS, emoji-iconen, filters en scannerstatussen.
- `findings.json` bevat genormaliseerde **Nuclei**-bevindingen en stabiele IDs.
- `scan-manifest.json` registreert profiel, scannerstatussen, artefacten en beperkingen.
- Het vorige UIkit-rapport blijft behouden als `report-legacy.html`.
- `--previous /output/.../previous-run` vergelijkt aantoonbaar afgeronde Nuclei-scans.
- `comparison.json` toont nieuwe, niet meer gedetecteerde en ongewijzigde Nuclei-bevindingen.
- `report.dokuwiki.txt` is een DokuWiki-geschikte technische assessmentpagina met ISO 27001-referenties die handmatig beoordeeld moeten worden.

## Build

```bash
docker buildx build --load -t ronny-webscanner:1.1.0-dev .
```

## Run

```bash
mkdir -p results
docker run --rm --network host --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$PWD/results:/output" ronny-webscanner:1.1.0-dev \
  https://example.org -o example --profile baseline
```

Voor een vergelijking met een vorige scan moet die vorige map ook in de container bereikbaar zijn:

```bash
docker run --rm --network host --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$PWD/results:/output" ronny-webscanner:1.1.0-dev \
  https://example.org -o example --profile baseline \
  --previous /output/example/example.org_20261123_190000
```

Vervang de voorbeeldmap door het daadwerkelijke pad van je vorige run. De vergelijking vindt alleen plaats bij hetzelfde target, hetzelfde profiel en aantoonbaar succesvolle Nuclei-runs. Verdwenen Nuclei-findings zijn nog niet automatisch verholpen kwetsbaarheden.

Alleen scannen binnen expliciet geautoriseerde scope. Baseline voert nog steeds actieve netwerkrequests uit.

## Statussen

- `COMPLETED`: procesexitcode 0 met controleerbare afronding (momenteel Nmap, testssl, Nuclei en ZAP; Nuclei kan terecht nul findings hebben).
- `FAILED`: procesexitcode niet-nul (dezelfde vier tools).
- `OUTPUT_PRESENT`: output bestaat, maar exitstatus is nog niet betrouwbaar vastgelegd.
- `PARTIAL`: mogelijk probleem in logoutput.
- `SKIPPED`: scanner of groep uitgeschakeld.
- `UNVERIFIED`: geen bewijsmateriaal of enkel console-output.

Deze status zegt **niets** over het aantal kwetsbaarheden. Slechts Nuclei-JSON wordt naar `findings.json` geconverteerd.

## Nog niet geïmplementeerd

Playwright screenshots, Trivy/Syft SBOM- en imagescans, Interactsh self-hosted integratie, SSLyze, feroxbuster, historievergelijking voor andere scanners dan Nuclei, scheduler en volledige processtatusvastlegging voor alle tools. Zie `ROADMAP.md`.

## Kwaliteitsgrenzen

Het oude script bevat nog enkele `|| true`-constructies en gebruikt nog niet overal een processtatus. De bot-check heeft nog beperkingen, onder meer source-IP-whitelisting en het onderscheid tussen HTTP blokkade en onverwachte statuscodes. Volledige containerbuild en echte scans zijn hier niet uitgevoerd.

## Licentie en attributie

Ronny WebScanner is een fork en uitbreiding van [KP WebScanner](https://github.com/kpirnie/webscanner) van Kevin Pirnie, uitgebracht onder de MIT-licentie. De originele copyrightvermelding en licentietekst staan in [`LICENSE`](LICENSE). Zie ook [`NOTICE.md`](NOTICE.md).

De scannerprogramma's die in de container worden geïnstalleerd, zijn afzonderlijke projecten met hun eigen licenties.

## Develop fixpack: conservative scan status and load control

This is a **development fixpack**, not a tagged v1.1.0 release. It follows the
2026-11-24 BW02 `webapp` assessment, where Nuclei exited zero despite processing
only 13,057 of 17,546 scheduled requests and reporting 148 request errors.

- `baseline` and `webapp` default to Nuclei `-rl 10 -c 3`; `extended` defaults
  to `-rl 20 -c 5`. Override using `--nuclei-rate N` and
  `--nuclei-concurrency N` for explicitly authorized assessments.
- Nuclei OAST/Interactsh is disabled by default using `-ni`.
  Enable external callbacks *only if authorized* with `--allow-oast`.
- Nuclei console statistics are assessed independently of process exit code.
  Request errors, incomplete coverage, or unreachable targets yield `PARTIAL`.
  When statistics are absent, completeness is not presumed.
- Nikto error-limit termination is `PARTIAL`; Arjun targeting excludes common
  static assets and stays in the requested hostname. Arjun per-target errors
  are treated as `PARTIAL`.
- Dalfox runs only on discovered same-host URLs containing query parameters;
  otherwise status is `NOT_APPLICABLE`. This does not assert that XSS is absent.
- WPScan reports `NOT_APPLICABLE` when WordPress is not detected.
- HTML and DokuWiki reports show observed Nuclei request coverage and scan
  limitations. Nuclei comparisons refuse to close findings if either scan
  lacks verified successful completion.

Example (authorized target):

```sh
docker buildx build --load -t webscanner:v1.1.0-dev-fixes .
docker run --rm webscanner:v1.1.0-dev-fixes --check-deps

docker run --rm --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$HOME/webscanner/results:/output" \
  webscanner:v1.1.0-dev-fixes \
  https://example.org --profile webapp \
  --skip-sqlmap --skip-zap --skip-botblocker \
  -o webapp-review
```

`scanner-status.tsv` contains explicit `PARTIAL` and `NOT_APPLICABLE`
classification overrides and `scanner-exitcodes.tsv` records selected tool
exit codes. These support audit trails but do not replace human validation.

Run local tests:

```sh
bash -n scan.sh
python3 -m unittest discover -s tests -v
```
