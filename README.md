# Ronny WebScanner

**Status:** v1.1.0-dev, in ontwikkeling. De stabiele versie is `v1.0.0`.

Ronny WebScanner is een Docker-gebaseerde verzameling tools voor technische security-assessments van webapplicaties en hun publicatieomgeving. Het project is een fork van [KP WebScanner](https://github.com/kpirnie/webscanner) van Kevin Pirnie.

De scanner verzamelt technisch bewijs en helpt bij de beoordeling daarvan. Een scan zonder bevindingen is geen garantie dat een applicatie veilig is.

> Gebruik de scanner uitsluitend voor systemen waarvoor je expliciet toestemming hebt. Sommige profielen voeren actieve, potentieel belastende controles uit.

## Snel starten

Bouw de ontwikkelversie vanuit deze branch:

```bash
docker buildx build --load -t ronny-webscanner:1.1.0-dev .
```

Controleer of de benodigde tools in de container beschikbaar zijn:

```bash
docker run --rm ronny-webscanner:1.1.0-dev --check-deps
```

Voer een beperkte scan uit op een geautoriseerd doel:

```bash
mkdir -p results

docker run --rm --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$PWD/results:/output" \
  -e SCAN_OUTPUT_UID="$(id -u)" -e SCAN_OUTPUT_GID="$(id -g)" \
  ronny-webscanner:1.1.0-dev \
  https://example.org --profile baseline -o example
```

Voor een webapp-assessment:

```bash
docker run --rm --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$PWD/results:/output" \
  -e SCAN_OUTPUT_UID="$(id -u)" -e SCAN_OUTPUT_GID="$(id -g)" \
  ronny-webscanner:1.1.0-dev \
  https://example.org --profile webapp \
  --skip-sqlmap --skip-zap --skip-botblocker \
  -o webapp-review
```

Vervang `example.org` door het geautoriseerde doel. De voorbeelden gebruiken `--network host` en netwerkcapabilities om de netwerktools binnen Docker te kunnen gebruiken. Controleer of deze rechten in jouw omgeving nodig en toegestaan zijn.

De container voert de scanners nog steeds als root uit. Met `SCAN_OUTPUT_UID` en `SCAN_OUTPUT_GID` zet het scanproces bij normale beëindiging de eigendom van de nieuw aangemaakte scanmap terug naar de hostgebruiker. Bij abrupt afbreken (bijvoorbeeld `docker kill -s KILL`) kan herstel van bestandsrechten alsnog nodig zijn. Gebruik bij `-o` uitsluitend één mapnaam, zonder padcomponenten.

Een bestaand rapport opnieuw genereren kan vanuit de host met `python3 reporting/generate.py --out /pad/naar/bestaande/scanmap --target https://example.org`. Een lege of niet-bestaande `--out` wordt geweigerd; bestaande scanmappen worden niet automatisch aangemaakt.

## Scanprofielen en opties

| Profiel | Gebruik | Standaard Nuclei-instellingen |
| --- | --- | --- |
| `baseline` | Beperkte technische uitgangsmeting, zonder crawlen | 10 requests/s, concurrency 3 |
| `webapp` | Webapplicatieonderzoek met endpoint discovery | 10 requests/s, concurrency 3 |
| `extended` | Uitgebreidere actieve controles | 20 requests/s, concurrency 5 |

Zonder `--profile` gebruikt de scanner om compatibiliteitsredenen `extended`. Kies daarom bij voorkeur expliciet een profiel.

Veelgebruikte opties:

| Optie | Betekenis |
| --- | --- |
| `-o NAAM` | Bewaar resultaten onder `/output/NAAM/` |
| `--profile baseline\|webapp\|extended` | Kies het scanprofiel |
| `--severity LEVELS` | Filter de Nuclei-severities |
| `--nuclei-rate N` | Stel de Nuclei-requestlimiet in |
| `--nuclei-concurrency N` | Stel de Nuclei-concurrency in |
| `--previous PAD` | Vergelijk met een eerdere scanmap |
| `--allow-oast` | Sta externe Nuclei OAST/Interactsh-callbacks expliciet toe |
| `--check-deps` | Controleer geïnstalleerde tools |
| `--skip-*` | Schakel specifieke controles uit; zie `--help` |

Nuclei gebruikt standaard `-ni`, zodat externe Interactsh-callbacks uitstaan. `--allow-oast` schakelt die beperking alleen uit wanneer dat uitdrukkelijk gewenst en toegestaan is.

De volledige CLI-help is beschikbaar met:

```bash
docker run --rm ronny-webscanner:1.1.0-dev --help
```

## Scopebewaking

De hardening-branch bevat twee maatregelen voor endpoint discovery:

1. Katana draait met `-fs fqdn` om de crawl tot de opgegeven hostname te beperken.
2. `scripts/scope_filter.py` filtert de gevonden URL's op exact HTTP(S)-origin (protocol, hostname en poort), dedupliceert ze en maakt een afzonderlijk bestand met afgewezen URL's.

De relevante bestanden zijn `endpoints-raw.txt`, `endpoints.txt` en `endpoints-out-of-scope.txt`. Vervolgscanners zoals Arjun en Dalfox gebruiken de gefilterde lijst; SQLMap kan die lijst eveneens gebruiken.

**Dit is nog geen volledige scopegarantie voor de gehele scanengine.** Redirects en afzonderlijke actieve tools moeten nog verder worden gecontroleerd. Gebruik de scanner niet voor een domein zonder toestemming voor de bijbehorende actieve tests.

## Resultaten en auditbewijs

De scanner maakt per run een map met de ruwe tooluitvoer en aanvullende rapportages.

| Bestand | Inhoud |
| --- | --- |
| `scan.log` | Log van de scan |
| `scanner-exitcodes.tsv` | Vastgelegde exitcodes van geselecteerde tools |
| `scanner-status.tsv` | Expliciete statuscorrecties, zoals `PARTIAL` en `NOT_APPLICABLE` |
| `scan-manifest.json` | Doel, profiel, scannerstatussen, dekking en beperkingen |
| `findings.json` | Genormaliseerde Nuclei-bevindingen |
| `report.html` | Zelfstandig offline dashboard |
| `report-legacy.html` | Oorspronkelijk uitgebreid UIkit-rapport |
| `report.dokuwiki.txt` | Technisch scanoverzicht voor DokuWiki |
| `comparison.json` | Vergelijking met een eerdere scan, indien aangevraagd |

De rapportgenerator verwerkt op dit moment alleen Nuclei-bevindingen tot genormaliseerde findings. Andere tooluitvoer blijft als technisch bewijs beschikbaar.

### Scannerstatussen

| Status | Betekenis |
| --- | --- |
| `COMPLETED` | De tool heeft volgens de beschikbare uitvoeringsgegevens succesvol afgerond |
| `PARTIAL` | De scan is niet aantoonbaar volledig uitgevoerd |
| `FAILED` | De tool heeft een bekende foutstatus |
| `OUTPUT_PRESENT` | Er is uitvoer, maar succesvolle afronding is niet bevestigd |
| `UNVERIFIED` | Er is onvoldoende bewijs voor een betrouwbare status |
| `NOT_APPLICABLE` | De controle is voor het doel niet van toepassing |
| `SKIPPED` | De controle is bewust overgeslagen |

Bij Nuclei worden exitcode en gerapporteerde requestdekking apart beoordeeld. Een exitcode 0 met requestfouten leidt niet automatisch tot `COMPLETED`. Ook Nikto die op zijn HTTP-foutlimiet stopt en Arjun met bekende doelfouten worden als gedeeltelijk beoordeeld.

Een status zegt niets op zichzelf over de aanwezigheid of afwezigheid van kwetsbaarheden.

## CrowdSec en WAF-beoordeling

**Scanneruitvoering, testdekking en effectiviteit van beveiligingsmaatregelen zijn verschillende beoordelingen.** Een WAF die een aanval bewust met HTTP 403 tegenhoudt, kan correct functioneren terwijl een kwetsbaarheidstest de achterliggende applicatie niet volledig bereikt.

Een losse HTTP 403 bewijst niet dat CrowdSec de blokkering heeft veroorzaakt.

De rapportgenerator kan optioneel door een beheerder gecorreleerd bewijs verwerken. Plaats in de betreffende scanmap een `waf-evidence.json`:

```json
{
  "events": [
    {
      "host": "example.org",
      "http_status": 403,
      "crowdsec_alert_id": "ALERT_ID",
      "crowdsec_rule": "crowdsecurity/example-rule",
      "crowdsec_alert_reference": "cscli alerts inspect ALERT_ID",
      "proxy_log_reference": "access.log:2026-11-24T08:41:24"
    }
  ]
}
```

Bij een passende hostname, HTTP 403 en ingevulde verwijzingen naar zowel CrowdSec als de reverse-proxylog rapporteert de generator `CONTROL_EFFECTIVE` voor deze aangeleverde gebeurtenissen. Zonder bruikbaar bewijs blijft de status `UNVERIFIED`.

Deze classificatie is **geen automatische koppeling met CrowdSec**. Het programma controleert de externe logs niet zelfstandig en verifieert niet dat de bewijsverwijzingen inhoudelijk kloppen. Nuclei-requestfouten blijven afzonderlijk zichtbaar en worden niet automatisch aan CrowdSec toegeschreven.

De functie is momenteel onderdeel van `reporting/generate.py`, niet van de algemene `scan.sh`-CLI. Voor het opnieuw genereren van een bestaand rapport moet je de oorspronkelijke doel- en profielgegevens aan de rapportgenerator doorgeven; houd er rekening mee dat dit de rapportbestanden in de bestaande scanmap opnieuw schrijft.

## Scans vergelijken

Gebruik `--previous` en zorg dat de eerdere scanmap via dezelfde Docker-volume beschikbaar is:

```bash
docker run --rm --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$PWD/results:/output" \
  -e SCAN_OUTPUT_UID="$(id -u)" -e SCAN_OUTPUT_GID="$(id -g)" \
  ronny-webscanner:1.1.0-dev \
  https://example.org --profile baseline -o example \
  --previous /output/example/example.org_20261123_190000
```

Vergelijkingen vereisen hetzelfde doel, hetzelfde profiel en voldoende betrouwbare Nuclei-dekking. De vergelijking onderscheidt nieuwe, ongewijzigde en niet meer gedetecteerde findings. **Niet meer gedetecteerd is niet automatisch opgelost.**

## Ontwikkeling en kwaliteit

De broncode staat in [rroethof/webscanner](https://github.com/rroethof/webscanner). De branches hebben elk een eigen rol:

| Branch | Doel |
| --- | --- |
| `master` | Stabiele v1.0.0-inhoud |
| `develop` | Ontwikkelbasis voor v1.1.0 |
| `feature/v1.1-hardening` | Scope- en rapportageverbeteringen, nog niet gemerged |

Voer de bestaande tests lokaal uit:

```bash
bash -n scan.sh
python3 -m unittest discover -s tests -v
```

De tests vervangen geen volledige Dockerbuild of gecontroleerde praktijkbeproeving. Deze hardening-wijzigingen zijn nog niet als stabiele v1.1.0-release gevalideerd.

Meerdere kernscanners leggen nu hun werkelijke procesexitcode vast via `run_logged`, waaronder WhatWeb, httpx, DNSX, Naabu, Nmap, testssl.sh, Nikto, Katana, Arjun, Dalfox, SQLMap, Nuclei en Wafw00f. Exitcode 0 bewijst op zichzelf geen volledige kwetsbaarheidsdekking.

De belangrijkste resterende werkzaamheden zijn exitcode- en timingregistratie voor de overige stappen, verdere redirect- en scopebeveiliging, betrouwbare verwerking van Nikto/Arjun/Dalfox en uitgebreidere rapportage. Zie [ROADMAP.md](ROADMAP.md) voor de ontwikkelplanning.

## Licentie en herkomst

Ronny WebScanner bouwt voort op [KP WebScanner](https://github.com/kpirnie/webscanner) van Kevin Pirnie, onder de MIT-licentie. De oorspronkelijke attributie blijft behouden in [LICENSE](LICENSE) en [NOTICE.md](NOTICE.md).

Meegeleverde externe scanners zijn afzonderlijke projecten met hun eigen licentievoorwaarden.
