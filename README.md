# Ronny WebScanner

**Version 1.0.0** | Docker-based web security assessment suite

Ronny WebScanner is a fork and further development of [KP WebScanner](https://github.com/kpirnie/webscanner) by **Kevin Pirnie**. This release retains the original 18-step scanning pipeline and adds Ronny WebScanner branding and a revised terminal/HTML interface. The upstream author's contribution remains credited under the MIT license.

> Only test systems that you own or are expressly authorized to assess. Active scans may generate substantial traffic or affect the target.

## Version 1.0.0

This is the **baseline release**, intended to be committed and tagged before any v1.1 development begins. There are **no scan profiles, `--check-deps`, Wafw00f, offline dashboard, or comparison of historical findings** in this version. Those are proposed for later releases.

The HTML report uses UIkit assets from a CDN. An internet connection may therefore be needed to display all styling and icons.

## Requirements

- Docker with Buildx / BuildKit for building the image
- Network access during build to download scanner dependencies
- Docker host networking and `NET_RAW`/`NET_ADMIN` for raw packet scanners, if those modules are enabled
- Enough disk, CPU and memory for Go tools and OWASP ZAP

## Build

```bash
docker buildx build --progress=plain --load -t ronny-webscanner:1.0.0 .
```

## Usage

```bash
mkdir -p results

docker run --rm --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$PWD/results:/output" \
  ronny-webscanner:1.0.0 \
  https://example.org -o example
```

A more limited run that skips several active test modules:

```bash
docker run --rm --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$PWD/results:/output" \
  ronny-webscanner:1.0.0 \
  https://example.org -o baseline \
  --skip-brute --skip-arjun --skip-xss \
  --skip-sqlmap --skip-osv --skip-zap --skip-botblocker
```

**Note:** This is not a formal non-invasive baseline profile: Nikto, Nmap and Nuclei still send active requests unless separately disabled.

List command-line options:

```bash
docker run --rm ronny-webscanner:1.0.0 --help
```

## Scan pipeline

| Step | Function | Tools |
| --- | --- | --- |
| 1 | Fingerprinting | WhatWeb, httpx |
| 2 | Passive reconnaissance | Shodan, Censys (API keys optional) |
| 3 | Subdomains | Subfinder, httpx |
| 4 | DNS records | dnsx |
| 5 | Open ports | Naabu |
| 6 | Services and NSE | Nmap |
| 7 | TLS configuration | testssl.sh |
| 8 | HTTP security headers | Mozilla Observatory |
| 9 | Web-server checks | Nikto |
| 10 | CMS detection | WPScan for detected WordPress |
| 11 | Content and endpoints | Katana, Gobuster, ffuf |
| 12 | Parameters | Arjun |
| 13 | XSS | Dalfox |
| 14 | SQL injection | SQLMap |
| 15 | Dependencies | OSV-Scanner (if manifests are found) |
| 16 | Template vulnerability checks | Nuclei |
| 17 | Bad-bot-blocker validation | HTTP test requests |
| 18 | Dynamic web scanning | OWASP ZAP |

The named tools do not guarantee coverage of every vulnerability category. Absence of findings is not proof that the target is secure. In v1.0 some scanners may fail or time out without a distinct status in the summary, so always examine the raw scanner outputs.

## Command-line options

| Option | Description |
| --- | --- |
| `-o PATH` | Save under `/output/PATH/<host>_<timestamp>/` |
| `--severity LEVEL` | Nuclei severities, default `low,medium,high,critical` |
| `--bot-sample N` | Bad bot sample size, default 50 |
| `--skip-fingerprint` | WhatWeb and httpx |
| `--skip-recon` | Shodan and Censys |
| `--skip-subdomains` | Subfinder |
| `--skip-dns` | dnsx |
| `--skip-ports` | Naabu |
| `--skip-nmap` | Nmap |
| `--skip-ssl` | testssl.sh |
| `--skip-headers` | HTTP Observatory |
| `--skip-nikto` | Nikto |
| `--skip-cms` | CMS detection and WPScan |
| `--skip-crawl` | Katana |
| `--skip-brute` | Gobuster and ffuf |
| `--skip-arjun` | Arjun |
| `--skip-xss` | Dalfox |
| `--skip-sqlmap` | SQLMap |
| `--skip-osv` | OSV-Scanner |
| `--skip-nuclei` | Nuclei |
| `--skip-botblocker` | Bad-bot-blocker validation |
| `--skip-zap` | OWASP ZAP |
| `--help` | Show CLI help |

## Optional credentials

Set `WPSCAN_API_TOKEN`, `SHODAN_API_KEY`, and `CENSYS_APP_ID` / `CENSYS_TOKEN` with Docker `-e` if you use the corresponding integrations. Never commit API keys to the repository.

## Results

With `-o`, the scanner creates a timestamped output directory containing `scan.log`, `report.html` and the individual tools' results, where produced. For example:

```text
results/
└── example/
    └── example.org_20261124_060000/
        ├── scan.log
        ├── report.html
        ├── nmap.txt
        ├── nmap.xml
        ├── testssl.txt
        ├── testssl.json
        ├── nuclei.txt
        ├── nuclei.json
        └── ...
```

Individual files may be absent when scanners are skipped or have no output. The report is a convenience overview, not a replacement for validation of original evidence.

## Known limitations in v1.0

- Several scanner steps use tolerant error handling; a displayed `done` does not always mean the scan completed successfully.
- Broad Nmap NSE selection may cause timeouts.
- IP-based bot-blocker checks that rely on `X-Forwarded-For` cannot reliably establish source-IP blocking. Proxy whitelisting can also influence results.
- Counting findings by text patterns can overcount or misclassify results.
- The HTML dashboard loads UIkit from a third-party CDN.
- Scanner versions and Nuclei templates are not fully pinned for reproducible builds.

These items are candidates for v1.1 and later, **not features of v1.0**.

## Attribution and license

This project is based on **[KP WebScanner](https://github.com/kpirnie/webscanner)**, originally developed by **Kevin Pirnie** (Copyright (c) 2026 Kevin Pirnie). This fork is developed and branded by **Ronny Roethof**, starting November 2026. The project is distributed under the [MIT License](LICENSE); see [NOTICE.md](NOTICE.md) for the origin and attribution statement.

External scanners and libraries retain their respective licenses. The project's MIT license does not supersede their licenses.
