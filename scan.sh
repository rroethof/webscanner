#!/usr/bin/env bash
# =============================================================================
# Ronny WebScanner — based on KP WebScanner by Kevin Pirnie
# Upstream: https://github.com/kpirnie/webscanner
# Original source copyright (c) 2026 Kevin Pirnie, MIT License
# Fork modifications (c) 2026 Ronny Roethof
# =============================================================================

set -euo pipefail

# really only for reference
VER='1.1.0-dev'

# Terminal UI. Disable colour when stdout is not interactive.
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
    CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
    BLUE=$'\033[1;34m'; DIM=$'\033[2m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''; BLUE=''; DIM=''
fi
info()    { printf '%b\n' "${CYAN}◆${RESET}  $*"; }
ok()      { printf '%b\n' "${GREEN}✔${RESET}  $*"; }
warn()    { printf '%b\n' "${YELLOW}⚠${RESET}  $*"; }
section() {
    printf '\n%b\n' "${BLUE}╭──────────────────────────────────────────────────────────────────╮${RESET}"
    printf '%b\n' "${BOLD}${CYAN}│  ◈  $*${RESET}"
    printf '%b\n\n' "${BLUE}╰──────────────────────────────────────────────────────────────────╯${RESET}"
}

usage() {
cat <<EOF

${BOLD}Ronny WebScanner${RESET} — based on KP WebScanner

${BOLD}Usage:${RESET}
  docker run --rm --network host --cap-add NET_ADMIN --cap-add NET_RAW \\
    [-v /host/output/path:/output] \\
    webscan <target-uri> [options]

${BOLD}Arguments:${RESET}
  <target-uri>        Bare domain or full URI
                        example.com
                        https://example.com
                        https://example.com:8443

${BOLD}Options:${RESET}
  -o PATH               Write results to /output/PATH (requires volume mount)
                        Omit to print summary to stdout
  --severity LEVEL      Nuclei severity filter (default: low,medium,high,critical)
  --profile NAME        baseline | webapp | extended (default: extended)
  --check-deps          Check tool availability and exit
  --previous DIR        Compare with previous run directory (mounted inside container)
  --nuclei-rate N       Nuclei requests/second (baseline/webapp: 10, extended: 20)
  --nuclei-concurrency N Concurrent Nuclei templates (baseline/webapp: 3, extended: 5)
  --allow-oast          Explicitly enable external Nuclei OAST/Interactsh callbacks

${BOLD}Skip Flags:${RESET}
  --skip-fingerprint    Skip WhatWeb + httpx
  --skip-recon          Skip Shodan + Censys
  --skip-subdomains     Skip subfinder subdomain enumeration
  --skip-dns            Skip dnsx DNS enumeration
  --skip-ports          Skip naabu port scanning
  --skip-nmap           Skip Nmap service + script scan
  --skip-ssl            Skip testssl.sh
  --skip-headers        Skip Mozilla Observatory
  --skip-nikto          Skip Nikto
  --skip-cms            Skip CMS detection + WPScan
  --skip-crawl          Skip katana crawling
  --skip-brute          Skip gobuster + ffuf
  --skip-arjun          Skip Arjun parameter discovery
  --skip-xss            Skip Dalfox XSS scanning
  --skip-sqlmap         Skip sqlmap SQL injection
  --skip-osv            Skip OSV-Scanner dependency scanning
  --skip-nuclei         Skip Nuclei vulnerability scanning
  --skip-botblocker     Skip nginx bad bot blocker validation
  --bot-sample N        Bad-bot random sample size per category (default: 50)
  --skip-zap            Skip OWASP ZAP active scan
  --help                Show this help

EOF
    exit 0
}

# -----------------------------------------------------------------------------
# Args
# -----------------------------------------------------------------------------
if [[ "${1:-}" == "--check-deps" ]]; then
    tools=(whatweb httpx subfinder dnsx naabu nmap testssl.sh mdn-http-observatory-scan nikto wpscan katana gobuster ffuf arjun dalfox sqlmap osv-scanner nuclei curl jq zap.sh wafw00f python3)
    missing=0
    for tool in "${tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then printf '[OK] %s\n' "$tool"; else printf '[MISSING] %s\n' "$tool"; ((missing+=1)); fi
    done
    ((missing==0))
    exit $?
fi
[[ $# -lt 1 || "$1" == "--help" ]] && usage

TARGET_RAW="$1"; shift

OUTPUT_PATH=""
SEVERITY="low,medium,high,critical"
PROFILE="extended"
PREVIOUS_DIR=""
REQUESTED_SKIPS=()
SKIP_FINGERPRINT=false
SKIP_RECON=false
SKIP_SUBDOMAINS=false
SKIP_DNS=false
SKIP_PORTS=false
SKIP_NMAP=false
SKIP_SSL=false
SKIP_HEADERS=false
SKIP_NIKTO=false
SKIP_CMS=false
SKIP_CRAWL=false
SKIP_BRUTE=false
SKIP_ARJUN=false
SKIP_XSS=false
SKIP_SQLMAP=false
SKIP_OSV=false
SKIP_NUCLEI=false
SKIP_BOTBLOCKER=false
SKIP_ZAP=false
SAMPLE_SIZE=50
NUCLEI_RATE=""
NUCLEI_CONCURRENCY=""
ALLOW_OAST=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o)                  OUTPUT_PATH="$2"; shift ;;
        --severity)          SEVERITY="$2"; shift ;;
        --profile)           PROFILE="$2"; shift ;;
        --previous)          [[ $# -ge 2 ]] || { echo "--previous requires a path" >&2; exit 2; }; PREVIOUS_DIR="$2"; shift ;;
        --nuclei-rate)       [[ $# -ge 2 ]] || { echo "--nuclei-rate requires a number" >&2; exit 2; }; NUCLEI_RATE="$2"; shift ;;
        --nuclei-concurrency) [[ $# -ge 2 ]] || { echo "--nuclei-concurrency requires a number" >&2; exit 2; }; NUCLEI_CONCURRENCY="$2"; shift ;;
        --allow-oast)        ALLOW_OAST=true ;;
        --skip-fingerprint)  SKIP_FINGERPRINT=true ;;
        --skip-recon)        SKIP_RECON=true ;;
        --skip-subdomains)   SKIP_SUBDOMAINS=true ;;
        --skip-dns)          SKIP_DNS=true ;;
        --skip-ports)        SKIP_PORTS=true ;;
        --skip-nmap)         SKIP_NMAP=true ;;
        --skip-ssl)          SKIP_SSL=true ;;
        --skip-headers)      SKIP_HEADERS=true ;;
        --skip-nikto)        SKIP_NIKTO=true ;;
        --skip-cms)          SKIP_CMS=true ;;
        --skip-crawl)        SKIP_CRAWL=true ;;
        --skip-brute)        SKIP_BRUTE=true ;;
        --skip-arjun)        SKIP_ARJUN=true ;;
        --skip-xss)          SKIP_XSS=true ;;
        --skip-sqlmap)       SKIP_SQLMAP=true ;;
        --skip-osv)          SKIP_OSV=true ;;
        --skip-nuclei)       SKIP_NUCLEI=true ;;
        --skip-botblocker)   SKIP_BOTBLOCKER=true ;;
        --bot-sample)        SAMPLE_SIZE="$2"; shift ;;
        --skip-zap)          SKIP_ZAP=true ;;
        --help)              usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
    shift
done

# Profiles apply before scanning; explicit --skip-* flags remain active.
case "$PROFILE" in
    baseline)
        SKIP_RECON=true; SKIP_SUBDOMAINS=true; SKIP_CRAWL=true
        SKIP_BRUTE=true; SKIP_ARJUN=true; SKIP_XSS=true; SKIP_SQLMAP=true
        SKIP_OSV=true; SKIP_BOTBLOCKER=true; SKIP_ZAP=true
        ;;
    webapp)
        SKIP_RECON=true; SKIP_SUBDOMAINS=true; SKIP_BRUTE=true
        SKIP_SQLMAP=true; SKIP_OSV=true; SKIP_BOTBLOCKER=true
        ;;
    extended) ;;
    *) printf 'Unknown profile: %s\n' "$PROFILE" >&2; exit 2 ;;
esac

# Rate limiting is conservative for production targets. No externally hosted OAST by default.
if [[ "$PROFILE" == "extended" ]]; then
    : "${NUCLEI_RATE:=20}"
    : "${NUCLEI_CONCURRENCY:=5}"
else
    : "${NUCLEI_RATE:=10}"
    : "${NUCLEI_CONCURRENCY:=3}"
fi
for value in "$NUCLEI_RATE" "$NUCLEI_CONCURRENCY"; do
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || { echo "Nuclei rates must be positive integers" >&2; exit 2; }
done

# -----------------------------------------------------------------------------
# Normalise target
# -----------------------------------------------------------------------------
TARGET_URI="${TARGET_RAW%/}"
[[ "${TARGET_URI}" != http* ]] && TARGET_URI="https://${TARGET_URI}"
TARGET_HOST=$(echo "${TARGET_URI}" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)

# -----------------------------------------------------------------------------
# Output directory
# -----------------------------------------------------------------------------
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SCAN_NAME="${TARGET_HOST}_${TIMESTAMP}"

if [[ -n "${OUTPUT_PATH}" ]]; then
    OUT_DIR="/output/${OUTPUT_PATH}/${SCAN_NAME}"
    mkdir -p "${OUT_DIR}"
    exec > >(tee -a "${OUT_DIR}/scan.log") 2>&1
else
    OUT_DIR="/tmp/${SCAN_NAME}"
    mkdir -p "${OUT_DIR}"
fi

SCAN_STATUS_FILE="${OUT_DIR}/scanner-exitcodes.tsv"
: > "${SCAN_STATUS_FILE}"
SCAN_OVERRIDES_FILE="${OUT_DIR}/scanner-status.tsv"
: > "${SCAN_OVERRIDES_FILE}"
mark_status() { # scanner, COMPLETED/PARTIAL/FAILED/NOT_APPLICABLE, note
    local key="$1" state="$2" note="${3:-}"
    note="${note//$'\t'/ }"; note="${note//$'\n'/ }"
    printf '%s\t%s\t%s\n' "$key" "$state" "$note" >> "$SCAN_OVERRIDES_FILE"
}
# Store exit code from first command in pipeline. Never report success from tee.
run_logged() {
    local key="$1" log="$2" rc
    shift 2
    if "$@" 2>&1 | tee "$log"; then rc=0; else rc=${PIPESTATUS[0]}; fi
    printf '%s\t%s\n' "$key" "$rc" >> "$SCAN_STATUS_FILE"
    return "$rc"
}

# Wordlist
WORDLIST=""
for wl in /usr/share/wordlists/big.txt \
          /usr/share/dirb/wordlists/big.txt \
          /usr/share/wordlists/dirb/big.txt \
          /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt; do
    [[ -f "${wl}" ]] && { WORDLIST="${wl}"; break; }
done

# -----------------------------------------------------------------------------
# Banner
# -----------------------------------------------------------------------------
section "webscan"
info "Target:      ${BOLD}${TARGET_URI}${RESET}"
info "Host:        ${TARGET_HOST}"
[[ -n "${OUTPUT_PATH}" ]] && info "Output:      ${OUT_DIR}"
info "Severity:    ${SEVERITY}"
info "Profile:     ${PROFILE}"
info "Release:     Ronny WebScanner ${VER}"
info "Started:     $(date)"

# -----------------------------------------------------------------------------
# 1 — Fingerprinting
# -----------------------------------------------------------------------------
section "1/18 — Fingerprinting"

if [[ "${SKIP_FINGERPRINT}" == "false" ]]; then
    info "whatweb..."
    whatweb "${TARGET_URI}" --log-verbose="${OUT_DIR}/whatweb.txt" 2>&1 \
        | tee "${OUT_DIR}/whatweb_console.txt" || true
    ok "whatweb done"

    info "httpx..."
    echo "${TARGET_HOST}" | httpx \
        -title -tech-detect -status-code -content-length -web-server -ip \
        -follow-redirects -o "${OUT_DIR}/httpx.txt" 2>&1 \
        | tee "${OUT_DIR}/httpx_console.txt" || true
    ok "httpx done"
else
    warn "Fingerprinting skipped (--skip-fingerprint)"
fi

# -----------------------------------------------------------------------------
# 2 — Passive Recon
# -----------------------------------------------------------------------------
section "2/18 — Passive Recon (Shodan & Censys)"

TARGET_IP=$(dig +short "${TARGET_HOST}" | grep -E '^[0-9]+\.' | head -1)

if [[ "${SKIP_RECON}" == "false" ]]; then
    if [[ -n "${SHODAN_API_KEY:-}" ]]; then
        info "Shodan lookup..."
        if [[ -n "${TARGET_IP}" ]]; then
            shodan init "${SHODAN_API_KEY}" &>/dev/null
            shodan host "${TARGET_IP}" > "${OUT_DIR}/shodan.txt" 2>&1 || true
            ok "Shodan done → ${OUT_DIR}/shodan.txt"
        else
            warn "Could not resolve ${TARGET_HOST} for Shodan"
        fi
    else
        warn "SHODAN_API_KEY not set — skipping Shodan (free key at shodan.io)"
    fi

    if [[ -n "${CENSYS_APP_ID:-}" && -n "${CENSYS_TOKEN:-}" ]]; then
        info "Censys lookup..."
        curl -s -H "Authorization: Bearer ${CENSYS_TOKEN}" \
            "https://search.censys.io/api/v2/hosts/${TARGET_IP:-${TARGET_HOST}}" \
            > "${OUT_DIR}/censys.txt" 2>&1 || true
        ok "Censys done → ${OUT_DIR}/censys.txt"
    else
        warn "CENSYS_APP_ID/CENSYS_TOKEN not set — skipping Censys (free at censys.io)"
    fi
else
    warn "Passive recon skipped (--skip-recon)"
fi

# -----------------------------------------------------------------------------
# 3 — Subdomain Enumeration
# -----------------------------------------------------------------------------
section "3/18 — Subdomain Enumeration"

if [[ "${SKIP_SUBDOMAINS}" == "false" ]]; then
    info "subfinder..."
    subfinder -d "${TARGET_HOST}" -o "${OUT_DIR}/subdomains.txt" 2>&1 \
        | tee "${OUT_DIR}/subfinder_console.txt" || true
    ok "subfinder done"

    if [[ -s "${OUT_DIR}/subdomains.txt" ]]; then
        info "Probing live subdomains..."
        cat "${OUT_DIR}/subdomains.txt" | httpx \
            -title -tech-detect -status-code \
            -o "${OUT_DIR}/subdomains_live.txt" 2>&1 || true
        ok "Subdomain probe done"
    fi
else
    warn "Subdomain enumeration skipped (--skip-subdomains)"
fi

# -----------------------------------------------------------------------------
# 4 — DNS
# -----------------------------------------------------------------------------
section "4/18 — DNS Enumeration"

if [[ "${SKIP_DNS}" == "false" ]]; then
    info "dnsx..."
    echo "${TARGET_HOST}" | dnsx \
        -a -aaaa -cname -mx -ns -txt -resp \
        -o "${OUT_DIR}/dns.txt" 2>&1 \
        | tee "${OUT_DIR}/dnsx_console.txt" || true
    ok "dnsx done"
else
    warn "DNS enumeration skipped (--skip-dns)"
fi

# -----------------------------------------------------------------------------
# 5 — Ports
# -----------------------------------------------------------------------------
section "5/18 — Port Scanning"

if [[ "${SKIP_PORTS}" == "false" ]]; then
    info "naabu (top 1000)..."
    naabu -host "${TARGET_HOST}" -top-ports 1000 \
        -o "${OUT_DIR}/ports.txt" 2>&1 \
        | tee "${OUT_DIR}/naabu_console.txt" || true
    ok "naabu done"
else
    warn "Port scanning skipped (--skip-ports)"
fi

# -----------------------------------------------------------------------------
# 6 — Nmap
# -----------------------------------------------------------------------------
section "6/18 — Nmap Service & Script Scan"

if [[ "${SKIP_NMAP}" == "false" ]]; then
    info "nmap — scoped service detection, no broad NSE broadcast scripts..."
    if [[ -s "${OUT_DIR}/ports.txt" ]]; then
        OPEN_PORTS=$(grep -oE ':[0-9]+' "${OUT_DIR}/ports.txt" | tr -d ':' | sort -u | tr '\n' ',' | sed 's/,$//')
    else
        OPEN_PORTS="80,443,8080,8443"
    fi

    if nmap -sV --version-light \
        --script "http-title,http-headers,ssl-cert" \
        -p "${OPEN_PORTS}" \
        --open \
        -oN "${OUT_DIR}/nmap.txt" \
        -oX "${OUT_DIR}/nmap.xml" \
        --host-timeout 600s \
        --max-retries 2 \
        "${TARGET_HOST}" 2>&1 \
        | tee "${OUT_DIR}/nmap_console.txt"
    then echo -e "nmap\t0" >> "${SCAN_STATUS_FILE}"; else echo -e "nmap\t1" >> "${SCAN_STATUS_FILE}"; warn "nmap failed or timed out"; fi
    info "nmap step finished (see status)"
else
    warn "Nmap skipped (--skip-nmap)"
fi

# -----------------------------------------------------------------------------
# 7 — SSL/TLS
# -----------------------------------------------------------------------------
section "7/18 — SSL/TLS Analysis"

if [[ "${SKIP_SSL}" == "false" ]]; then
    info "testssl.sh..."
    if testssl.sh \
        --logfile "${OUT_DIR}/testssl.txt" \
        --jsonfile "${OUT_DIR}/testssl.json" \
        --severity LOW --quiet \
        "${TARGET_URI}" 2>&1 \
        | tee "${OUT_DIR}/testssl_console.txt"
    then echo -e "testssl.sh\t0" >> "${SCAN_STATUS_FILE}"; else echo -e "testssl.sh\t1" >> "${SCAN_STATUS_FILE}"; warn "testssl.sh failed or timed out"; fi
    info "testssl.sh step finished (see status)"
else
    warn "SSL/TLS analysis skipped (--skip-ssl)"
fi

# -----------------------------------------------------------------------------
# 8 — Mozilla HTTP Observatory
# -----------------------------------------------------------------------------
section "8/18 — HTTP Security Headers (Mozilla Observatory)"

if [[ "${SKIP_HEADERS}" == "false" ]]; then
    info "observatory..."
    if command -v mdn-http-observatory-scan &>/dev/null; then
        mdn-http-observatory-scan "${TARGET_HOST}" \
            > "${OUT_DIR}/observatory.json" \
            2> "${OUT_DIR}/observatory_error.txt" || true
        ok "observatory done"
    else
        info "observatory CLI not found, querying MDN API..."
        curl -sf --max-time 30 \
            -X POST \
            "https://observatory-api.mdn.mozilla.net/api/v2/scan?host=${TARGET_HOST}" \
            -o "${OUT_DIR}/observatory.json" \
            2> "${OUT_DIR}/observatory_error.txt" || true
        ok "observatory done (API fallback)"
    fi
else
    warn "HTTP header analysis skipped (--skip-headers)"
fi

# -----------------------------------------------------------------------------
# 9 — Nikto
# -----------------------------------------------------------------------------
section "9/18 — Nikto"

if [[ "${SKIP_NIKTO}" == "false" ]]; then
    info "nikto — single JSON-aware run; errors are not successful findings"
    if run_logged nikto "${OUT_DIR}/nikto_console.txt" nikto -h "${TARGET_URI}" -C all -Tuning x -nointeractive \
        -Format txt -o "${OUT_DIR}/nikto.txt"; then
        ok "nikto process finished"
    else
        warn "nikto exited with an error"
    fi
    if grep -Eiq 'Error limit \([0-9]+\) reached|Scan terminated: [0-9]+ errors|giving up' "${OUT_DIR}/nikto_console.txt" "${OUT_DIR}/nikto.txt" 2>/dev/null; then
        mark_status nikto PARTIAL "Nikto stopped after reaching its HTTP error limit"
        warn "Nikto scan incomplete: error limit reached"
    fi
else
    warn "Nikto skipped (--skip-nikto)"
fi

# -----------------------------------------------------------------------------
# 10 — CMS Scanning
# -----------------------------------------------------------------------------
section "10/18 — CMS Scanning"

if [[ "${SKIP_CMS}" == "false" ]]; then
    IS_WORDPRESS=false
    IS_DRUPAL=false
    IS_JOOMLA=false

    grep -qi "wordpress" "${OUT_DIR}/httpx.txt"   2>/dev/null && IS_WORDPRESS=true
    grep -qi "wordpress" "${OUT_DIR}/whatweb.txt"  2>/dev/null && IS_WORDPRESS=true
    grep -qi "drupal"    "${OUT_DIR}/httpx.txt"   2>/dev/null && IS_DRUPAL=true
    grep -qi "drupal"    "${OUT_DIR}/whatweb.txt"  2>/dev/null && IS_DRUPAL=true
    grep -qi "joomla"    "${OUT_DIR}/httpx.txt"   2>/dev/null && IS_JOOMLA=true
    grep -qi "joomla"    "${OUT_DIR}/whatweb.txt"  2>/dev/null && IS_JOOMLA=true

    if [[ "${IS_WORDPRESS}" == "true" ]]; then
        info "WordPress detected — running WPScan..."
        WPSCAN_ARGS=(
            --url "${TARGET_URI}"
            --enumerate vp,vt,u
            --plugins-detection mixed
            --no-banner
            --format json
            --output "${OUT_DIR}/wpscan.json"
        )
        [[ -n "${WPSCAN_API_TOKEN:-}" ]] && WPSCAN_ARGS+=(--api-token "${WPSCAN_API_TOKEN}")
        wpscan "${WPSCAN_ARGS[@]}" 2>&1 | tee "${OUT_DIR}/wpscan_console.txt" || true
        wpscan --url "${TARGET_URI}" \
            --enumerate vp,vt,u \
            --plugins-detection mixed \
            --no-banner \
            ${WPSCAN_API_TOKEN:+--api-token "${WPSCAN_API_TOKEN}"} \
            --output "${OUT_DIR}/wpscan.txt" \
            2>/dev/null || true
        ok "WPScan done"
    else
        warn "WordPress not detected — skipping WPScan"
        mark_status wpscan NOT_APPLICABLE "WordPress fingerprint not detected"
    fi

    [[ "${IS_DRUPAL}" == "true" ]]  && warn "Drupal detected — covered by Nuclei templates and ZAP active scan"
    [[ "${IS_JOOMLA}" == "true" ]]  && warn "Joomla detected — covered by Nuclei templates and ZAP active scan"
    [[ "${IS_WORDPRESS}" == "false" && "${IS_DRUPAL}" == "false" && "${IS_JOOMLA}" == "false" ]] && \
        info "No known CMS detected"
else
    warn "CMS scanning skipped (--skip-cms)"
fi

# -----------------------------------------------------------------------------
# 11 — Endpoint Discovery
# -----------------------------------------------------------------------------
section "11/18 — Endpoint Discovery"

if [[ "${SKIP_CRAWL}" == "false" ]]; then
    info "katana — exact hostname scope (fqdn)..."
    # -fs fqdn restricts the crawler itself, not merely the resulting file.
    if run_logged katana "${OUT_DIR}/katana_console.txt" \
        katana -u "${TARGET_URI}" -depth 3 -js-crawl -fs fqdn \
        -o "${OUT_DIR}/endpoints-raw.txt"; then
        ok "katana process finished"
    else
        warn "katana failed or timed out"
    fi

    # Defensive second gate: downstream scanners never receive raw discoveries.
    if python3 /usr/local/lib/ronny-webscanner/scope_filter.py \
        "${TARGET_URI}" "${OUT_DIR}/endpoints-raw.txt" \
        "${OUT_DIR}/endpoints.txt" "${OUT_DIR}/endpoints-out-of-scope.txt"; then
        info "Filtered crawler output is ready for Arjun, Dalfox and SQLMap"
    else
        warn "Scope filter failed: refusing to pass raw crawler URLs downstream"
        : > "${OUT_DIR}/endpoints.txt"
        mark_status katana FAILED "Post-crawl origin filter failed"
    fi
else
    warn "Crawling skipped (--skip-crawl)"
fi

if [[ "${SKIP_BRUTE}" == "false" ]]; then
    if [[ -n "${WORDLIST}" ]]; then
        info "gobuster..."
        gobuster dir -u "${TARGET_URI}" -w "${WORDLIST}" \
            -o "${OUT_DIR}/gobuster.txt" -k --timeout 10s \
            --delay 100ms 2>&1 \
            | tee "${OUT_DIR}/gobuster_console.txt" || true
        ok "gobuster done"

        info "ffuf..."
        ffuf -u "${TARGET_URI}/FUZZ" -w "${WORDLIST}" \
            -o "${OUT_DIR}/ffuf.json" -of json \
            -mc 200,201,204,301,302,307,401,403 -timeout 10 \
            -rate 50 2>&1 \
            | tee "${OUT_DIR}/ffuf_console.txt" || true
        ok "ffuf done"
    else
        warn "No wordlist found — skipping gobuster and ffuf"
    fi
else
    warn "Brute-forcing skipped (--skip-brute)"
fi

# -----------------------------------------------------------------------------
# 12 — Arjun
# -----------------------------------------------------------------------------
section "12/18 — Arjun (Parameter Discovery)"

if [[ "${SKIP_ARJUN}" == "false" ]]; then
    info "arjun — only same-host HTML-like routes; no static bundles"
    # All paths must stay inside the original hostname, and dynamic URLs must be confirmed before testing.
    python3 - "$TARGET_URI" "${OUT_DIR}/endpoints.txt" "${OUT_DIR}/arjun_targets.txt" <<'PYARJUN'
from urllib.parse import urlsplit, urlunsplit
import sys, pathlib
base, discovered, dest=sys.argv[1:]
root=urlsplit(base)
candidates=[base]
if pathlib.Path(discovered).exists():
    candidates+=pathlib.Path(discovered).read_text(errors='replace').splitlines()
seen=set(); picked=[]
for raw in candidates:
    raw=raw.strip()
    try: u=urlsplit(raw)
    except ValueError: continue
    if u.scheme not in ('https','http') or u.hostname != root.hostname or u.port != root.port:continue
    path=u.path.lower()
    if path.endswith(('.js','.css','.json','.map','.png','.jpg','.jpeg','.gif','.svg','.ico','.woff','.woff2','.ttf','.xml','.pdf','.zip','.wasm','.txt')):continue
    normalized=urlunsplit((u.scheme,u.netloc,u.path,'',''))
    if normalized not in seen:
        seen.add(normalized);picked.append(normalized)
    if len(picked)>=10:break
pathlib.Path(dest).write_text('\n'.join(picked)+'\n')
PYARJUN
    if run_logged arjun "${OUT_DIR}/arjun_console.txt" \
        arjun -i "${OUT_DIR}/arjun_targets.txt" -oJ "${OUT_DIR}/arjun.json" -t 2; then
        ok "arjun process finished"
    else
        warn "arjun failed"
    fi
    if grep -Eiq 'Skipped .* due to errors|Encountered an error|ConnectionError|Traceback|timed out' "${OUT_DIR}/arjun_console.txt"; then
        mark_status arjun PARTIAL "One or more Arjun targets failed; check console output"
        warn "Arjun incomplete; at least one target failed"
    fi
else
    warn "Arjun skipped (--skip-arjun)"
fi

# -----------------------------------------------------------------------------
# 13 — Dalfox
# -----------------------------------------------------------------------------
section "13/18 — Dalfox (XSS Scanning)"

if [[ "${SKIP_XSS}" == "false" ]]; then
    # Dalfox is relevant to parameterized URLs. Avoid forcing a run on the Bitwarden login page.
    python3 - "$TARGET_URI" "${OUT_DIR}/endpoints.txt" "${OUT_DIR}/dalfox_targets.txt" <<'PYDALFOX'
from urllib.parse import urlsplit
from pathlib import Path
import sys
base, infile, outfile=sys.argv[1:]
root=urlsplit(base)
found=[];seen=set()
if Path(infile).exists():
    for url in Path(infile).read_text(errors='replace').splitlines():
        try: u=urlsplit(url.strip())
        except ValueError:continue
        if u.scheme in ('http','https') and u.hostname==root.hostname and u.port==root.port and u.query and url not in seen:
            found.append(url);seen.add(url)
        if len(found)>=20:break
Path(outfile).write_text('\n'.join(found)+('\n' if found else ''))
PYDALFOX
    if [[ -s "${OUT_DIR}/dalfox_targets.txt" ]]; then
        info "dalfox — parameterized URLs only"
        if run_logged dalfox "${OUT_DIR}/dalfox_console.txt" dalfox file "${OUT_DIR}/dalfox_targets.txt" \
            --silence --no-spinner --follow-redirects --output "${OUT_DIR}/dalfox.txt"; then
            ok "dalfox process finished"
        else
            warn "dalfox failed"
        fi
    else
        info "No eligible parameterized URLs for Dalfox"
        mark_status dalfox NOT_APPLICABLE "No parameterized URLs discovered within target scope"
    fi
else
    warn "XSS scanning skipped (--skip-xss)"
fi

# -----------------------------------------------------------------------------
# 14 — SQLMap
# -----------------------------------------------------------------------------
section "14/18 — SQLMap (SQL Injection)"

if [[ "${SKIP_SQLMAP}" == "false" ]]; then
    info "sqlmap — crawling target for injection points..."
    SQLMAP_ARGS=(
        -u "${TARGET_URI}"
        --crawl=2
        --forms
        --batch
        --level=2
        --risk=1
        --output-dir="${OUT_DIR}/sqlmap"
        --random-agent
        --timeout=10
        --retries=2
    )

    if [[ -s "${OUT_DIR}/endpoints.txt" ]]; then
        info "Feeding katana-discovered endpoints to sqlmap..."
        SQLMAP_ARGS+=(-m "${OUT_DIR}/endpoints.txt")
    fi

    sqlmap "${SQLMAP_ARGS[@]}" 2>&1 \
        | tee "${OUT_DIR}/sqlmap_console.txt" || true
    ok "sqlmap done"
else
    warn "sqlmap skipped (--skip-sqlmap)"
fi

# -----------------------------------------------------------------------------
# 15 — OSV-Scanner
# -----------------------------------------------------------------------------
section "15/18 — OSV-Scanner (Dependency Vulnerabilities)"

if [[ "${SKIP_OSV}" == "false" ]]; then
    info "osv-scanner — checking for exposed dependency files..."
    OSV_DIR="${OUT_DIR}/osv_scan"
    mkdir -p "${OSV_DIR}"

    if [[ -s "${OUT_DIR}/endpoints.txt" ]]; then
        while IFS= read -r url; do
            if echo "${url}" | grep -qiE \
                '(composer\.(json|lock)|package(-lock)?\.json|yarn\.lock|requirements.*\.txt|Gemfile(\.lock)?|go\.(mod|sum)|pom\.xml|Cargo\.(toml|lock)|\.csproj|packages\.config)$'; then
                SAFE_NAME=$(echo "${url}" | sed 's|[^a-zA-Z0-9._-]|_|g' | cut -c1-120)
                curl -sf --max-time 10 "${url}" \
                    -o "${OSV_DIR}/${SAFE_NAME}" 2>/dev/null && \
                    info "Downloaded: ${url}"
            fi
        done < "${OUT_DIR}/endpoints.txt"
    fi

    for dep_path in \
        composer.json composer.lock \
        package.json package-lock.json yarn.lock \
        requirements.txt requirements-dev.txt \
        Gemfile Gemfile.lock \
        go.mod go.sum \
        Cargo.toml Cargo.lock; do
        curl -sf --max-time 8 "${TARGET_URI}/${dep_path}" \
            -o "${OSV_DIR}/${dep_path}" 2>/dev/null && \
            info "Found exposed: ${dep_path}" || \
            rm -f "${OSV_DIR}/${dep_path}"
    done

    if find "${OSV_DIR}" -type f | grep -q .; then
        info "Running osv-scanner on discovered dependency files..."
        osv-scanner scan source \
            --recursive \
            --format json \
            "${OSV_DIR}" \
            > "${OUT_DIR}/osv_scanner.json" 2>&1 || true
        osv-scanner scan source \
            --recursive \
            "${OSV_DIR}" \
            > "${OUT_DIR}/osv_scanner.txt" 2>&1 || true
        ok "osv-scanner done"
    else
        warn "No exposed dependency files found — skipping osv-scanner"
    fi
else
    warn "OSV-Scanner skipped (--skip-osv)"
fi

# -----------------------------------------------------------------------------
# 16 — Nuclei
# -----------------------------------------------------------------------------
section "16/18 — Nuclei"

if [[ "${SKIP_NUCLEI}" == "false" ]]; then
    info "Nuclei with rate limit ${NUCLEI_RATE}/s, concurrency ${NUCLEI_CONCURRENCY}"
    NUCLEI_EXTRA=(-ni)
    [[ "$ALLOW_OAST" == true ]] && NUCLEI_EXTRA=()
    if run_logged nuclei "${OUT_DIR}/nuclei_console.txt" nuclei -u "${TARGET_URI}" \
        -o "${OUT_DIR}/nuclei.txt" -je "${OUT_DIR}/nuclei.json" \
        -severity "${SEVERITY}" -rl "$NUCLEI_RATE" -c "$NUCLEI_CONCURRENCY" \
        -timeout 10 -retries 1 "${NUCLEI_EXTRA[@]}" -stats; then
        ok "nuclei process finished (coverage inspected by reporting)"
    else
        warn "nuclei failed or timed out"
    fi
else
    warn "Nuclei skipped (--skip-nuclei)"
fi

# -----------------------------------------------------------------------------
# 17 — Nginx Bad Bot Blocker Validation
# -----------------------------------------------------------------------------
section "17/18 — Nginx Bad Bot Blocker Validation"

if [[ "${SKIP_BOTBLOCKER}" == "false" ]]; then
    REPO_RAW="https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists"
    BOT_REPORT="${OUT_DIR}/botblocker_test.txt"
    BLOCKED=0
    ALLOWED=0
    FP=0

    is_blocked() {
        local ua="${1:-}" ref="${2:-}"
        local http_code
        http_code=$(curl -sf \
            --max-time 8 \
            --connect-timeout 5 \
            ${ua:+-A "${ua}"} \
            ${ref:+-e "${ref}"} \
            -o /dev/null \
            -w "%{http_code}" \
            "${TARGET_URI}" 2>/dev/null) || { echo "error"; return; }
        if [[ "${http_code}" =~ ^[23][0-9][0-9]$ ]]; then
            echo "allowed"
        elif [[ "${http_code}" =~ ^(403|406|429)$ ]]; then
            echo "blocked"
        else
            echo "unverified"
        fi
    }

    info "Fetching bad user-agent list..."
    BAD_UA_LIST=$(curl -sf --max-time 15 "${REPO_RAW}/bad-user-agents.list" 2>/dev/null | \
        grep -v '^#' | grep -v '^[[:space:]]*$' | shuf | head -${SAMPLE_SIZE}) || true

    info "Fetching fake Googlebot list..."
    FAKE_GOOGLE_LIST=$(curl -sf --max-time 15 "${REPO_RAW}/fake-googlebots.list" 2>/dev/null | \
        grep -v '^#' | grep -v '^[[:space:]]*$' | shuf | head -${SAMPLE_SIZE}) || true

    info "Fetching bad referrer list..."
    BAD_REF_LIST=$(curl -sf --max-time 15 "${REPO_RAW}/bad-referrers.list" 2>/dev/null | \
        grep -v '^#' | grep -v '^[[:space:]]*$' | shuf | head -${SAMPLE_SIZE}) || true

    info "Fetching bad IP list..."
    BAD_IP_LIST=$(curl -sf --max-time 15 "${REPO_RAW}/bad-ip-addresses.list" 2>/dev/null | \
        grep -v '^#' | grep -v '^[[:space:]]*$' | grep -E '^[0-9]+\.' | shuf | head -${SAMPLE_SIZE}) || true

    info "Fetching whitelist user-agents..."
    WHITELIST_UA=$(curl -sf --max-time 15 \
        "https://raw.githubusercontent.com/kpirnie-me/bots-for-scanner/refs/heads/main/whitelist-ua.list" \
        2>/dev/null | grep -v '^#' | grep -v '^[[:space:]]*$') || true

    info "Fetching whitelist IPs..."
    WHITELIST_IP=$(curl -sf --max-time 15 \
        "https://raw.githubusercontent.com/kpirnie-me/bots-for-scanner/refs/heads/main/whitelist-ip.list" \
        2>/dev/null | grep -v '^#' | grep -v '^[[:space:]]*$' | grep -E '^[0-9]+\.') || true

    {
    echo "ngxbottest — Nginx Bad Bot Blocker Validation"
    echo "Target:  ${TARGET_URI}"
    echo "Date:    $(date)"
    echo "Samples: ${SAMPLE_SIZE} per bad-bot category | Whitelist: full coverage (no sampling)"
    echo ""

    echo "=== BAD USER-AGENTS (should be BLOCKED) ==="
    if [[ -n "${BAD_UA_LIST}" ]]; then
        while IFS= read -r ua; do
            [[ -z "${ua}" ]] && continue
            result=$(is_blocked "${ua}" "")
            if [[ "${result}" == "blocked" ]]; then
                echo "  [BLOCKED ✓] UA: ${ua}"
                (( BLOCKED++ )) || true
            else
                echo "  [ALLOWED ✗] UA: ${ua}"
                (( ALLOWED++ )) || true
            fi
        done <<< "${BAD_UA_LIST}"
    else
        echo "  [!] Could not fetch bad user-agent list"
    fi

    echo ""
    echo "=== FAKE GOOGLEBOTS (should be BLOCKED) ==="
    if [[ -n "${FAKE_GOOGLE_LIST}" ]]; then
        while IFS= read -r ua; do
            [[ -z "${ua}" ]] && continue
            result=$(is_blocked "${ua}" "")
            if [[ "${result}" == "blocked" ]]; then
                echo "  [BLOCKED ✓] UA: ${ua}"
                (( BLOCKED++ )) || true
            else
                echo "  [ALLOWED ✗] UA: ${ua}"
                (( ALLOWED++ )) || true
            fi
        done <<< "${FAKE_GOOGLE_LIST}"
    else
        echo "  [!] Could not fetch fake Googlebot list"
    fi

    echo ""
    echo "=== BAD REFERRERS (should be BLOCKED) ==="
    if [[ -n "${BAD_REF_LIST}" ]]; then
        while IFS= read -r ref; do
            [[ -z "${ref}" ]] && continue
            [[ "${ref}" != http* ]] && ref="http://${ref}"
            result=$(is_blocked "" "${ref}")
            if [[ "${result}" == "blocked" ]]; then
                echo "  [BLOCKED ✓] Ref: ${ref}"
                (( BLOCKED++ )) || true
            else
                echo "  [ALLOWED ✗] Ref: ${ref}"
                (( ALLOWED++ )) || true
            fi
        done <<< "${BAD_REF_LIST}"
    else
        echo "  [!] Could not fetch bad referrer list"
    fi

    echo ""
    echo "=== BAD IP ADDRESSES ==="
    echo "  NOT TESTED: source-IP ACLs need requests from controlled real source addresses."
    echo "  X-Forwarded-For must not be used as evidence of IP blocking."
    echo ""
    echo ""
    echo "=== WHITELISTED USER-AGENTS (should be ALLOWED — full coverage, no sampling) ==="
    WL_FP=0
    if [[ -n "${WHITELIST_UA}" ]]; then
        while IFS= read -r ua; do
            [[ -z "${ua}" ]] && continue
            result=$(is_blocked "${ua}" "")
            if [[ "${result}" == "allowed" ]]; then
                echo "  [ALLOWED ✓] ${ua}"
            else
                echo "  [BLOCKED ✗] ${ua} — FALSE POSITIVE"
                (( WL_FP++ )) || true
                (( FP++ )) || true
            fi
        done <<< "${WHITELIST_UA}"
    else
        echo "  [!] Could not fetch whitelist-ua.list — using hardcoded fallback"
        for ua in Googlebot bingbot DuckDuckBot ClaudeBot GPTBot Applebot \
                   FacebookBot PerplexityBot Amazonbot Bytespider cohere-ai; do
            result=$(is_blocked "${ua}" "")
            if [[ "${result}" == "allowed" ]]; then
                echo "  [ALLOWED ✓] ${ua}"
            else
                echo "  [BLOCKED ✗] ${ua} — FALSE POSITIVE"
                (( WL_FP++ )) || true
                (( FP++ )) || true
            fi
        done
    fi

    echo ""
    echo "=== WHITELISTED IPs ==="
    echo "  NOT TESTED: cannot validate source IP allowlist via spoofed headers."
    WL_IP_FP=0
    echo ""
    echo ""
    echo "═══════════════════════════════════════════════════"
    echo "SUMMARY"
    echo "  Correctly blocked: ${BLOCKED}"
    echo "  Not blocked:       ${ALLOWED}"
    echo "  False positives:   ${FP}"
    echo "    → Whitelisted UAs blocked: ${WL_FP}"
    echo "    → Whitelisted IPs blocked: ${WL_IP_FP}"
    TOTAL=$(( BLOCKED + ALLOWED ))
    if [[ ${TOTAL} -gt 0 ]]; then
        PCT=$(( BLOCKED * 100 / TOTAL ))
        echo "  Block rate:        ${PCT}%"
    fi
    if [[ ${ALLOWED} -gt 0 ]]; then
        echo ""
        echo "  !! ${ALLOWED} bad bots/referrers were NOT blocked."
        echo "     Check your nginx-ultimate-bad-bot-blocker configuration."
    fi
    if [[ ${FP} -gt 0 ]]; then
        echo ""
        echo "  !! ${FP} legitimate bots were blocked — investigate whitelist."
    fi
    echo "═══════════════════════════════════════════════════"

    } | tee "${BOT_REPORT}"

    ok "Bot blocker test done → ${BOT_REPORT}"
else
    warn "Bot blocker validation skipped (--skip-botblocker)"
fi

# -----------------------------------------------------------------------------
# 18 — OWASP ZAP
# -----------------------------------------------------------------------------
section "18/18 — OWASP ZAP"

if [[ "${SKIP_ZAP}" == "false" ]]; then
    info "ZAP full scan (may take several minutes)..."
    timeout 600 zap.sh -cmd \
        -quickurl "${TARGET_URI}" \
        -quickout "${OUT_DIR}/zap_report.html" \
        -quickprogress 2>&1 \
        | tee "${OUT_DIR}/zap_console.txt" && {
            printf 'zap\t0\n' >> "${SCAN_STATUS_FILE}"
        } || {
            printf 'zap\t1\n' >> "${SCAN_STATUS_FILE}"
            warn "ZAP exited non-zero or hit 10 min timeout — partial results may exist"
        }
    info "ZAP step finished (see status)"
else
    warn "ZAP skipped (--skip-zap)"
fi

# -----------------------------------------------------------------------------
# HTML Report
# -----------------------------------------------------------------------------
section "WAF Fingerprint (optional)"
if command -v wafw00f >/dev/null 2>&1; then
    timeout 60 wafw00f "${TARGET_URI}" > "${OUT_DIR}/wafw00f.txt" 2>&1 || warn "WAF fingerprint incomplete"
else
    warn "wafw00f not installed, skipping"
fi

section "Generating HTML Report"

REPORT_FILE="${OUT_DIR}/report.html"

file_content() {
    local f="$1"
    if [[ -s "${f}" ]]; then
        cat "${f}" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
    else
        echo "(no output)"
    fi
}

json_content() {
    local f="$1"
    if [[ -s "${f}" ]]; then
        jq . "${f}" 2>/dev/null | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' || file_content "${f}"
    else
        echo "(no output)"
    fi
}

OPEN_PORT_COUNT=0
[[ -s "${OUT_DIR}/ports.txt" ]] && OPEN_PORT_COUNT=$(wc -l < "${OUT_DIR}/ports.txt" | tr -d ' ')

SUBDOMAIN_COUNT=0
[[ -s "${OUT_DIR}/subdomains.txt" ]] && SUBDOMAIN_COUNT=$(wc -l < "${OUT_DIR}/subdomains.txt" | tr -d ' ')

ENDPOINT_COUNT=0
[[ -s "${OUT_DIR}/endpoints.txt" ]] && ENDPOINT_COUNT=$(wc -l < "${OUT_DIR}/endpoints.txt" | tr -d ' ')

NUCLEI_COUNT=0
[[ -s "${OUT_DIR}/nuclei.txt" ]] && NUCLEI_COUNT=$(wc -l < "${OUT_DIR}/nuclei.txt" | tr -d ' ')

NIKTO_COUNT=0
[[ -s "${OUT_DIR}/nikto.txt" ]] && NIKTO_COUNT=$(grep -c '^+' "${OUT_DIR}/nikto.txt" 2>/dev/null || echo 0)

XSS_COUNT=0
[[ -s "${OUT_DIR}/dalfox.txt" ]] && XSS_COUNT=$(grep -cE 'VULN|POC' "${OUT_DIR}/dalfox.txt" 2>/dev/null || echo 0)

SQLI_COUNT=0
[[ -s "${OUT_DIR}/sqlmap_console.txt" ]] && SQLI_COUNT=$(grep -c 'injectable' "${OUT_DIR}/sqlmap_console.txt" 2>/dev/null || echo 0)

SSL_ISSUES=0
[[ -s "${OUT_DIR}/testssl.txt" ]] && SSL_ISSUES=$(grep -cE 'WARN|CRITICAL|NOT ok' "${OUT_DIR}/testssl.txt" 2>/dev/null || echo 0)

BOT_BLOCK_RATE="N/A"
if [[ -s "${OUT_DIR}/botblocker_test.txt" ]]; then
    BOT_BLOCK_RATE=$(grep 'Block rate:' "${OUT_DIR}/botblocker_test.txt" | awk '{print $NF}' || echo "N/A")
fi

cat > "${REPORT_FILE}" <<HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ronny WebScanner — ${TARGET_HOST}</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/uikit/3.21.5/css/uikit.min.css"/>
<script src="https://cdnjs.cloudflare.com/ajax/libs/uikit/3.21.5/js/uikit.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/uikit/3.21.5/js/uikit-icons.min.js"></script>
<style>
:root { color-scheme: dark; --kp-dark:#080e18; --kp-surface:#111c2d; --kp-surface2:#17243a; --kp-border:#28364e; --kp-accent:#38bdf8; --kp-accent2:#67d7fa; --kp-text:#e6edf8; --kp-muted:#9aabc3; --kp-green:#4ade80; --kp-red:#fb7185; --kp-yellow:#facc15; --kp-orange:#fb923c; }
*{box-sizing:border-box}
html{scroll-behavior:smooth;scroll-padding-top:94px}
body{margin:0;background:radial-gradient(ellipse at 15% 0%,#16243e 0%,transparent 40%),var(--kp-dark);color:var(--kp-text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.6}
a{color:var(--kp-accent2)}a:hover{color:#b8efff}
.kp-header{position:relative;overflow:hidden;background:linear-gradient(120deg,#101a30,#14233d 65%,#0c2738);border-bottom:1px solid var(--kp-border);padding:44px max(28px,calc((100vw - 1350px)/2)) 38px}
.kp-header:after{content:"";position:absolute;right:-100px;top:-180px;width:520px;height:520px;border:1px solid #ffffff18;border-radius:50%;box-shadow:0 0 0 76px #ffffff05,0 0 0 152px #ffffff04;pointer-events:none}
.kp-header h1{color:#fff;margin:0;font-size:2.3rem;font-weight:800;letter-spacing:-.055em}.kp-header .target{color:#dcecff;font-weight:550;font-size:1.13rem;word-break:break-all;margin-top:7px}.kp-header .meta{color:var(--kp-muted);font-size:.85rem;margin-top:17px;display:flex;gap:18px;flex-wrap:wrap;align-items:center}
.brand-icon{height:52px;width:52px;display:inline-grid;place-items:center;background:#38bdf81d;border:1px solid #38bdf84f;border-radius:15px;color:#7cdeff;flex-shrink:0}.eyebrow{display:block;letter-spacing:.17em;text-transform:uppercase;font-size:.7rem;font-weight:800;color:var(--kp-accent2);margin-bottom:7px}
.kp-nav{background:#101a2cf2;backdrop-filter:blur(18px);border-bottom:1px solid var(--kp-border);position:sticky;top:0;z-index:100;overflow-x:auto;scrollbar-width:thin}.kp-nav .uk-navbar-nav{gap:3px;flex-wrap:nowrap}.kp-nav .uk-navbar-nav>li>a{color:var(--kp-muted);font-size:.78rem;padding:0 12px;min-height:55px;height:55px;white-space:nowrap;border-bottom:2px solid transparent;transition:color .18s,border .18s}.kp-nav .uk-navbar-nav>li>a:hover,.kp-nav .uk-navbar-nav>li>a:focus{color:#fff;border-bottom-color:var(--kp-accent)}
.kp-main{padding:34px 28px 72px;max-width:1400px;margin:0 auto}
.kp-card{background:linear-gradient(130deg,var(--kp-surface),#101a2b);border:1px solid var(--kp-border);border-radius:15px;margin-bottom:22px;box-shadow:0 12px 32px #00000019;overflow:hidden}.kp-card-header{padding:18px 22px;border-bottom:1px solid var(--kp-border);display:flex;align-items:center;gap:11px}.kp-card-header h3{margin:0;font-size:1rem;font-weight:700;color:#f2f7ff;letter-spacing:-.01em}.kp-card-header [uk-icon]{color:var(--kp-accent2)!important}.kp-card-header .step-badge{margin-left:auto;background:#38bdf81c;color:#94e6ff;border:1px solid #38bdf83c;font-size:.7rem;font-weight:700;padding:3px 10px;border-radius:99px;white-space:nowrap}.kp-card-body{padding:21px 23px}
pre.kp-pre{background:#080f1e;border:1px solid #253149;border-radius:10px;padding:17px 19px;font:12px/1.7 ui-monospace,SFMono-Regular,Consolas,monospace;color:#d5e4f8;white-space:pre-wrap;overflow-wrap:anywhere;max-height:480px;overflow:auto;margin:0;tab-size:2}
.stat-card{position:relative;min-height:138px;background:linear-gradient(155deg,#18253b,#111b2c);border:1px solid var(--kp-border);border-radius:13px;padding:19px 18px;overflow:hidden;transition:transform .15s,border-color .15s}.stat-card:hover{transform:translateY(-2px);border-color:#47718a}.stat-card .stat-num{font-size:2.15rem;font-weight:800;letter-spacing:-.05em;line-height:1.1;margin:14px 0 6px}.stat-card .stat-label{font-size:.72rem;color:#afbed0;text-transform:uppercase;letter-spacing:.095em;font-weight:700}.stat-card .stat-icon{position:absolute;right:18px;top:16px;color:#8baccb;opacity:.85}.stat-green{color:var(--kp-green)}.stat-red{color:var(--kp-red)}.stat-yellow{color:var(--kp-yellow)}.stat-blue{color:var(--kp-accent2)}.stat-orange{color:var(--kp-orange)}
.kp-summary-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:18px;flex-wrap:wrap}.kp-summary-head h2{color:#f3f8ff!important;margin:0!important;font-size:1.13rem!important;font-weight:750}.kp-summary-note{font-size:.76rem;color:var(--kp-muted)}
.skipped-badge{display:inline-flex;align-items:center;gap:7px;background:#2a2a2a66;border:1px solid #5c647180;color:#b9c3d2;border-radius:8px;padding:9px 13px;font-size:.83rem}
.uk-accordion-title{color:#d8e9fc!important;background:transparent!important;font-size:.91rem;font-weight:600}.uk-accordion-title::before{filter:brightness(1.5)}.uk-open>.uk-accordion-title{color:var(--kp-accent2)!important}.uk-accordion>li{border:1px solid var(--kp-border);padding:14px 16px;border-radius:10px;margin-top:10px}.uk-accordion-content{margin-top:14px}
details>summary{padding:11px 0;cursor:pointer}footer{border-top:1px solid var(--kp-border);padding:26px;text-align:center;color:var(--kp-muted);font-size:.8rem}
@media(max-width:768px){.kp-header{padding:30px 20px}.kp-header h1{font-size:1.9rem}.kp-main{padding:20px 15px 54px}.kp-card-body{padding:16px}.kp-card-header{padding:15px}.stat-card{min-height:118px;padding:14px}.kp-nav .uk-navbar-nav>li>a{padding:0 9px}}
@media print{body{background:#fff;color:#111}.kp-nav{display:none}.kp-header{background:#eaf3fc;color:#111}.kp-card,.stat-card{box-shadow:none;break-inside:avoid}pre.kp-pre{max-height:initial;color:#111;background:#f7f9fc}.kp-card-header h3{color:#111}}
</style>
</head>
<body>

<div class="kp-header">
  <div style="display:flex;align-items:center;gap:17px;position:relative;z-index:1;">
    <div class="brand-icon"><span uk-icon="icon:shield;ratio:1.6"></span></div>
    <div><span class="eyebrow">SECURITY ASSESSMENT / ${VER}</span><h1>Ronny WebScanner</h1></div>
  </div>
  <div class="target" style="position:relative;z-index:1">${TARGET_URI}</div>
  <div class="meta" style="position:relative;z-index:1">
    <span><span uk-icon="icon:calendar;ratio:0.8"></span> ${TIMESTAMP}</span>
    <span><span uk-icon="icon:server;ratio:0.8"></span> ${TARGET_HOST}</span>
    <span><span uk-icon="icon:tag;ratio:0.8"></span> ${SEVERITY}</span>
    <span><span uk-icon="icon:file-text;ratio:0.8"></span> 18 scan stages</span>
  </div>
</div>

<div class="kp-nav">
  <nav class="uk-navbar-container uk-navbar" uk-navbar style="background:transparent;">
    <div class="uk-navbar-left" style="padding-left:20px;">
      <ul class="uk-navbar-nav">
        <li><a href="#summary"><span uk-icon="icon:thumbnails;ratio:0.8"></span> Summary</a></li>
        <li><a href="#fingerprint"><span uk-icon="icon:search;ratio:0.8"></span> Fingerprint</a></li>
        <li><a href="#recon"><span uk-icon="icon:world;ratio:0.8"></span> Recon</a></li>
        <li><a href="#ports"><span uk-icon="icon:server;ratio:0.8"></span> Ports</a></li>
        <li><a href="#ssl"><span uk-icon="icon:lock;ratio:0.8"></span> SSL/TLS</a></li>
        <li><a href="#headers"><span uk-icon="icon:settings;ratio:0.8"></span> Headers</a></li>
        <li><a href="#cms"><span uk-icon="icon:social;ratio:0.8"></span> CMS</a></li>
        <li><a href="#endpoints"><span uk-icon="icon:link;ratio:0.8"></span> Endpoints</a></li>
        <li><a href="#vulns"><span uk-icon="icon:warning;ratio:0.8"></span> Vulns</a></li>
        <li><a href="#bots"><span uk-icon="icon:ban;ratio:0.8"></span> Bot Blocker</a></li>
        <li><a href="#zap"><span uk-icon="icon:bolt;ratio:0.8"></span> ZAP</a></li>
      </ul>
    </div>
  </nav>
</div>

<div class="kp-main">

<div id="summary" style="margin-bottom:32px;">
 <div class="kp-summary-head"><h2><span uk-icon="icon:thumbnails"></span> Assessment overview</h2><span class="kp-summary-note">Counts reflect generated output; check stage details for skipped or incomplete tests.</span></div>
 <div class="uk-grid-small uk-child-width-1-4@m uk-child-width-1-2@s" uk-grid>
   <div><div class="stat-card"><span class="stat-icon" uk-icon="icon:server;ratio:1.25"></span><div class="stat-num stat-blue">${OPEN_PORT_COUNT}</div><div class="stat-label">Open ports</div></div></div>
   <div><div class="stat-card"><span class="stat-icon" uk-icon="icon:world;ratio:1.25"></span><div class="stat-num stat-blue">${SUBDOMAIN_COUNT}</div><div class="stat-label">Subdomains</div></div></div>
   <div><div class="stat-card"><span class="stat-icon" uk-icon="icon:link;ratio:1.25"></span><div class="stat-num stat-blue">${ENDPOINT_COUNT}</div><div class="stat-label">Endpoints</div></div></div>
   <div><div class="stat-card"><span class="stat-icon" uk-icon="icon:shield;ratio:1.25"></span><div class="stat-num stat-yellow">${NUCLEI_COUNT}</div><div class="stat-label">Nuclei matches</div></div></div>
   <div><div class="stat-card"><span class="stat-icon" uk-icon="icon:warning;ratio:1.25"></span><div class="stat-num stat-orange">${NIKTO_COUNT}</div><div class="stat-label">Nikto lines</div></div></div>
   <div><div class="stat-card"><span class="stat-icon" uk-icon="icon:code;ratio:1.25"></span><div class="stat-num stat-red">${XSS_COUNT}</div><div class="stat-label">XSS matches</div></div></div>
   <div><div class="stat-card"><span class="stat-icon" uk-icon="icon:database;ratio:1.25"></span><div class="stat-num stat-red">${SQLI_COUNT}</div><div class="stat-label">SQLi matches</div></div></div>
   <div><div class="stat-card"><span class="stat-icon" uk-icon="icon:lock;ratio:1.25"></span><div class="stat-num stat-yellow">${SSL_ISSUES}</div><div class="stat-label">TLS warnings</div></div></div>
 </div>
</div>

HTMLEOF

# ── 1: Fingerprinting ──────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="fingerprint" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:search" style="color:var(--kp-accent2)"></span>
    <h3>Fingerprinting</h3><span class="step-badge">1/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_FINGERPRINT}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-fingerprint)</div>' >> "${REPORT_FILE}"
else
    cat >> "${REPORT_FILE}" <<HTMLEOF
    <ul uk-accordion>
      <li><a class="uk-accordion-title" href="#">WhatWeb</a><div class="uk-accordion-content"><pre class="kp-pre">$(file_content "${OUT_DIR}/whatweb.txt")</pre></div></li>
      <li><a class="uk-accordion-title" href="#">httpx</a><div class="uk-accordion-content"><pre class="kp-pre">$(file_content "${OUT_DIR}/httpx.txt")</pre></div></li>
    </ul>
HTMLEOF
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 2: Passive Recon ───────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="recon" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:world" style="color:var(--kp-accent2)"></span>
    <h3>Passive Recon</h3><span class="step-badge">2/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_RECON}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-recon)</div>' >> "${REPORT_FILE}"
else
    cat >> "${REPORT_FILE}" <<HTMLEOF
    <ul uk-accordion>
      <li><a class="uk-accordion-title" href="#">Shodan</a><div class="uk-accordion-content"><pre class="kp-pre">$(file_content "${OUT_DIR}/shodan.txt")</pre></div></li>
      <li><a class="uk-accordion-title" href="#">Censys</a><div class="uk-accordion-content"><pre class="kp-pre">$(file_content "${OUT_DIR}/censys.txt")</pre></div></li>
    </ul>
HTMLEOF
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 3: Subdomains ──────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="subdomains" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:git-branch" style="color:var(--kp-accent2)"></span>
    <h3>Subdomain Enumeration</h3><span class="step-badge">3/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_SUBDOMAINS}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-subdomains)</div>' >> "${REPORT_FILE}"
else
    cat >> "${REPORT_FILE}" <<HTMLEOF
    <ul uk-accordion>
      <li><a class="uk-accordion-title" href="#">Subdomains (${SUBDOMAIN_COUNT} found)</a><div class="uk-accordion-content"><pre class="kp-pre">$(file_content "${OUT_DIR}/subdomains.txt")</pre></div></li>
      <li><a class="uk-accordion-title" href="#">Live Subdomains</a><div class="uk-accordion-content"><pre class="kp-pre">$(file_content "${OUT_DIR}/subdomains_live.txt")</pre></div></li>
    </ul>
HTMLEOF
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 4: DNS ─────────────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="dns" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:database" style="color:var(--kp-accent2)"></span>
    <h3>DNS Enumeration</h3><span class="step-badge">4/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_DNS}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-dns)</div>' >> "${REPORT_FILE}"
else
    echo '<pre class="kp-pre">'"$(file_content "${OUT_DIR}/dns.txt")"'</pre>' >> "${REPORT_FILE}"
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 5+6: Ports ─────────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="ports" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:server" style="color:var(--kp-accent2)"></span>
    <h3>Port &amp; Service Scanning</h3><span class="step-badge">5–6/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_PORTS}" == "true" && "${SKIP_NMAP}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-ports --skip-nmap)</div>' >> "${REPORT_FILE}"
else
    echo '<ul uk-accordion>' >> "${REPORT_FILE}"
    [[ "${SKIP_PORTS}" == "false" ]] && echo '<li><a class="uk-accordion-title" href="#">naabu — Open Ports ('"${OPEN_PORT_COUNT}"' found)</a><div class="uk-accordion-content"><pre class="kp-pre">'"$(file_content "${OUT_DIR}/ports.txt")"'</pre></div></li>' >> "${REPORT_FILE}"
    [[ "${SKIP_NMAP}" == "false" ]]  && echo '<li><a class="uk-accordion-title" href="#">Nmap — Service &amp; Script Scan</a><div class="uk-accordion-content"><pre class="kp-pre">'"$(file_content "${OUT_DIR}/nmap.txt")"'</pre></div></li>' >> "${REPORT_FILE}"
    echo '</ul>' >> "${REPORT_FILE}"
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 7: SSL ─────────────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="ssl" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:lock" style="color:var(--kp-accent2)"></span>
    <h3>SSL/TLS Analysis</h3><span class="step-badge">7/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_SSL}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-ssl)</div>' >> "${REPORT_FILE}"
else
    if [[ -s "${OUT_DIR}/testssl.txt" ]]; then
        ISSUES=$(grep -E 'WARN|CRITICAL|NOT ok' "${OUT_DIR}/testssl.txt" 2>/dev/null | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' || true)
        if [[ -n "${ISSUES}" ]]; then
            echo "<p style='color:var(--kp-yellow);margin-bottom:10px;'><span uk-icon='icon:warning'></span> ${SSL_ISSUES} issue(s) found</p><pre class='kp-pre'>${ISSUES}</pre>" >> "${REPORT_FILE}"
        else
            echo "<p style='color:var(--kp-green);'><span uk-icon='icon:check'></span> No WARN/CRITICAL issues found</p>" >> "${REPORT_FILE}"
        fi
        echo '<details style="margin-top:12px;"><summary style="cursor:pointer;color:var(--kp-muted);font-size:0.85rem;">Full testssl.sh output</summary><pre class="kp-pre" style="margin-top:8px;">'"$(file_content "${OUT_DIR}/testssl.txt")"'</pre></details>' >> "${REPORT_FILE}"
    else
        echo '<pre class="kp-pre">(no output)</pre>' >> "${REPORT_FILE}"
    fi
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 8: Headers ─────────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="headers" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:settings" style="color:var(--kp-accent2)"></span>
    <h3>HTTP Security Headers</h3><span class="step-badge">8/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_HEADERS}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-headers)</div>' >> "${REPORT_FILE}"
else
    echo '<pre class="kp-pre">'"$(json_content "${OUT_DIR}/observatory.json")"'</pre>' >> "${REPORT_FILE}"
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 9: Nikto ───────────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="nikto" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:warning" style="color:var(--kp-accent2)"></span>
    <h3>Nikto Web Server Scan</h3><span class="step-badge">9/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_NIKTO}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-nikto)</div>' >> "${REPORT_FILE}"
else
    if [[ -s "${OUT_DIR}/nikto.txt" ]]; then
        NIKTO_FINDINGS=$(grep '^+' "${OUT_DIR}/nikto.txt" 2>/dev/null | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' || true)
        if [[ -n "${NIKTO_FINDINGS}" ]]; then
            echo "<p style='color:var(--kp-yellow);margin-bottom:10px;'><span uk-icon='icon:warning'></span> ${NIKTO_COUNT} finding(s)</p><pre class='kp-pre'>${NIKTO_FINDINGS}</pre>" >> "${REPORT_FILE}"
        else
            echo "<p style='color:var(--kp-green);'><span uk-icon='icon:check'></span> No findings</p>" >> "${REPORT_FILE}"
        fi
    else
        echo '<pre class="kp-pre">(no output)</pre>' >> "${REPORT_FILE}"
    fi
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 10: CMS ────────────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="cms" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:social" style="color:var(--kp-accent2)"></span>
    <h3>CMS Scanning</h3><span class="step-badge">10/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_CMS}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-cms)</div>' >> "${REPORT_FILE}"
else
    cat >> "${REPORT_FILE}" <<HTMLEOF
    <ul uk-accordion>
      <li><a class="uk-accordion-title" href="#">WPScan Results</a><div class="uk-accordion-content"><pre class="kp-pre">$(file_content "${OUT_DIR}/wpscan.txt")</pre></div></li>
    </ul>
HTMLEOF
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 11: Endpoints ──────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="endpoints" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:link" style="color:var(--kp-accent2)"></span>
    <h3>Endpoint Discovery</h3><span class="step-badge">11/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_CRAWL}" == "true" && "${SKIP_BRUTE}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-crawl --skip-brute)</div>' >> "${REPORT_FILE}"
else
    echo '<ul uk-accordion>' >> "${REPORT_FILE}"
    [[ "${SKIP_CRAWL}" == "false" ]] && echo '<li><a class="uk-accordion-title" href="#">katana — Crawled Endpoints ('"${ENDPOINT_COUNT}"')</a><div class="uk-accordion-content"><pre class="kp-pre">'"$(file_content "${OUT_DIR}/endpoints.txt")"'</pre></div></li>' >> "${REPORT_FILE}"
    [[ "${SKIP_BRUTE}" == "false" ]] && {
        echo '<li><a class="uk-accordion-title" href="#">gobuster</a><div class="uk-accordion-content"><pre class="kp-pre">'"$(file_content "${OUT_DIR}/gobuster.txt")"'</pre></div></li>' >> "${REPORT_FILE}"
        echo '<li><a class="uk-accordion-title" href="#">ffuf</a><div class="uk-accordion-content"><pre class="kp-pre">'"$(json_content "${OUT_DIR}/ffuf.json")"'</pre></div></li>' >> "${REPORT_FILE}"
    }
    echo '</ul>' >> "${REPORT_FILE}"
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 12: Arjun ──────────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="arjun" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:code" style="color:var(--kp-accent2)"></span>
    <h3>Parameter Discovery</h3><span class="step-badge">12/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_ARJUN}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-arjun)</div>' >> "${REPORT_FILE}"
else
    echo '<pre class="kp-pre">'"$(json_content "${OUT_DIR}/arjun.json")"'</pre>' >> "${REPORT_FILE}"
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 13-16: Vulns ───────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="vulns" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:warning" style="color:var(--kp-accent2)"></span>
    <h3>Vulnerability Findings</h3><span class="step-badge">13–16/18</span>
  </div>
  <div class="kp-card-body">
    <ul uk-accordion>
HTMLEOF

if [[ "${SKIP_XSS}" == "true" ]]; then
    echo '<li><a class="uk-accordion-title" href="#">Dalfox XSS</a><div class="uk-accordion-content"><div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-xss)</div></div></li>' >> "${REPORT_FILE}"
else
    echo '<li class="uk-open"><a class="uk-accordion-title" href="#">Dalfox XSS ('"${XSS_COUNT}"' findings)</a><div class="uk-accordion-content"><pre class="kp-pre">'"$(file_content "${OUT_DIR}/dalfox.txt")"'</pre></div></li>' >> "${REPORT_FILE}"
fi

if [[ "${SKIP_SQLMAP}" == "true" ]]; then
    echo '<li><a class="uk-accordion-title" href="#">SQLMap</a><div class="uk-accordion-content"><div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-sqlmap)</div></div></li>' >> "${REPORT_FILE}"
else
    echo '<li><a class="uk-accordion-title" href="#">SQLMap ('"${SQLI_COUNT}"' injectable)</a><div class="uk-accordion-content"><pre class="kp-pre">'"$(file_content "${OUT_DIR}/sqlmap_console.txt")"'</pre></div></li>' >> "${REPORT_FILE}"
fi

if [[ "${SKIP_OSV}" == "true" ]]; then
    echo '<li><a class="uk-accordion-title" href="#">OSV-Scanner</a><div class="uk-accordion-content"><div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-osv)</div></div></li>' >> "${REPORT_FILE}"
else
    echo '<li><a class="uk-accordion-title" href="#">OSV-Scanner (Dependency Vulnerabilities)</a><div class="uk-accordion-content"><pre class="kp-pre">'"$(file_content "${OUT_DIR}/osv_scanner.txt")"'</pre></div></li>' >> "${REPORT_FILE}"
fi

if [[ "${SKIP_NUCLEI}" == "true" ]]; then
    echo '<li><a class="uk-accordion-title" href="#">Nuclei</a><div class="uk-accordion-content"><div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-nuclei)</div></div></li>' >> "${REPORT_FILE}"
else
    echo '<li><a class="uk-accordion-title" href="#">Nuclei ('"${NUCLEI_COUNT}"' findings)</a><div class="uk-accordion-content"><pre class="kp-pre">'"$(file_content "${OUT_DIR}/nuclei.txt")"'</pre></div></li>' >> "${REPORT_FILE}"
fi

echo '    </ul>' >> "${REPORT_FILE}"
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 17: Bot Blocker ────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="bots" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:ban" style="color:var(--kp-accent2)"></span>
    <h3>Nginx Bad Bot Blocker Validation</h3><span class="step-badge">17/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_BOTBLOCKER}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-botblocker)</div>' >> "${REPORT_FILE}"
else
    if [[ -s "${OUT_DIR}/botblocker_test.txt" ]]; then
        SUMMARY_BLOCK=$(grep -A 10 '^SUMMARY' "${OUT_DIR}/botblocker_test.txt" 2>/dev/null | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' || true)
        echo "<p style='margin-bottom:12px;'><span uk-icon='icon:check-circle'></span> Block rate: <strong style='color:var(--kp-green);'>${BOT_BLOCK_RATE}</strong></p><pre class='kp-pre'>${SUMMARY_BLOCK}</pre>" >> "${REPORT_FILE}"
        echo '<details style="margin-top:12px;"><summary style="cursor:pointer;color:var(--kp-muted);font-size:0.85rem;">Full bot blocker test output</summary><pre class="kp-pre" style="margin-top:8px;">'"$(file_content "${OUT_DIR}/botblocker_test.txt")"'</pre></details>' >> "${REPORT_FILE}"
    else
        echo '<pre class="kp-pre">(no output)</pre>' >> "${REPORT_FILE}"
    fi
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 18: ZAP ────────────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="zap" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:bolt" style="color:var(--kp-accent2)"></span>
    <h3>OWASP ZAP Active Scan</h3><span class="step-badge">18/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_ZAP}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-zap)</div>' >> "${REPORT_FILE}"
else
    if [[ -s "${OUT_DIR}/zap_report.html" ]]; then
        echo '<p><a href="zap_report.html" class="uk-button" style="background:var(--kp-accent);color:#fff;border:none;padding:8px 18px;border-radius:4px;" target="_blank"><span uk-icon="icon:bolt"></span> Open Full ZAP Report</a></p><p style="color:var(--kp-muted);font-size:0.85rem;margin-top:8px;">ZAP produces a standalone HTML report. Click above to open it.</p>' >> "${REPORT_FILE}"
    else
        echo '<pre class="kp-pre">(no output — ZAP may have timed out or failed)</pre>' >> "${REPORT_FILE}"
    fi
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── Close ──────────────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
</div>

<footer>
  Ronny WebScanner · Based on <a href="https://github.com/kpirnie/webscanner" target="_blank" rel="noopener noreferrer">KP WebScanner by Kevin Pirnie</a> · MIT licensed
  
  &nbsp;·&nbsp; ${TIMESTAMP}
</footer>
</body>
</html>
HTMLEOF

ok "HTML report → ${REPORT_FILE}"

# -----------------------------------------------------------------------------
# Final Summary
# -----------------------------------------------------------------------------
section "Complete — $(date)"

FILES=(
    whatweb.txt httpx.txt shodan.txt censys.txt
    subdomains.txt subdomains_live.txt
    dns.txt ports.txt nmap.txt nmap.xml
    testssl.txt testssl.json
    observatory.json
    nikto.txt nikto.json
    wpscan.txt wpscan.json
    endpoints.txt gobuster.txt ffuf.json
    arjun.json dalfox.txt
    sqlmap_console.txt
    osv_scanner.txt osv_scanner.json
    botblocker_test.txt
    nuclei.txt nuclei.json
    zap_report.html
    report.html
)

if [[ -n "${OUTPUT_PATH}" ]]; then
    echo -e "\n${BOLD}Results: ${OUT_DIR}${RESET}"
    for f in "${FILES[@]}"; do
        fp="${OUT_DIR}/${f}"
        if [[ -f "${fp}" && -s "${fp}" ]]; then
            SIZE=$(du -sh "${fp}" | cut -f1)
            echo -e "  ${GREEN}✓${RESET} ${f} ${CYAN}(${SIZE})${RESET}"
        fi
    done
    if [[ -d "${OUT_DIR}/sqlmap" ]]; then
        echo -e "  ${GREEN}✓${RESET} sqlmap/ ${CYAN}(dir)${RESET}"
    fi
    echo -e "\n  ${BOLD}${GREEN}→ Open report.html for full results${RESET}"
else
    [[ -s "${OUT_DIR}/shodan.txt" ]]          && { echo -e "\n${BOLD}── Shodan ───────────${RESET}"; cat "${OUT_DIR}/shodan.txt"; }
    [[ -s "${OUT_DIR}/censys.txt" ]]          && { echo -e "\n${BOLD}── Censys ───────────${RESET}"; cat "${OUT_DIR}/censys.txt"; }
    [[ -s "${OUT_DIR}/httpx.txt" ]]           && { echo -e "\n${BOLD}── Fingerprint ──────${RESET}"; cat "${OUT_DIR}/httpx.txt"; }
    [[ -s "${OUT_DIR}/ports.txt" ]]           && { echo -e "\n${BOLD}── Open Ports ───────${RESET}"; cat "${OUT_DIR}/ports.txt"; }
    [[ -s "${OUT_DIR}/nmap.txt" ]]            && { echo -e "\n${BOLD}── Nmap Services ────${RESET}"; grep -E "^[0-9]+/|SCRIPT OUTPUT|^Host" "${OUT_DIR}/nmap.txt" | head -50 || true; }
    [[ -s "${OUT_DIR}/testssl.txt" ]]         && { echo -e "\n${BOLD}── SSL Issues ───────${RESET}"; grep -E "WARN|CRITICAL|NOT ok" "${OUT_DIR}/testssl.txt" || echo "  None"; }
    [[ -s "${OUT_DIR}/observatory.json" ]]    && { echo -e "\n${BOLD}── HTTP Headers ─────${RESET}"; jq -r '.scan | "Grade: \(.grade) | Score: \(.score)"' "${OUT_DIR}/observatory.json" 2>/dev/null || cat "${OUT_DIR}/observatory.json"; }
    [[ -s "${OUT_DIR}/nikto.txt" ]]           && { echo -e "\n${BOLD}── Nikto ────────────${RESET}"; grep "^+" "${OUT_DIR}/nikto.txt" || echo "  None"; }
    [[ -s "${OUT_DIR}/wpscan.txt" ]]          && { echo -e "\n${BOLD}── WPScan ───────────${RESET}"; grep -E "\[!\]|\[\+\]" "${OUT_DIR}/wpscan.txt" || echo "  None"; }
    [[ -s "${OUT_DIR}/arjun.json" ]]          && { echo -e "\n${BOLD}── Arjun Params ─────${RESET}"; jq -r '.[] | .url + " → " + (.params | join(", "))' "${OUT_DIR}/arjun.json" 2>/dev/null || cat "${OUT_DIR}/arjun.json"; }
    [[ -s "${OUT_DIR}/dalfox.txt" ]]          && { echo -e "\n${BOLD}── Dalfox XSS ───────${RESET}"; grep -E "VULN|WEAK|POC" "${OUT_DIR}/dalfox.txt" || echo "  None found"; }
    [[ -s "${OUT_DIR}/sqlmap_console.txt" ]]  && { echo -e "\n${BOLD}── SQLMap ───────────${RESET}"; grep -E "injectable|Parameter|Type:" "${OUT_DIR}/sqlmap_console.txt" || echo "  None found"; }
    [[ -s "${OUT_DIR}/osv_scanner.txt" ]]     && { echo -e "\n${BOLD}── OSV Dependencies ─${RESET}"; grep -E "CRITICAL|HIGH|MEDIUM" "${OUT_DIR}/osv_scanner.txt" || echo "  None found"; }
    [[ -s "${OUT_DIR}/botblocker_test.txt" ]] && { echo -e "\n${BOLD}── Bot Blocker ──────${RESET}"; grep -E "SUMMARY|blocked:|positives:|rate:" "${OUT_DIR}/botblocker_test.txt" || true; }
    [[ -s "${OUT_DIR}/nuclei.txt" ]]          && { echo -e "\n${BOLD}── Nuclei ───────────${RESET}"; cat "${OUT_DIR}/nuclei.txt"; }
    [[ -s "${OUT_DIR}/gobuster.txt" ]]        && { echo -e "\n${BOLD}── Paths ────────────${RESET}"; head -50 "${OUT_DIR}/gobuster.txt"; }
fi
# Offline evidence dashboard. Keep original UIkit report available as legacy report.
if [[ -f /usr/local/lib/ronny-webscanner/reporting/generate.py ]]; then
    cp "${OUT_DIR}/report.html" "${OUT_DIR}/report-legacy.html"
    PREVIOUS_ARGS=()
    [[ -n "${PREVIOUS_DIR}" ]] && PREVIOUS_ARGS=(--previous "${PREVIOUS_DIR}")
    python3 /usr/local/lib/ronny-webscanner/reporting/generate.py \
        --out "${OUT_DIR}" --target "${TARGET_URI}" --profile "${PROFILE}" \
        --version "${VER}" \
        "${PREVIOUS_ARGS[@]}" \
        $(for flag in FINGERPRINT RECON SUBDOMAINS DNS PORTS NMAP SSL HEADERS NIKTO CMS CRAWL BRUTE ARJUN XSS SQLMAP OSV NUCLEI BOTBLOCKER ZAP; do
            var="SKIP_${flag}"; [[ "${!var}" == true ]] && printf ' --skipped %s' "${flag,,}"
        done) \
        || warn "Offline report generation failed; report-legacy.html remains"
fi
