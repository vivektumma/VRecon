#!/usr/bin/env bash
#
# recon_pipeline.sh - Domain Recon Orchestrator
# Author: <your_name> (Vivek Cyber Defense LLC)
# Description:
#   For authorized targets only.
#   1) Subdomain enumeration (subfinder, assetfinder, amass, shosubgo)
#   2) Port scanning with naabu
#   3) HTTP probing + status codes + tech with httpx
#   4) Optional nuclei scan
#   5) Crawl + endpoint discovery with katana + gau
#
# Usage:
#   ./recon_pipeline.sh example.com
#   ./recon_pipeline.sh example.com output_dir
#
# Requirements (CLI tools installed and in PATH):
#   subfinder, assetfinder, amass, naabu, httpx, katana, gau, nuclei (optional), shosubgo (optional)
#
# NOTE: Only use on systems/domains you own OR have explicit permission to test.

set -euo pipefail

DOMAIN="${1:-}"
OUTDIR="${2:-recon_$DOMAIN}"

if [[ -z "$DOMAIN" ]]; then
  echo "Usage: $0 <domain> [output_dir]"
  exit 1
fi

mkdir -p "$OUTDIR"

log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

# -----------------------------------
# 1) Subdomain Enumeration
# -----------------------------------
run_subdomain_enum() {
  log "=== Subdomain Enumeration for $DOMAIN ==="

  local subfinder_file="$OUTDIR/subfinder.txt"
  local assetfinder_file="$OUTDIR/assetfinder.txt"
  local amass_file="$OUTDIR/amass.txt"
  local shosubgo_file="$OUTDIR/shosubgo.txt"
  local all_subs="$OUTDIR/all_subdomains.txt"

  # subfinder
  if have subfinder; then
    log "[subfinder] Running..."
    subfinder -d "$DOMAIN" -silent -all -o "$subfinder_file" || true
  else
    log "[subfinder] Not found, skipping."
  fi

  # assetfinder
  if have assetfinder; then
    log "[assetfinder] Running..."
    assetfinder --subs-only "$DOMAIN" | sort -u > "$assetfinder_file" || true
  else
    log "[assetfinder] Not found, skipping."
  fi

  # amass (passive to avoid noisy active scans by default)
  if have amass; then
    log "[amass] Running passive enum..."
    amass enum -passive -d "$DOMAIN" -o "$amass_file" || true
  else
    log "[amass] Not found, skipping."
  fi

  # shosubgo (Shodan subdomain helper – requires API key config on your side)
  if have shosubgo; then
    log "[shosubgo] Running..."
    # Example; adjust flags/API key handling as per your setup
    shosubgo -d "$DOMAIN" -o "$shosubgo_file" || true
  else
    log "[shosubgo] Not found, skipping."
  fi

  log "[combine] Merging and deduplicating subdomains..."
  cat \
    "$subfinder_file" \
    "$assetfinder_file" \
    "$amass_file" \
    "$shosubgo_file" 2>/dev/null \
    | sed '/^$/d' \
    | sort -u > "$all_subs" || true

  if [[ ! -s "$all_subs" ]]; then
    log "[!] No subdomains found. Check tools/scopes."
  else
    log "[+] Total unique subdomains: $(wc -l < "$all_subs") (saved to $all_subs)"
  fi
}

# -----------------------------------
# 2) Port Scanning with naabu
# -----------------------------------
run_naabu_scan() {
  local all_subs="$OUTDIR/all_subdomains.txt"
  local naabu_out="$OUTDIR/naabu_ports.txt"

  if [[ ! -s "$all_subs" ]]; then
    log "[naabu] No subdomains file found or empty. Skipping naabu."
    return
  fi

  if ! have naabu; then
    log "[naabu] Not found, skipping."
    return
  fi

  log "=== Port Scanning (naabu) for $DOMAIN ==="
  # top 1000 ports; adjust rate/timeouts if needed
  naabu -list "$all_subs" -top-ports 1000 -rate 1000 -timeout 1000 -o "$naabu_out" || true

  if [[ -s "$naabu_out" ]]; then
    log "[+] naabu results saved to $naabu_out (lines: $(wc -l < "$naabu_out"))"
  else
    log "[naabu] No open ports detected or scan failed."
  fi
}

# -----------------------------------
# 3) HTTP Probing with httpx
# -----------------------------------
run_httpx() {
  local all_subs="$OUTDIR/all_subdomains.txt"
  local httpx_out="$OUTDIR/httpx_results.txt"
  local httpx_urls="$OUTDIR/httpx_urls.txt"

  if [[ ! -s "$all_subs" ]]; then
    log "[httpx] No subdomains file found or empty. Skipping httpx."
    return
  fi

  if ! have httpx; then
    log "[httpx] Not found, skipping."
    return
  fi

  log "=== HTTP Probing (httpx) for $DOMAIN ==="
  # -status-code, -title, -tech-detect give good recon output
  httpx -l "$all_subs" \
        -ports 80,443,8080,8443 \
        -follow-redirects \
        -status-code \
        -title \
        -tech-detect \
        -silent \
        -o "$httpx_out" || true

  if [[ -s "$httpx_out" ]]; then
    log "[+] httpx results saved to $httpx_out"

    # Extract just URLs from httpx output (first column)
    awk '{print $1}' "$httpx_out" | sort -u > "$httpx_urls"
    log "[+] Live URLs saved to $httpx_urls (lines: $(wc -l < "$httpx_urls"))"
  else
    log "[httpx] No live HTTP services detected (or command failed)."
  fi
}

# -----------------------------------
# 4) Optional Nuclei Scan
# -----------------------------------
run_nuclei() {
  local httpx_urls="$OUTDIR/httpx_urls.txt"
  local nuclei_out="$OUTDIR/nuclei_findings.txt"

  if [[ ! -s "$httpx_urls" ]]; then
    log "[nuclei] No URLs file found or empty. Skipping nuclei."
    return
  fi

  if ! have nuclei; then
    log "[nuclei] Not found, skipping."
    return
  fi

  log "=== Nuclei Scan (optional) for $DOMAIN ==="
  nuclei -l "$httpx_urls" \
         -severity medium,high,critical \
         -o "$nuclei_out" || true

  if [[ -s "$nuclei_out" ]]; then
    log "[+] nuclei findings saved to $nuclei_out"
  else
    log "[nuclei] No findings or scan failed."
  fi
}

# -----------------------------------
# 5) Crawl & Endpoint Discovery (katana + gau)
# -----------------------------------
run_crawl_and_endpoints() {
  local httpx_urls="$OUTDIR/httpx_urls.txt"
  local katana_out="$OUTDIR/katana_urls.txt"
  local gau_out="$OUTDIR/gau_urls.txt"
  local endpoints="$OUTDIR/all_endpoints.txt"

  log "=== Crawl & Endpoint Discovery for $DOMAIN ==="

  # katana: crawl from live URLs
  if [[ -s "$httpx_urls" ]] && have katana; then
    log "[katana] Crawling from live URLs..."
    katana -list "$httpx_urls" \
           -d 2 \
           -silent \
           -o "$katana_out" || true
  else
    log "[katana] Missing katana or httpx_urls.txt; skipping katana."
  fi

  # gau: URLs from archives
  if have gau; then
    log "[gau] Pulling archived URLs for $DOMAIN..."
    gau --subs "$DOMAIN" | sort -u > "$gau_out" || true
  else
    log "[gau] Not found, skipping gau."
  fi

  log "[combine] Merging crawl + archive URLs..."
  cat "$katana_out" "$gau_out" 2>/dev/null \
    | sed '/^$/d' \
    | sort -u > "$endpoints" || true

  if [[ -s "$endpoints" ]]; then
    log "[+] Combined endpoints saved to $endpoints (lines: $(wc -l < "$endpoints"))"
  else
    log "[!] No endpoints collected."
  fi
}

# -----------------------------------
# Main
# -----------------------------------
main() {
  log "======================================================="
  log "Recon Pipeline for $DOMAIN"
  log "Output directory: $OUTDIR"
  log "======================================================="

  run_subdomain_enum
  run_naabu_scan
  run_httpx
  run_nuclei         # optional; auto-skips if nuclei not installed
  run_crawl_and_endpoints

  log "Recon pipeline complete for $DOMAIN"
  log "Outputs:"
  log "  - Subdomains   : $OUTDIR/all_subdomains.txt"
  log "  - Open Ports   : $OUTDIR/naabu_ports.txt"
  log "  - HTTP Results : $OUTDIR/httpx_results.txt"
  log "  - Live URLs    : $OUTDIR/httpx_urls.txt"
  log "  - Nuclei       : $OUTDIR/nuclei_findings.txt (if available)"
  log "  - Endpoints    : $OUTDIR/all_endpoints.txt"
}

main "$@"
