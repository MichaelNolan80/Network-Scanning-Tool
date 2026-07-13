#!/usr/bin/env bash

# ------------------------------------------------------------
# vuln.sh - CVE vulnerability lookup via NVD API v2
# ------------------------------------------------------------
# Parses nmap tcp_scan.txt for software/version strings,
# queries the NVD API, and writes results to vuln output files.
#
# NVD API docs: https://nvd.nist.gov/developers/vulnerabilities
#
# Optional: set NVD_API_KEY in your environment for higher
# rate limits (50 req/30s vs 5 req/30s unauthenticated).
# export NVD_API_KEY="your-key-here"
# ------------------------------------------------------------

# --- Config --------------------------------------------------
NVD_API_BASE="https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RESULTS_PER_PAGE=5        # CVEs to fetch per product (keep low)
NVD_DELAY_UNAUTH=6            # seconds between requests (unauth: 5/30s)
NVD_DELAY_AUTH=1              # seconds between requests (auth: 50/30s)
NVD_TIMEOUT=15                # curl timeout per request
NVD_SEVERITY_FILTER="HIGH"    # CRITICAL, HIGH, MEDIUM, LOW, or "" for all
# -------------------------------------------------------------

# Decide rate-limit delay based on whether API key is set
_nvd_delay() {
  if [[ -n "${NVD_API_KEY:-}" ]]; then
    echo "$NVD_DELAY_AUTH"
  else
    echo "$NVD_DELAY_UNAUTH"
  fi
}

# Build curl auth header args
_nvd_auth_args() {
  if [[ -n "${NVD_API_KEY:-}" ]]; then
    echo "-H" "apiKey: ${NVD_API_KEY}"
  fi
}

# ------------------------------------------------------------
# parse_services_from_nmap FILE
#
# Reads an nmap -oN tcp_scan.txt and extracts
# "product version" pairs from open TCP ports.
#
# Output: one "product version" per line (tab-separated)
# ------------------------------------------------------------
parse_services_from_nmap() {
  local file="$1"

  [[ -f "$file" ]] || return 0

  # Nmap -sV lines look like:
  # 22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
  # 80/tcp   open  http    Apache httpd 2.4.52 ((Ubuntu))
  # 443/tcp  open  ssl     nginx 1.18.0
  #
  # Field layout (awk):
  #   $1 = port/proto   $2 = state   $3 = service   $4+ = product+version

  awk '
    /^[0-9]+\/tcp[[:space:]]+open/ {
      # Build the version string from field 4 onward
      ver = ""
      for (i = 4; i <= NF; i++) ver = ver " " $i
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", ver)

      # Skip empty or generic strings
      if (ver == "" || ver == "?" ) next

      # Extract product (first word) and version (second word if looks like x.y...)
      n = split(ver, parts, " ")
      product = parts[1]
      version = ""

      for (j = 2; j <= n; j++) {
        if (parts[j] ~ /^[0-9]/) {
          version = parts[j]
          # Strip trailing non-version noise: (Ubuntu), ((Debian)), etc.
          gsub(/[^0-9.].*$/, "", version)
          break
        }
      }

      # Only emit if we have both product and a version number
      if (product != "" && version ~ /^[0-9]/) {
        print product "\t" version
      }
    }
  ' "$file" | sort -u
}

# ------------------------------------------------------------
# nvd_lookup PRODUCT VERSION
#
# Queries NVD for CVEs matching the given CPE keyword search.
# Prints a formatted block of results to stdout.
# ------------------------------------------------------------
nvd_lookup() {
  local product="$1"
  local version="$2"
  local delay
  delay="$(_nvd_delay)"

  # Build keyword query: "apache 2.4.52"
  local keyword
  keyword="${product} ${version}"

  # URL-encode spaces as %20
  local encoded_kw
  encoded_kw="$(printf '%s' "$keyword" | sed 's/ /%20/g')"

  local url="${NVD_API_BASE}?keywordSearch=${encoded_kw}&resultsPerPage=${NVD_RESULTS_PER_PAGE}"

  # Add severity filter if set
  if [[ -n "$NVD_SEVERITY_FILTER" ]]; then
    url="${url}&cvssV3Severity=${NVD_SEVERITY_FILTER}"
  fi

  # Build optional auth header
  local auth_header=""
  if [[ -n "${NVD_API_KEY:-}" ]]; then
    auth_header="-H apiKey:${NVD_API_KEY}"
  fi

  local response http_code body

  # Fetch with timeout; capture HTTP status separately
  response="$(curl -s -w "\n__HTTP_CODE__:%{http_code}" \
    --max-time "$NVD_TIMEOUT" \
    -H "Accept: application/json" \
    ${auth_header:+$auth_header} \
    "$url" </dev/null 2>/dev/null)" || {
    echo "  [ERROR] curl failed for: ${keyword}"
    sleep "$delay"
    return 1
  }

  http_code="$(echo "$response" | grep -oP '(?<=__HTTP_CODE__:)\d+' || echo "000")"
  body="$(echo "$response" | sed '/__HTTP_CODE__:/d')"

  if [[ "$http_code" == "403" ]]; then
    echo "  [RATE LIMITED] NVD returned 403. Consider adding an NVD_API_KEY."
    sleep 30
    return 1
  fi

  if [[ "$http_code" != "200" ]]; then
    echo "  [ERROR] NVD HTTP ${http_code} for: ${keyword}"
    sleep "$delay"
    return 1
  fi

  # Parse JSON with awk (no jq dependency)
  # Extract: CVE ID, severity, score, description
  local parsed
  parsed="$(echo "$body" | awk '
    BEGIN { id=""; score=""; severity=""; desc=""; in_desc=0 }

    /"cveId"[[:space:]]*:/ {
      match($0, /"cveId"[[:space:]]*:[[:space:]]*"([^"]+)"/, a)
      if (a[1] != "") id = a[1]
    }

    /"baseSeverity"[[:space:]]*:/ {
      match($0, /"baseSeverity"[[:space:]]*:[[:space:]]*"([^"]+)"/, a)
      if (a[1] != "" && severity == "") severity = a[1]
    }

    /"baseScore"[[:space:]]*:/ {
      match($0, /"baseScore"[[:space:]]*:[[:space:]]*([0-9.]+)/, a)
      if (a[1] != "" && score == "") score = a[1]
    }

    /"value"[[:space:]]*:/ && in_desc == 0 {
      match($0, /"value"[[:space:]]*:[[:space:]]*"([^"]+)"/, a)
      if (a[1] != "") { desc = substr(a[1], 1, 120); in_desc = 1 }
    }

    /"weaknesses"/ {
      if (id != "") {
        printf "  %-20s  %-8s  Score:%-4s  %s\n", id, severity, score, desc
        id=""; score=""; severity=""; desc=""; in_desc=0
      }
    }
  ')"

  if [[ -z "$parsed" ]]; then
    echo "  No CVEs found matching: ${keyword}"
  else
    echo "$parsed"
  fi

  sleep "$delay"
}

# ------------------------------------------------------------
# run_vuln_scan IP IP_DIR VULN_DIR
#
# Main entry point. Parses scan results for an IP,
# looks up CVEs for each detected service, writes output.
# ------------------------------------------------------------
run_vuln_scan() {
  local ip="$1"
  local ip_dir="$2"
  local vuln_dir="$3"

  local tcp_scan="${ip_dir}/tcp_scan.txt"
  local vuln_file="${vuln_dir}/${ip}_vuln.txt"

  mkdir -p "$vuln_dir"

  {
    echo "========================================"
    echo " Vulnerability Report"
    echo " IP      : ${ip}"
    echo " Generated: $(date -Is)"
    echo "========================================"
    echo

    if [[ ! -f "$tcp_scan" ]]; then
      echo "No tcp_scan.txt found for ${ip}. Skipping."
      return 0
    fi

    # Parse services
    local services
    services="$(parse_services_from_nmap "$tcp_scan")"

    if [[ -z "$services" ]]; then
      echo "No versioned services detected. Nothing to look up."
      echo
      echo "Tip: Ensure nmap was run with -sV (version detection)."
      return 0
    fi

    echo "Detected services:"
    while IFS=$'\t' read -r product version; do
      echo "  - ${product} ${version}"
    done <<< "$services"
    echo

    if [[ -z "${NVD_API_KEY:-}" ]]; then
      echo "NOTE: No NVD_API_KEY set. Rate limit: 5 requests/30s."
      echo "      Set NVD_API_KEY in your environment for faster lookups."
      echo
    fi

    echo "CVE Lookup Results (Severity filter: ${NVD_SEVERITY_FILTER:-ALL})"
    echo "--------------------------------------------------------"

    local product version
    while IFS=$'\t' read -r product version; do
      echo
      echo ">>> ${product} ${version}"
      nvd_lookup "$product" "$version" || echo "  [WARN] Lookup failed for ${product} ${version}, continuing."
    done <<< "$services"

    echo
    echo "========================================"
    echo " End of Report"
    echo "========================================"

  } > "$vuln_file" 2>&1

  echo "[$(date +%H:%M:%S)] Vuln scan complete: ${ip} -> ${vuln_file}"
}

export -f run_vuln_scan
export -f parse_services_from_nmap
export -f nvd_lookup

