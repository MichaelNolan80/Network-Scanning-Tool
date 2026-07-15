#!/usr/bin/env bash

# ------------------------------------------------------------
# brute.sh - Credential brute-force using port index files
# ------------------------------------------------------------
# The scan phase writes <port>-tcp.txt files in the project
# folder, each containing every IP that has that port open.
# We use Hydra's -M flag to pass the whole IP list at once
# per service — one Hydra run per service, not per host.
#
# Supported services and their port index files:
#   22-tcp.txt  → ssh
#   21-tcp.txt  → ftp
#   23-tcp.txt  → telnet
#   139-tcp.txt → smb
#   445-tcp.txt → smb
#   3389-tcp.txt→ rdp
#   80-tcp.txt  → http-get
#   8080-tcp.txt→ http-get
#   443-tcp.txt → https-get
#   8443-tcp.txt→ https-get
#
# Requires: hydra
# ------------------------------------------------------------

# --- Config --------------------------------------------------
BRUTE_TASKS="${BRUTE_TASKS:-4}"       # Hydra -t parallel tasks per service
BRUTE_TIMEOUT="${BRUTE_TIMEOUT:-30}"  # Seconds per connection attempt
BRUTE_EXIT_FOUND="${BRUTE_EXIT_FOUND:-true}"  # Stop after first find per host
# -------------------------------------------------------------

# Map of port → Hydra service name
# Ports that share a service (139/445 → smb) are handled by
# merging their IP lists before passing to Hydra.
declare -A PORT_SERVICE_MAP=(
  [21]="ftp"
  [22]="ssh"
  [23]="telnet"
  [25]="smtp"
  [110]="pop3"
  [139]="smb"
  [143]="imap"
  [445]="smb"
  [3306]="mysql"
  [3389]="rdp"
  [5432]="postgres"
  [5900]="vnc"
  [6379]="redis"
  [80]="http-get"
  [443]="https-get"
  [8080]="http-get"
  [8443]="https-get"
)

# ------------------------------------------------------------
# _collect_targets_for_service MAIN_FOLDER SERVICE
#
# Finds all port index files for a given service name,
# merges and deduplicates their IPs into a temp file.
# Prints the temp file path, or empty string if no IPs found.
# Caller must delete the temp file when done.
# ------------------------------------------------------------
_collect_targets_for_service() {
  local main_folder="$1"
  local service="$2"

  local tmp_file
  tmp_file="$(mktemp /tmp/brute_targets_XXXXXX)"

  local port svc port_file
  for port in "${!PORT_SERVICE_MAP[@]}"; do
    svc="${PORT_SERVICE_MAP[$port]}"
    [[ "$svc" != "$service" ]] && continue

    port_file="${main_folder}/${port}-tcp.txt"
    if [[ -s "$port_file" ]]; then
      cat "$port_file" >> "$tmp_file"
    fi
  done

  # Deduplicate
  if [[ -s "$tmp_file" ]]; then
    sort -u "$tmp_file" -o "$tmp_file"
    echo "$tmp_file"
  else
    rm -f "$tmp_file"
    echo ""
  fi
}

# ------------------------------------------------------------
# _run_hydra_multi SERVICE PORT TARGET_FILE USER_LIST PASS_LIST OUT_FILE
#
# Runs Hydra against a list of IPs for a single service.
# Uses -M for multi-target mode.
# ------------------------------------------------------------
_run_hydra_multi() {
  local service="$1"
  local port="$2"
  local target_file="$3"
  local user_list="$4"
  local pass_list="$5"
  local out_file="$6"

  local target_count
  target_count="$(wc -l < "$target_file" | tr -d ' ')"

  ui_info "Hydra: ${service} on port ${port} — ${target_count} target(s)"

  local exit_flag=""
  [[ "$BRUTE_EXIT_FOUND" == "true" ]] && exit_flag="-f"

  # -M  : multi-target file (one IP per line)
  # -s  : port (explicit)
  # -t  : parallel tasks per host
  # -w  : wait timeout
  # -o  : output file for found creds
  # -f  : exit after first found cred (per host when used with -M)
  # -q  : suppress banner
  hydra \
    -L "$user_list" \
    -P "$pass_list" \
    -M "$target_file" \
    -s "$port" \
    -t "$BRUTE_TASKS" \
    -w "$BRUTE_TIMEOUT" \
    -o "$out_file" \
    $exit_flag \
    -q \
    "$service" </dev/null 2>&1 || true

  if [[ -s "$out_file" ]]; then
    local found_count
    found_count="$(grep -cE '^\[' "$out_file" 2>/dev/null || echo 0)"
    ui_ok "FOUND ${found_count} credential(s) for ${service} — see ${out_file}"
  else
    ui_info "No credentials found for ${service}."
  fi
}

# ------------------------------------------------------------
# run_brute_scan MAIN_FOLDER BRUTE_DIR USER_LIST PASS_LIST SELECTED_SERVICES
#
# Main entry point. Iterates over each service that:
#   a) was selected by the user at startup, AND
#   b) has at least one IP in the port index files from the scan.
# Runs one Hydra job per qualifying service.
# ------------------------------------------------------------
run_brute_scan() {
  local main_folder="$1"
  local brute_dir="$2"
  local user_list="$3"
  local pass_list="$4"
  local selected_services="${5:-}"  # space-separated list of Hydra service names

  mkdir -p "$brute_dir"

  # Build list of services that are both selected AND have scan targets.
  # We use a grep word-match to check membership rather than an associative
  # array — local -A lookup of non-existent keys trips set -u on some bash
  # versions even with the :- fallback.
  local -A seen_services=()
  local -a service_order=()
  local port svc port_file

  for port in "${!PORT_SERVICE_MAP[@]}"; do
    svc="${PORT_SERVICE_MAP[$port]}"
    port_file="${main_folder}/${port}-tcp.txt"

    # Skip if user didn't select this service
    echo " ${selected_services} " | grep -qw "$svc" || continue

    if [[ -s "$port_file" && -z "${seen_services[$svc]:-}" ]]; then
      seen_services[$svc]=1
      service_order+=("$svc")
    fi
  done

  if [[ "${#service_order[@]}" -eq 0 ]]; then
    ui_warn "None of the selected services (${selected_services}) were found in the scan."
    ui_warn "Check the project folder or broaden the service selection."
    return 0
  fi

  # Pick a representative port per service for Hydra's -s flag
  # (Hydra needs a port even in multi-target mode)
  declare -A SERVICE_DEFAULT_PORT=(
    [ftp]="21"
    [ssh]="22"
    [telnet]="23"
    [smtp]="25"
    [http-get]="80"
    [pop3]="110"
    [imap]="143"
    [smb]="445"
    [https-get]="443"
    [mysql]="3306"
    [rdp]="3389"
    [postgres]="5432"
    [vnc]="5900"
    [redis]="6379"
  )

  local summary_file="${brute_dir}/brute_summary.txt"
  {
    echo "========================================"
    echo " Brute-Force Summary"
    echo " Generated : $(date -Is)"
    echo " Wordlists :"
    echo "   Users    : ${user_list}"
    echo "   Passwords: ${pass_list}"
    echo " Services  : ${selected_services}"
    echo "========================================"
    echo
  } > "$summary_file"

  local total="${#service_order[@]}"
  local i=0 targets_file out_file default_port

  ui_ok "Services to attack: ${service_order[*]}"
  echo

  for svc in "${service_order[@]}"; do
    i=$(( i + 1 ))
    ui_phase "Service ${i}/${total}: ${svc}"

    # Collect and merge all IPs for this service
    targets_file="$(_collect_targets_for_service "$main_folder" "$svc")"

    if [[ -z "$targets_file" ]]; then
      ui_warn "No targets found for ${svc}, skipping."
      continue
    fi

    local target_count
    target_count="$(wc -l < "$targets_file" | tr -d ' ')"
    ui_info "Targets: ${target_count} IP(s)"

    default_port="${SERVICE_DEFAULT_PORT[$svc]:-0}"
    out_file="${brute_dir}/${svc}_found.txt"

    _run_hydra_multi \
      "$svc" \
      "$default_port" \
      "$targets_file" \
      "$user_list" \
      "$pass_list" \
      "$out_file"

    # Append results to the master summary
    {
      echo "--- ${svc} (port ${default_port}) ---"
      echo "Targets: ${target_count}"
      if [[ -s "$out_file" ]]; then
        echo "Status : CREDENTIALS FOUND"
        grep -E '^\[' "$out_file" 2>/dev/null \
          | grep -v '^\[DATA\]\|^\[WARNING\]\|^\[ERROR\]' || true
      else
        echo "Status : Nothing found"
      fi
      echo
    } >> "$summary_file"

    rm -f "$targets_file"
    echo
  done

  ui_ok "Brute-force complete."
  ui_ok "Summary : ${summary_file}"
  ui_ok "Per-service results in: ${brute_dir}/"

  # Write any found credentials back into each host's summary.txt
  append_brute_to_summaries "$main_folder" "$brute_dir"
}

# ------------------------------------------------------------
# append_brute_to_summaries MAIN_FOLDER BRUTE_DIR
#
# After brute-force completes, reads each <service>_found.txt,
# extracts the IP from each found credential line, and appends
# the result to that host's summary.txt under a new section.
#
# Hydra found-credential lines look like:
#   [22][ssh] host: 10.0.0.5   login: admin   password: 1234
# ------------------------------------------------------------
append_brute_to_summaries() {
  local main_folder="$1"
  local brute_dir="$2"
  local found_file ip ip_summary cred_line

  # Collect all per-service found files
  local -a found_files=()
  while IFS= read -r -d '' found_file; do
    found_files+=("$found_file")
  done < <(find "$brute_dir" -maxdepth 1 -name "*_found.txt" -size +0c -print0 2>/dev/null)

  if [[ "${#found_files[@]}" -eq 0 ]]; then
    ui_info "No credentials found — host summaries unchanged."
    return 0
  fi

  ui_info "Updating host summaries with found credentials..."

  # Build a temp map: ip → credential lines
  # We use temp files keyed by IP to collect all hits across services
  local tmp_dir
  tmp_dir="$(mktemp -d /tmp/brute_creds_XXXXXX)"

  for found_file in "${found_files[@]}"; do
    while IFS= read -r cred_line; do
      # Only process Hydra result lines (start with [ and contain "host:")
      [[ "$cred_line" =~ ^\[ ]] || continue
      [[ "$cred_line" =~ host:[[:space:]] ]] || continue
      [[ "$cred_line" =~ \[DATA\]|\[WARNING\]|\[ERROR\] ]] && continue

      # Extract the IP from "host: x.x.x.x"
      ip="$(echo "$cred_line" | grep -oP '(?<=host:\s)[\d.]+')" || continue
      [[ -z "$ip" ]] && continue

      echo "$cred_line" >> "${tmp_dir}/${ip}.txt"
    done < "$found_file"
  done

  # Now append to each host's summary.txt
  local updated=0
  for cred_file in "${tmp_dir}"/*.txt; do
    [[ -f "$cred_file" ]] || continue
    ip="$(basename "$cred_file" .txt)"

    # Find this IP's summary.txt anywhere under main_folder/*/hosts/
    ip_summary="$(find "$main_folder" -path "*/hosts/${ip}/summary.txt" 2>/dev/null | head -n 1)"

    if [[ -z "$ip_summary" ]]; then
      ui_warn "Could not find summary.txt for ${ip} — skipping."
      continue
    fi

    {
      echo
      echo "=== Brute-Force Credentials Found ==="
      cat "$cred_file"
    } >> "$ip_summary"

    ui_ok "Credentials appended to: ${ip_summary}"
    updated=$(( updated + 1 ))
  done

  rm -rf "$tmp_dir"
  ui_ok "Updated ${updated} host summary file(s) with credentials."
}

export -f run_brute_scan
export -f append_brute_to_summaries
