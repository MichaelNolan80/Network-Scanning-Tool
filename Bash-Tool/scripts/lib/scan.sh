#!/usr/bin/env bash

# ------------------------------------------------------------
# scan.sh - core scanning functions
# Requires: ui.sh, utils.sh, vuln.sh sourced before this file
# ------------------------------------------------------------

get_os_guess_from_nmap() {
  local file="$1"
  local os=""

  os="$(awk -F': ' '/^Running: /{print $2; exit}' "$file" 2>/dev/null || true)"
  [[ -n "$os" ]] && { echo "$os"; return; }

  os="$(awk -F': ' '/^OS details: /{print $2; exit}' "$file" 2>/dev/null || true)"
  [[ -n "$os" ]] && { echo "$os"; return; }

  os="$(awk -F': ' '/^Aggressive OS guesses: /{print $2; exit}' "$file" 2>/dev/null || true)"
  if [[ -n "$os" ]]; then
    os="${os%%,*}"
    os="$(echo "$os" | sed -E 's/[[:space:]]*\([0-9]+%\)[[:space:]]*$//')"
    echo "$os"
    return
  fi

  echo "Unknown"
}

calc_fast_timing() {
  local target="$1"
  local t4_max="$2"
  local t3_max="$3"

  local base probe avg_ms avg_int

  base="$(echo "$target" | grep -Eo '^([0-9]{1,3}\.){3}' | head -n 1 || true)"

  if [[ -z "$base" ]]; then
    echo "-T4"
    return
  fi

  probe="${base}1"
  avg_ms="$(ping -c 2 -W 1 "$probe" 2>/dev/null \
    | awk -F'/' '/min\/avg\/max/{print $5; exit}' || true)"

  if [[ -z "$avg_ms" ]]; then
    echo "-T4"
    return
  fi

  avg_int="$(printf "%.0f" "$avg_ms" 2>/dev/null || echo 999)"

  if (( avg_int <= t4_max )); then
    echo "-T4"
  elif (( avg_int <= t3_max )); then
    echo "-T3"
  else
    echo "-T2"
  fi
}

discover_hosts() {
  local target="$1"
  local fast="$2"
  local devices_file="$3"
  local exclude_file="${4:-}"

  local exclude_arg=""
  if [[ -n "$exclude_file" && -f "$exclude_file" ]]; then
    exclude_arg="--excludefile ${exclude_file}"
  fi

  # shellcheck disable=SC2086
  # `|| true` ensures a non-zero nmap exit (e.g. partial permission
  # issues, no hosts up) doesn't trip `set -e` in the caller and
  # kill the entire script. We check $devices_file afterward anyway.
  nmap $fast -sn -n "$target" $exclude_arg </dev/null \
    | awk '/Nmap scan report/{print $NF}' \
    | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' \
    | sort -u > "$devices_file" || true
}

scan_fast_host() {
  local ip="$1"
  local ip_dir="$2"
  local main_folder="$3"
  local fast="$4"

  mkdir -p "$ip_dir"

  echo "[$(date +%H:%M:%S)] TCP Scan Starting: $ip"

  # MAC + Vendor (best-effort ARP ping). `|| true`: a failure here
  # for one host must not abort the whole run under set -e.
  nmap "$fast" -sn -n -PR "$ip" > "${ip_dir}/mac_vendor.txt" 2>&1 || true

  # TCP service + version scan. `|| true`: one host's nmap failure
  # must not abort the whole run under set -e.
  # shellcheck disable=SC2086
  nmap $fast -n -sS -sV --version-all --reason --script default "$ip" \
    -oN "${ip_dir}/tcp_scan.txt" \
    -oX "${ip_dir}/tcp_scan.xml" \
    > "${ip_dir}/tcp_scan_console.log" 2>&1 || true

  # Index open ports into per-port files in the main folder
  if [[ -s "${ip_dir}/tcp_scan.txt" ]]; then
    awk '/^[0-9]+\/tcp[[:space:]]+open/{split($1,a,"/"); print a[1]}' \
      "${ip_dir}/tcp_scan.txt" 2>/dev/null \
      | sort -n -u \
      | while read -r port; do
          [[ -n "$port" ]] && append_unique_locked "$ip" "${main_folder}/${port}-tcp.txt"
        done
  fi

  echo "[$(date +%H:%M:%S)] TCP Scan Complete: $ip"
}

scan_os_host() {
  local ip="$1"
  local ip_dir="$2"

  mkdir -p "$ip_dir"

  echo "[$(date +%H:%M:%S)] OS Scan Starting: $ip"

  # `|| true`: one host's OS-scan failure must not abort the whole run.
  nmap -n -O --osscan-guess "$ip" \
    -oN "${ip_dir}/os_scan.txt" \
    -oX "${ip_dir}/os_scan.xml" \
    > "${ip_dir}/os_scan_console.log" 2>&1 || true

  echo "[$(date +%H:%M:%S)] OS Scan Complete: $ip"
}

write_summary() {
  local ip="$1"
  local target="$2"
  local ip_dir="$3"

  {
    echo "========================================"
    echo " Host Summary"
    echo " IP      : ${ip}"
    echo " Target  : ${target}"
    echo " Generated: $(date -Is)"
    echo "========================================"
    echo
    echo "=== OS ==="
    cat "${ip_dir}/os.txt" 2>/dev/null || echo "Unknown"
    echo
    echo "=== MAC / Vendor ==="
    grep -E 'MAC Address:|Nmap scan report for|Host is up' \
      "${ip_dir}/mac_vendor.txt" 2>/dev/null || echo "Not detected"
    echo
    echo "=== Open TCP Ports ==="
    awk '/^[0-9]+\/tcp[[:space:]]+open/' \
      "${ip_dir}/tcp_scan.txt" 2>/dev/null || echo "None"
  } > "${ip_dir}/summary.txt"
}

scan_target() {
  local main_folder="$1"
  local vuln_dir="$2"
  local target="$3"
  local fast="$4"
  local tcp_workers="$5"
  local exclude_file="${6:-}"

  local safe_target workdir devices_file hosts_dir total_hosts
  safe_target="$(safe_name "$target")"
  workdir="${main_folder}/${safe_target}"
  devices_file="${workdir}/network_devices/devices.txt"
  hosts_dir="${workdir}/hosts"

  mkdir -p "$(dirname "$devices_file")" "$hosts_dir"

  # ---- Phase 1: Discovery ----------------------------------
  ui_phase "Discovery"
  ui_info "Running host discovery scan..."
  discover_hosts "$target" "$fast" "$devices_file" "$exclude_file"

  if [[ ! -s "$devices_file" ]]; then
    ui_warn "No live hosts found in ${target}. Skipping to next target."
    return 0
  fi

  total_hosts="$(wc -l < "$devices_file" | tr -d ' ')"
  ui_ok "Discovered ${total_hosts} host(s)."
  echo

  # ---- Phase 2: MAC + TCP (parallel) -----------------------
  ui_phase "MAC + TCP Scan (parallel, ${tcp_workers} workers)"
  ui_info "Starting parallel version scans..."

  local -a ip_list=()
  while IFS= read -r _ip_line; do
    [[ -z "$_ip_line" ]] && continue
    ip_list+=("$_ip_line")
  done < "$devices_file"

  for ip in "${ip_list[@]}"; do
    (
      scan_fast_host "$ip" "${hosts_dir}/${ip}" "$main_folder" "$fast" </dev/null
    ) &

    while (( "$(jobs -r -p | wc -l)" >= tcp_workers )); do
      sleep 1
    done
  done

  wait
  ui_ok "TCP scans completed."
  echo

  # ---- Phase 3: OS Scans (serialised) ----------------------
  ui_phase "OS Scans (serialised, no -T4)"
  local i=0 ip ip_dir os_guess os_label

  i=0
  for ip in "${ip_list[@]}"; do
    i=$(( i + 1 ))
    ip_dir="${hosts_dir}/${ip}"

    ui_progress "$i" "$total_hosts" "OS scan: ${ip}"
    scan_os_host "$ip" "$ip_dir" </dev/null

    os_guess="$(get_os_guess_from_nmap "${ip_dir}/os_scan.txt")"
    echo "$os_guess" > "${ip_dir}/os.txt"

    os_label="$(sanitize_label "$os_guess")"
    [[ -z "$os_label" ]] && os_label="Unknown"
    append_unique_locked "$ip" "${main_folder}/OS_${os_label}.txt"
  done

  ui_ok "OS scans completed."
  echo

  # ---- Phase 4: Summaries ----------------------------------
  ui_phase "Writing host summaries"
  i=0

  for ip in "${ip_list[@]}"; do
    i=$(( i + 1 ))
    ip_dir="${hosts_dir}/${ip}"
    ui_progress "$i" "$total_hosts" "Summary: ${ip}"
    write_summary "$ip" "$target" "$ip_dir"
  done

  ui_ok "Summaries written."
  echo

  # ---- Phase 5: Vulnerability Lookups ----------------------
  ui_phase "CVE Vulnerability Lookup (NVD API)"
  ui_info "Querying NVD for each detected service/version..."
  [[ -z "${NVD_API_KEY:-}" ]] && \
    ui_warn "NVD_API_KEY not set — rate limited to 5 req/30s. Scans will be slow."
  echo

  i=0
  for ip in "${ip_list[@]}"; do
    i=$(( i + 1 ))
    ip_dir="${hosts_dir}/${ip}"
    ui_progress "$i" "$total_hosts" "CVE lookup: ${ip}"
    run_vuln_scan "$ip" "$ip_dir" "$vuln_dir" </dev/null
  done

  ui_ok "Vulnerability lookups complete. Reports in: ${vuln_dir}"
}

export -f scan_fast_host
export -f scan_os_host
export -f scan_target
export -f write_summary
export -f discover_hosts
export -f get_os_guess_from_nmap
export -f calc_fast_timing

