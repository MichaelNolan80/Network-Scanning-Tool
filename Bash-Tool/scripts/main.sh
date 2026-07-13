#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# Network Scanner - main.sh
# Sources: lib/ui.sh  lib/utils.sh  lib/vuln.sh  lib/scan.sh  lib/brute.sh
# ============================================================

# --- Locate script directory so lib/ sources always work ----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"

# --- Source libraries ----------------------------------------
# Order matters: ui → utils → vuln → scan → brute
for _lib in ui utils vuln scan brute; do
  _lib_path="${LIB_DIR}/${_lib}.sh"
  if [[ ! -f "$_lib_path" ]]; then
    echo "[ERROR] Missing library: ${_lib_path}" >&2
    exit 1
  fi
  # shellcheck source=/dev/null
  source "$_lib_path"
done

# --- Tunables ------------------------------------------------
TCP_WORKERS="${TCP_WORKERS:-6}"
RTT_T4_MAX_MS="${RTT_T4_MAX_MS:-30}"
RTT_T3_MAX_MS="${RTT_T3_MAX_MS:-80}"

# ------------------------------------------------------------
# main
# ------------------------------------------------------------
main() {
  ui_banner "Network TCP + OS + CVE + Brute-Force Scanner"

  # Must run as root for SYN + OS scans
  ensure_root "${BASH_SOURCE[0]}" "$@"

  # Dependency check
  for _cmd in nmap hydra curl awk grep sort wc sed tr ping flock; do
    require_cmd "$_cmd"
  done

  # ---- Project setup ---------------------------------------
  local project_name project_clean date_str main_folder vuln_dir brute_dir
  local targets_file exclude_file

  read -rp "Enter project name: " project_name
  project_clean="$(echo "$project_name" | tr ' ' '_' | tr -cd '[:alnum:]_-')"
  [[ -z "$project_clean" ]] && project_clean="project"

  date_str="$(date +"%Y-%m-%d")"
  main_folder="${date_str}_${project_clean}"
  mkdir -p "$main_folder"

  vuln_dir="${main_folder}/Vuln"
  brute_dir="${main_folder}/Brute"
  mkdir -p "$vuln_dir" "$brute_dir"

  targets_file="${main_folder}/targets.txt"
  exclude_file="${main_folder}/exclude.txt"

  ui_ok "Project folder : ${main_folder}"
  ui_ok "Vuln reports   : ${vuln_dir}"
  ui_ok "Brute reports  : ${brute_dir}"
  echo

  # ---- All user inputs are gathered here, up front -----------

  # ---- NVD API key -----------------------------------------
  if [[ -z "${NVD_API_KEY:-}" ]]; then
    ui_warn "NVD_API_KEY is not set."
    ui_info "Get a free key at: https://nvd.nist.gov/developers/request-an-api-key"
    ui_info "Paste it now, or leave blank to continue unauthenticated (slower)."
    read -rsp "NVD API key (input hidden, press Enter to skip): " _entered_key
    echo
    if [[ -n "$_entered_key" ]]; then
      NVD_API_KEY="$_entered_key"
      export NVD_API_KEY
      ui_ok "NVD_API_KEY set for this run."
    else
      ui_warn "Continuing without a key — rate limit: 5 requests/30s."
    fi
    unset _entered_key
  else
    ui_ok "NVD_API_KEY detected — using authenticated rate limits."
  fi
  echo

  # ---- Wordlists for brute-force ---------------------------
  local user_list pass_list _do_brute

  ui_phase "Brute-Force Wordlists"
  ui_info "Common locations on Kali/Parrot:"
  ui_info "  Users : /usr/share/seclists/Usernames/top-usernames-shortlist.txt"
  ui_info "  Passes: /usr/share/seclists/Passwords/Common-Credentials/best110.txt"
  ui_info "  Passes: /usr/share/wordlists/rockyou.txt"
  echo

  while true; do
    read -rp "Path to username list (or Enter to skip brute-force): " user_list
    user_list="$(trim "$user_list")"
    [[ -z "$user_list" ]] && { _do_brute=false; break; }
    if [[ -f "$user_list" ]]; then
      _do_brute=true
      break
    fi
    ui_err "File not found: ${user_list}. Try again."
  done

  if [[ "$_do_brute" == "true" ]]; then
    while true; do
      read -rp "Path to password list: " pass_list
      pass_list="$(trim "$pass_list")"
      if [[ -f "$pass_list" ]]; then
        break
      fi
      ui_err "File not found: ${pass_list}. Try again."
    done
    ui_ok "Username list : ${user_list}"
    ui_ok "Password list : ${pass_list}"
  else
    ui_warn "No username list provided — brute-force phase will be skipped."
  fi
  echo

  # ---- Targets ---------------------------------------------
  ui_info "Enter target ranges (CIDR/IP/hostname), one per line. Blank line to finish."

  : > "$targets_file"
  while true; do
    read -r line || break
    line="$(trim "$line")"
    [[ -z "$line" ]] && break
    echo "$line" >> "$targets_file"
  done

  grep -vE '^[[:space:]]*($|#)' "$targets_file" > "${targets_file}.tmp" || true
  mv -f "${targets_file}.tmp" "$targets_file"

  if [[ ! -s "$targets_file" ]]; then
    ui_err "No targets provided. Exiting."
    exit 1
  fi

  # ---- Exclude file (optional) -----------------------------
  : > "$exclude_file"
  ui_info "Enter IPs to exclude (one per line). Blank line to skip."
  while true; do
    read -r line || break
    line="$(trim "$line")"
    [[ -z "$line" ]] && break
    echo "$line" >> "$exclude_file"
  done
  echo

  # ---- All inputs collected — scanning starts now ------------
  ui_banner "Starting scans"
  echo

  # ---- Scan ------------------------------------------------
  local total_targets idx target fast
  local -a target_list=()

  # Read all targets into an array FIRST — avoids stdin-consumption
  # bug where nmap/ping/curl inside the loop eat remaining targets.
  while IFS= read -r target; do
    target="$(trim "$target")"
    [[ -z "$target" || "$target" =~ ^# ]] && continue
    target_list+=("$target")
  done < "$targets_file"

  total_targets="${#target_list[@]}"
  ui_ok "Targets: ${total_targets}"
  ui_info "TCP workers   : ${TCP_WORKERS}"
  echo

  idx=0
  for target in "${target_list[@]}"; do
    idx=$(( idx + 1 ))
    ui_banner "Target ${idx}/${total_targets}: ${target}"

    fast="$(calc_fast_timing "$target" "$RTT_T4_MAX_MS" "$RTT_T3_MAX_MS" </dev/null)"
    ui_info "Timing: ${fast} (discovery + MAC + TCP only)"
    echo

    if scan_target \
        "$main_folder" \
        "$vuln_dir" \
        "$target" \
        "$fast" \
        "$TCP_WORKERS" \
        "$exclude_file" \
        </dev/null; then
      ui_ok "Scan completed: ${target}"
    else
      ui_warn "Target ${target} finished with no results or an error. Continuing."
    fi
    echo
  done

  # ---- Brute-Force -----------------------------------------
  if [[ "$_do_brute" == "true" ]]; then
    ui_banner "Brute-Force Phase"
    ui_warn "Only run this against systems you own or have written permission to test."
    echo
    run_brute_scan "$main_folder" "$brute_dir" "$user_list" "$pass_list" </dev/null
    echo
  fi

  # ---- Done ------------------------------------------------
  ui_banner "All done"
  ui_ok "Project folder : ${main_folder}"
  ui_ok "Vuln reports   : ${vuln_dir}"
  [[ "$_do_brute" == "true" ]] && ui_ok "Brute reports  : ${brute_dir}"
  echo
  ui_info "View a vuln report  : cat ${vuln_dir}/<ip>_vuln.txt"
  ui_info "View a brute report : cat ${brute_dir}/<ip>/brute_summary.txt"
}

main "$@"
