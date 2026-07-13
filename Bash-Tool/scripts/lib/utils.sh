#!/usr/bin/env bash

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing dependency: $1"
    exit 1
  }
}

ensure_root() {
  local script="$1"
  shift || true

  if [[ ${EUID:-999} -ne 0 ]]; then
    echo "Not running as root. Re-running with sudo..."
    # -E preserves the calling user's environment (e.g. NVD_API_KEY)
    # across the sudo re-exec. Without -E, sudo resets the env by default.
    exec sudo -E "$script" "$@"
  fi
}

trim() {
  echo "$1" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//'
}

count_nonempty_lines() {
  local file="$1"
  grep -vE '^[[:space:]]*($|#)' "$file" | wc -l | tr -d ' '
}

create_main_folder() {
  local project="$1"
  local date_str
  date_str="$(date +"%Y-%m-%d")"

  local clean
  clean="$(echo "$project" | tr ' ' '_' | tr -cd '[:alnum:]_-')"

  local folder="${date_str}_${clean}"
  mkdir -p "$folder"
  echo "$folder"
}

read_targets_into_file() {
  local file="$1"

  : > "$file"

  while true; do
    read -r line || break
    line="$(trim "$line")"

    [[ -z "$line" ]] && break

    echo "$line" >> "$file"
  done

  grep -vE '^[[:space:]]*($|#)' "$file" > "${file}.tmp" || true
  mv -f "${file}.tmp" "$file"
}

append_unique_locked() {
  local text="$1"
  local file="$2"
  local lock="${file}.lock"

  (
    exec 200>"$lock"
    flock -x 200

    touch "$file"

    if ! grep -Fxq "$text" "$file"; then
      echo "$text" >> "$file"
    fi
  )
}

sanitize_label() {
  echo "$1" | tr ' /' '__' | tr -cd '[:alnum:]_.-'
}

safe_name() {
  echo "$1" | tr ' /' '__' | tr -cd '[:alnum:]_.-'
}

