#!/usr/bin/env bash

# ------------------------------------------------------------
# ui.sh - visual helper functions for the network scan script
# ------------------------------------------------------------
# IMPORTANT:
# Do not put 'set -Eeuo pipefail' in module files.
# Keep strict mode in main.sh only.
# ------------------------------------------------------------

# Basic colors, only when stdout is a terminal
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'
  C_DIM=$'\033[2m'
  C_BOLD=$'\033[1m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
else
  C_RESET=""
  C_DIM=""
  C_BOLD=""
  C_RED=""
  C_GREEN=""
  C_YELLOW=""
  C_BLUE=""
fi

ts() {
  date +"%Y-%m-%d %H:%M:%S"
}

ui_banner() {
  local msg="$1"
  echo -e "${C_BOLD}${C_BLUE}==> ${msg}${C_RESET}"
}

ui_phase() {
  local msg="$1"
  echo -e "${C_BOLD}${C_BLUE}--- ${msg} ---${C_RESET}"
}

ui_info() {
  echo -e "${C_DIM}[$(ts)]${C_RESET} ${C_BLUE}INFO${C_RESET}  $*"
}

ui_ok() {
  echo -e "${C_DIM}[$(ts)]${C_RESET} ${C_GREEN}OK${C_RESET}    $*"
}

ui_warn() {
  echo -e "${C_DIM}[$(ts)]${C_RESET} ${C_YELLOW}WARN${C_RESET}  $*"
}

ui_err() {
  echo -e "${C_DIM}[$(ts)]${C_RESET} ${C_RED}ERR${C_RESET}   $*"
}

ui_prompt() {
  local prompt="$1"
  local answer
  read -rp "${prompt}: " answer
  echo "$answer"
}

ui_progress() {
  local current="$1"
  local total="$2"
  local message="$3"
  echo -e "${C_DIM}[$(ts)]${C_RESET} ${C_BLUE}PROG${C_RESET}  (${current}/${total}) ${message}"
}

ui_spinner_wait() {
  local pid="$1"
  local label="${2:-Working}"
  local spin='-\|/'
  local i=0

  kill -0 "$pid" 2>/dev/null || return 0

  echo -ne "${C_DIM}[$(ts)]${C_RESET} ${C_BLUE}${label}${C_RESET} "

  while kill -0 "$pid" 2>/dev/null; do
    i=$(( (i + 1) % 4 ))
    echo -ne "${C_BOLD}${spin:$i:1}${C_RESET}\r"
    sleep 0.15
  done

  echo -ne " \r"
}

