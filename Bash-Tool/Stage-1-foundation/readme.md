# Stage 1 — Foundation

## What I was trying to do

Before writing any scanning logic I wanted to get the architecture right. My original script was a single monolithic `main.sh` that had everything in one file — UI helpers, scanning functions, output writing — all mixed together. I'd hit the point where it was getting hard to read and hard to change without breaking something else, so I decided to split it into modules before going any further.

I also knew the script needed to run as root (nmap's SYN scan and OS detection require it), handle parallel subshells writing to shared files, and work cleanly whether or not stdout is a terminal. I wanted to solve those problems once, properly, before the codebase got bigger.

## What I built

**`lib/ui.sh`** — all terminal output in one place. Coloured, timestamped log lines (`ui_info`, `ui_ok`, `ui_warn`, `ui_err`), section banners, and a progress indicator. It detects whether stdout is a terminal and strips colour codes automatically when it's not (e.g. if output is piped to a file). Keeping this separate means I can change how the tool looks without touching any logic.

**`lib/utils.sh`** — shared helper functions used across all other modules:
- `require_cmd` — checks a dependency is installed and exits cleanly if not
- `ensure_root` — re-runs the script with `sudo` if not already root
- `trim`, `safe_name`, `sanitize_label` — input cleaning
- `append_unique_locked` — the most important one (see below)

**`main.sh`** — stripped back to just: source the libs, check dependencies, collect user input, drive the flow. No logic lives here.

## Key decisions and what I learned

**Why `sudo -E` not just `sudo`**

I ran into a bug early on where I'd `export NVD_API_KEY=...` in my terminal then run `sudo ./main.sh` and the script would say the key wasn't set. I couldn't understand it — I'd definitely exported it.

The reason is that plain `sudo` resets the environment by default. It starts a fresh shell for root, so any variables you've exported in your user session don't carry over. The fix is `sudo -E` which preserves the calling user's environment. I now use that in `ensure_root` whenever the script re-execs itself.

**`set -Eeuo pipefail` — strict mode**

I added this to `main.sh` to catch common bash mistakes:
- `-e` exits immediately if any command returns non-zero
- `-E` makes that work inside functions too
- `-u` errors on unset variables
- `-o pipefail` catches failures in the middle of a pipeline, not just the last command

The important thing I learned: this goes in `main.sh` only, not in the lib modules. If you put it in every file you source, you get confusing interactions. The strict mode from `main.sh` propagates into sourced functions anyway.

**`flock`-based file locking**

The TCP scanning phase runs multiple nmap processes in parallel subshells, and each one needs to write to shared output files (like `22-tcp.txt` which lists every IP with port 22 open). Without locking, two subshells can write at the same time and corrupt the file or write duplicate lines.

`append_unique_locked` solves this by opening a `.lock` file alongside the target file and acquiring an exclusive `flock` before writing. The other subshells block until the lock is released. This is why you'll see `.lock` files appearing alongside the output files during a scan — they're just the lock mechanism, not data files, and they're harmless to leave around.

```bash
append_unique_locked() {
  local text="$1" file="$2" lock="${file}.lock"
  (
    exec 200>"$lock"
    flock -x 200
    touch "$file"
    grep -Fxq "$text" "$file" || echo "$text" >> "$file"
  )
}
```


| Stage | What I built |
|---|---|
| [Penetration Tool Creation – Without Keys ](https://github.com/MichaelNolan80/Network-Scanning-Tool) | Custom tool development for penetration testing |
| [Stage-2-scanning](https://github.com/MichaelNolan80/Network-Scanning-Tool/blob/main/Bash-Tool/Stage-2-Network-Scanning/readme.md) | Host discovery, TCP + OS scanning, port index files |
| [Back to the home page](https://github.com/MichaelNolan80/MichaelNolan80) | Home page |
