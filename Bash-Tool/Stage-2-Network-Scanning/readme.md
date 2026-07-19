# Stage 2 — Network Scanning

## What I was trying to do

With the foundation in place I could start building the actual scanning logic. I wanted the tool to take a CIDR range, find every live host, determine what services were running and at what versions, and detect the operating system — all automatically, and fast enough to be practical on a real network.

I also wanted the output to be structured in a way that later stages could use without re-scanning. Rather than storing everything in one big file, I decided to write the scan results into a folder hierarchy per host, and to build a set of index files (one per open port) that would make the brute-force stage much faster later on.

## What I built

**`lib/scan.sh`** — the full scanning pipeline:

- `discover_hosts` — runs `nmap -sn` (ping scan only, no port scan) to find live IPs and writes them to `devices.txt`
- `scan_fast_host` — runs `nmap -sS -sV` per host (SYN scan + version detection), writing results in both human-readable and XML formats
- `scan_os_host` — runs `nmap -O` for OS detection, serialised rather than parallel
- `get_os_guess_from_nmap` — parses nmap's OS output, trying three different fields in order of confidence
- `write_summary` — combines OS, MAC/vendor, and open port data into a single `summary.txt` per host
- `scan_target` — orchestrates all of the above for a given target range

## Key decisions and what I learned

**Out of Scope**

I wanted to make sure that any IP addresses that had been identified as out of scope and are not to be part of the test would not be included. So for this after the ip addresses or ranges are given it then asks for the ip addresses to be excluded from the test. 

**Adaptive timing**

I didn't want to hardcode `-T4` (nmap's aggressive timing) because on slower networks or over VPN it causes false negatives — hosts that are up get missed because nmap gives up waiting too quickly. But I also didn't want to always use `-T2` because that makes scans very slow on fast local networks.

The solution: before scanning, ping `.1` of the target subnet and measure the average RTT. Under 30ms → `-T4`, under 80ms → `-T3`, otherwise `-T2`. This adapts automatically to the network speed.

Importantly, the aggressive timing only applies to discovery, MAC/vendor, and TCP scans. OS detection (`-O`) always runs without `-T4` because OS fingerprinting probes are sensitive to timing — pushing them too fast causes unreliable results.

**Port index files**

As each host is scanned, I extract the open port numbers and append the host's IP to a shared file named after the port — `22-tcp.txt`, `445-tcp.txt`, and so on. These files contain one IP per line.

When I got to building the brute-force stage, this decision paid off. Instead of iterating host by host and checking which ports each one has open, I could just open `22-tcp.txt` and immediately have the complete list of SSH targets to pass to Hydra. One file, one lookup, no re-scanning.

**Parallel TCP scans with a worker throttle**

Running nmap on one host at a time would be very slow on a large subnet. I run the TCP scans in parallel background subshells, but with a cap (`TCP_WORKERS`, default 6) on how many run at once. Without the cap, launching 254 nmap processes simultaneously would overwhelm both the machine and the network switch.

```bash
for ip in "${ip_list[@]}"; do
  ( scan_fast_host "$ip" ... ) &
  while (( "$(jobs -r -p | wc -l)" >= tcp_workers )); do
    sleep 1
  done
done
wait
```

**The stdin-consumption bug — a nasty one**

This took me a while to track down. The script was stopping after scanning only the first subnet, even though I'd given it multiple targets. No error, no crash — it just... stopped.

The root cause was that I was iterating targets with `while read ... done < "$targets_file"`. Inside that loop, I call `scan_target`, which calls `nmap`, `ping`, and eventually `curl`. All of these inherit the loop's stdin by default. So when the first `nmap` ran, it consumed all the remaining lines from `targets_file` — leaving nothing for the loop to read on subsequent iterations.

The fix has two parts:
1. Read targets into a bash array before the loop, then iterate with `for`. This way the loop has no stdin file descriptor to leak.
2. Add `</dev/null` to every external command (`nmap`, `curl`, `ping`, `hydra`) as a second layer of defence.

```bash
# Wrong — external commands eat the loop's stdin:
while IFS= read -r target; do
  scan_target "$target"   # nmap inside here reads from $targets_file stdin!
done < "$targets_file"

# Right — array iteration has no stdin to leak:
mapfile -t target_list < "$targets_file"
for target in "${target_list[@]}"; do
  scan_target "$target" </dev/null
done
```

This same bug existed inside `scan_target` itself for the per-host loops, so I fixed it there too.

**`set -e` stopping the whole script when a subnet was empty**

Another bug: if a subnet had no live hosts, `nmap` would exit with a non-zero code, `set -e` would catch it, and the entire script would die silently. Every subsequent target would be skipped.

The fix is two things:
- Add `|| true` to every nmap call so a non-zero exit doesn't propagate
- Wrap the `scan_target` call in `if ... then ... else` — bash explicitly exempts commands in an `if` condition from `set -e`

```bash
if scan_target ... </dev/null; then
  ui_ok "Completed: ${target}"
else
  ui_warn "No results for ${target}. Continuing."
fi
```

Now an empty or unreachable subnet prints a warning and the loop moves on to the next target.

## Output structure at this stage

```
2026-06-18_myproject/
├── targets.txt
├── exclude.txt
├── 22-tcp.txt          ← all IPs with SSH open
├── 80-tcp.txt          ← all IPs with HTTP open
├── OS_Linux.txt        ← IPs grouped by OS
└── 10.0.0.0__24/
    ├── network_devices/
    │   └── devices.txt
    └── hosts/
        └── 10.0.0.5/
            ├── tcp_scan.txt
            ├── tcp_scan.xml
            ├── os_scan.txt
            ├── mac_vendor.txt
            └── summary.txt
```

---
| Page Jumper | What I built |
|---|---|
| [Back to Penetration Tool Creation Main Page](https://github.com/MichaelNolan80/Network-Scanning-Tool) | Custom tool development for penetration testing |
| [Back to Without Keys - Stage-1-foundation](https://github.com/MichaelNolan80/Network-Scanning-Tool/tree/main/Bash-Tool/Stage-1-foundation) | Project scaffold, UI module, shared utilities |
| [Without Keys - Stage-3-vulnerability](https://github.com/MichaelNolan80/Network-Scanning-Tool/tree/main/Bash-Tool/Stage-3-Vulnerability-Lookup) | NVD API integration, CVE reporting |
| [Back to the home page](https://github.com/MichaelNolan80/MichaelNolan80) | Home page |

