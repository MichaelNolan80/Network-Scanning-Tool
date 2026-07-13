# Stage 4 — Credential Brute-Force

## What I was trying to do

The scanning and CVE lookup phases tell me what's running and whether it's known to be vulnerable. The brute-force phase goes one step further and tests whether any of those services have weak credentials. I wanted this to be automatic — read the scan output, figure out what services are running where, and attack them — rather than manually specifying targets each time.

I also wanted to think carefully about efficiency. Brute-forcing is slow by nature (especially against services that delay on failed login), so the design of how targets are organised matters a lot.

## What I built

**`lib/brute.sh`** — Hydra orchestration using port index files:

- `_port_to_service` — maps a port number to the Hydra service name (e.g. 22 → ssh, 445 → smb)
- `_collect_targets_for_service` — reads all port index files for a given service and merges their IPs into a deduplicated temp file
- `_run_hydra_multi` — runs Hydra in multi-target mode (`-M`) against the combined IP list for a service
- `run_brute_scan` — iterates over every service that has at least one target and runs one Hydra job per service
- `append_brute_to_summaries` — after brute-forcing completes, finds any credentials that were discovered and appends them to the relevant host's `summary.txt`

## Supported services

SSH, FTP, Telnet, SMB (139 + 445), RDP, HTTP/HTTPS Basic Auth, MySQL, PostgreSQL, VNC, Redis.

## Key decisions and what I learned

**Using port index files instead of scanning host by host**

My first version of the brute module iterated over each host, opened its `tcp_scan.txt`, found the open ports, and launched a Hydra process per port per host. On a subnet with 20 hosts all running SSH, that meant 20 separate Hydra processes, each loading the wordlist from disk, each establishing their own connection pool.

Then I realised I'd already built exactly what I needed in stage 2: the port index files. `22-tcp.txt` already contains every IP with SSH open, one per line. Hydra has a `-M` flag that accepts a file of target IPs and attacks them all within a single process.

So instead of 20 Hydra processes for SSH, I run one:

```bash
hydra -L users.txt -P passwords.txt -M 22-tcp.txt -s 22 ssh
```

That's one wordlist load, one process, all targets handled in parallel internally by Hydra. For SMB specifically, both `139-tcp.txt` and `445-tcp.txt` get merged and deduplicated before being passed to Hydra so no host gets hit twice.

This architectural decision — building the index files during scanning specifically so brute-forcing can use them — was something I worked out before writing any of the brute-force code. Getting the data structure right upfront made the implementation much simpler.

**Writing credentials back to host summaries**

After brute-forcing completes, I wanted the findings to appear in each host's `summary.txt` alongside the scan and CVE data — so there's one place to look for everything about a host, rather than having to cross-reference multiple output files.

Hydra's found-credential lines contain the host IP:
```
[22][ssh] host: 10.0.0.5   login: admin   password: password123
```

`append_brute_to_summaries` reads every `*_found.txt` file, extracts the IP from each credential line, finds that host's `summary.txt` in the folder structure, and appends the credentials under a new section. I tested this with a simulated Hydra output file before running it for real, to make sure the parsing was correct.

**Asking for wordlists at the start**

Originally the brute-force wordlist prompts came at the end of the setup section, just before scanning started. That meant the tool asked for:
1. Project name
2. Targets
3. Excludes
4. NVD API key
5. Wordlists (much later)

I moved the wordlists prompt to the beginning, right after the project name, so all user inputs are collected upfront before any scanning starts. That way you set everything at the start and then walk away — you don't have to come back later to answer more questions.

**Skipping brute-force gracefully**

If you press Enter when asked for a username list, the brute-force phase is skipped entirely. The scanning and CVE lookup still run normally. This means the tool is still useful for reconnaissance-only runs without having to comment anything out or use flags.

## Output

```
Brute/
├── brute_summary.txt          ← all services, targets, and results
├── ssh_found.txt              ← raw Hydra output for SSH
└── smb_found.txt              ← raw Hydra output for SMB
```

And in each host's summary:

```
=== Brute-Force Credentials Found ===
[22][ssh] host: 10.0.0.5   login: admin   password: password123
```

## Things to think about for stage 5

- Add a delay/jitter between attempts to avoid account lockouts on services that have lockout policies
- Add a check for whether a service is actually accepting connections before launching a full brute-force (a quick banner grab)
- Let the user configure `BRUTE_TASKS` and `BRUTE_TIMEOUT` interactively rather than just via environment variables
