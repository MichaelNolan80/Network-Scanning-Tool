# Stage 4 — Credential Brute-Force

## Changelog

| Date | Change |
|---|---|
| July 2026 | Added two-phase brute-force — Phase 1 tries hardcoded default credentials per service before falling back to wordlist attack |
| June 2026 | Initial build — Hydra multi-target brute-force using port index files |

## What I was trying to do
...

## What I was trying to do

The scanning and CVE lookup phases tell me what's running and whether it's known to be vulnerable. The brute-force phase goes one step further and tests whether any of those services have weak credentials. I wanted this to be automatic — read the scan output, figure out what services are running where, and attack them — rather than manually specifying targets each time.

I also wanted to think carefully about efficiency. Brute-forcing is slow by nature (especially against services that delay on failed login), so the design of how targets are organised matters a lot.

## What I built

**`lib/brute.sh`** — Hydra orchestration using port index files:

- `_default_creds_for_service` — returns hardcoded default credentials for a given service
- `_collect_targets_for_service` — reads all port index files for a service and merges their IPs into a deduplicated temp file
- `_run_hydra_defaults` — Phase 1: runs Hydra with `-C` against the hardcoded default credential list
- `_run_hydra_wordlist` — Phase 2: runs Hydra with `-L`/`-P` against user-supplied wordlists
- `run_brute_scan` — orchestrates both phases per service, records results in the summary
- `append_brute_to_summaries` — after brute-forcing completes, appends any found credentials to each host's `summary.txt`

## Supported services

SSH, FTP, Telnet, SMB (139 + 445), RDP, HTTP/HTTPS Basic Auth, MySQL, PostgreSQL, VNC, Redis, SMTP, POP3, IMAP.

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

**Adding a default credentials phase**

After getting the wordlist attack working I started thinking about the order of operations. In real environments, a surprising number of devices still have factory default credentials — routers, network switches, IoT devices, database servers installed with default accounts. Running a full wordlist against those is overkill and slow when `admin:admin` would have worked in the first attempt.

So I added a two-phase approach:

- **Phase 1** always runs first, regardless of whether wordlists are provided. It tries a hardcoded set of well-known default credentials for each service using Hydra's `-C` flag, which accepts `username:password` pairs directly from a file. This is fast — typically done in seconds — and catches the low-hanging fruit immediately.
- **Phase 2** runs after if wordlists were provided. This is the full `-L`/`-P` brute-force for anything that didn't fall to defaults.

The credentials are hardcoded directly into `brute.sh` as a `case` statement in `_default_creds_for_service`, one block per service. I chose hardcoding over an external file because it keeps the tool completely self-contained — there are no extra files to manage, lose, or forget to include, and the defaults aren't going to change. Separating data from code made sense for user wordlists (which change every run) but not for a fixed reference list.

The credential sets are sourced from vendor documentation, publicly disclosed CVEs, and widely-published default credential databases. For example:
- SSH includes `pi:raspberry` (Raspberry Pi), `ubnt:ubnt` (Ubiquiti), `root:alpine` (Alpine Linux)
- Telnet includes `cisco:cisco` and `enable:enable` (Cisco IOS)
- MySQL includes a blank root password and `debian-sys-maint` (Debian/Ubuntu default installer accounts)
- Redis uses a blank password by default in older versions, so the first entry is `:`

The result is that Phase 1 covers the "should never have been deployed this way" category, and Phase 2 covers everything else. The `brute_summary.txt` reports both phases separately so it's clear which phase found anything.

**Letting the user choose which services to attack**

An earlier version attacked every service found in the scan automatically. I changed this to a numbered menu at startup where the user picks which services to target. The reasons:

- Brute-forcing every service indiscriminately is noisy and risks triggering account lockouts, especially on SMB and RDP which often have domain lockout policies
- In an authorised test you often have a specific scope — you might be testing SSH hardening but not want to touch the database
- It makes the tool more deliberate and professional

The selection is recorded in `brute_summary.txt` so there's a clear record of exactly what was tested in each run.

**Writing credentials back to host summaries**

After brute-forcing completes, I wanted the findings to appear in each host's `summary.txt` alongside the scan and CVE data — so there's one place to look for everything about a host, rather than having to cross-reference multiple output files.

Hydra's found-credential lines contain the host IP:
```
[22][ssh] host: 10.0.0.5   login: admin   password: password123
```

`append_brute_to_summaries` reads every `*_found.txt` file, extracts the IP from each credential line, finds that host's `summary.txt` in the folder structure, and appends the credentials under a new section.

**Asking for wordlists and service selection at the start**

All user inputs — project name, NVD API key, wordlist paths, and service selection — are collected upfront before any scanning begins. Phase 1 (default credentials) runs even if no wordlists are provided, so the tool is still useful for a quick default-credential sweep without needing wordlists ready.

## Output

```
Brute/
├── brute_summary.txt              ← both phases, all services, all results
├── ssh_defaults_found.txt         ← Phase 1 Hydra output for SSH
├── ssh_wordlist_found.txt         ← Phase 2 Hydra output for SSH
└── smb_defaults_found.txt         ← Phase 1 Hydra output for SMB
```

The summary clearly distinguishes what each phase found:

```
--- ssh (port 22) ---
Targets : 4

  [ Phase 1 — Default Credentials ]
  Status : FOUND
  [22][ssh] host: 10.0.0.5   login: pi   password: raspberry

  [ Phase 2 — Wordlist ]
  Status : Nothing found
```

And in each host's `summary.txt`:

```
=== Brute-Force Credentials Found ===
[22][ssh] host: 10.0.0.5   login: pi   password: raspberry
```

## Things to think about for stage 5

- Add a delay/jitter between attempts to avoid account lockouts on services that have lockout policies
- Add a check for whether a service is actually accepting connections before launching a full brute-force (a quick banner grab)
- Let the user configure `BRUTE_TASKS` and `BRUTE_TIMEOUT` interactively rather than just via environment variables

---

| Page Jumper | What I built |
|---|---|
| [Back to Penetration Tool Creation Main Page](https://github.com/MichaelNolan80/Network-Scanning-Tool) | Custom tool development for penetration testing |
| [Back to Without Keys - Stage-3-vulnerability](https://github.com/MichaelNolan80/Network-Scanning-Tool/tree/main/Bash-Tool/Stage-3-Vulnerability-Lookup) | NVD API integration, CVE reporting |
| [Without Keys - Scripts for this project](https://github.com/MichaelNolan80/Network-Scanning-Tool/tree/main/Bash-Tool/scripts/main.md) | All the code |
| [Back to the home page](https://github.com/MichaelNolan80/MichaelNolan80) | Home page |
