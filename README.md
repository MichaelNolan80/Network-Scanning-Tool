# Network-Scanning-Tool
This is my network scanning tool project that im calling Without-Keys.

# Without Keys

A bash-based network scanning and penetration testing toolkit I built from scratch while learning cybersecurity. The goal was to understand how professional tools work under the hood by building my own version — rather than just running existing tools without knowing what they're actually doing.

The tool automates a full reconnaissance-to-exploitation workflow: host discovery, service fingerprinting, OS detection, CVE lookup against the National Vulnerability Database, and credential brute-forcing. It's designed for use in **authorised environments and personal home labs only**.

---

## Why I building it

I wanted a project that would teach me real cybersecurity concepts hands-on, and that I could actually use in my work (where I'm authorised to test) and in my home lab. Rather than using a GUI tool like Nessus or Metasploit as a black box, I wanted to understand each phase of a pentest by building the tooling myself in bash — something I already knew — and layering in specialist tools like nmap and Hydra as I learned what they do.

---

## What it does

Given one or more target IP ranges, the tool will:

1. Discover which hosts are live on the network
2. Fingerprint open TCP ports and running service versions
3. Detect the operating system of each host
4. Query the NVD API for known CVEs matching detected software versions
5. Brute-force credentials against discovered services using provided wordlists
6. Produce per-host reports combining all findings in one file

---

## How it's structured

The project is a modular bash suite. A single orchestrator (`main.sh`) sources five library modules. I built it this way so each concern is isolated and the project could grow without becoming one enormous script.

| File | Role |
|---|---|
| `lib/ui.sh` | Colour output, banners, progress indicators |
| `lib/utils.sh` | Shared helpers — file locking, root elevation, input sanitisation |
| `lib/scan.sh` | Host discovery, TCP version scan, OS detection |
| `lib/vuln.sh` | NVD API v2 CVE lookup |
| `lib/brute.sh` | Hydra-based credential brute-forcing |

---

## Dependencies

| Tool | Purpose |
|---|---|
| `nmap` | Host discovery, TCP scanning, OS detection |
| `hydra` | Credential brute-forcing |
| `curl` | NVD API requests |
| `flock` | Safe concurrent file writes |
| `awk`, `grep`, `sed` | Output parsing — no `jq` needed |

---

## Project stages

I built this incrementally, solving real problems as they came up. Each stage folder contains the files as they existed at that point so you can follow the progression:

| Stage | What I built |
|---|---|
| [Stage-1-foundation](Bash-Tool/Stage-1-foundation/readme.md) | Project scaffold, UI module, shared utilities |
| [Stage-2-scanning](Bash-Tool/Stage-2-Network-Scanning/readme.md) | Host discovery, TCP + OS scanning, port index files |
| [Stage-3-vulnerability](Bash-Tool/Stage-3-Vulnerability-Lookup/readme.md) | NVD API integration, CVE reporting |
| [Stage-4-bruteforce](Bash-Tool/Stage-4-Credential-Brute-Force/readme.md) | Hydra brute-force, credential reporting, host summary integration |
| [Without Keys - Scripts for this project](https://github.com/MichaelNolan80/Network-Scanning-Tool/tree/main/Bash-Tool/scripts/main.md) | All the code |

---

## Usage

```bash
apt install nmap hydra curl seclists

# Optional: NVD API key for higher rate limits (free)
# https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY=your-key-here

sudo -E ./main.sh
```

---

## Legal notice

This tool is for use only on networks and systems you own or have **explicit written authorisation** to test. Unauthorised use against third-party systems is illegal under the Computer Misuse Act (UK) and equivalent legislation elsewhere.

---

| Page Jumper | What I built |
|---|---|
| [Without Keys - Stage-1-foundation](Bash-Tool/Stage-1-foundation/readme.md) | Project scaffold, UI module, shared utilities |
| [Back to the home page](https://github.com/MichaelNolan80/MichaelNolan80) | Home page |

---
