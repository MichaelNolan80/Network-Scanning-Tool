# Files

Here are the code for the program- 

<img width="907" height="415" alt="image" src="https://github.com/user-attachments/assets/dc808e9b-86fc-46bb-9466-a3eb25e943b6" />


| File | Description |
|---|---|
| `main.sh` | Orchestrator — collects input, drives the workflow |
| `lib/ui.sh` | Terminal output, banners, formatting |
| `lib/utils.sh` | Shared helpers, safe concurrent file writes (`flock`) |
| `lib/scan.sh` | `nmap`-based host discovery and service fingerprinting |
| `lib/vuln.sh` | NVD API v2 CVE lookups |
| `lib/brute.sh` | Hydra-based credential brute-forcing |
