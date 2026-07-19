# Files

Here are the code for the program- 

<img width="907" height="415" alt="image" src="https://github.com/user-attachments/assets/dc808e9b-86fc-46bb-9466-a3eb25e943b6" />

<img width="138" height="166" alt="image" src="https://github.com/user-attachments/assets/f425af06-11ae-4a3d-ac86-be4cd07b95df" />


| File | Description |
|---|---|
| [`main.sh`](https://github.com/MichaelNolan80/Network-Scanning-Tool/blob/main/Bash-Tool/scripts/main.sh) | Orchestrator — collects input, drives the workflow |
| [`lib/ui.sh`](https://github.com/MichaelNolan80/Network-Scanning-Tool/blob/main/Bash-Tool/scripts/lib/ui.sh) | Terminal output, banners, formatting |
| [`lib/utils.sh`](https://github.com/MichaelNolan80/Network-Scanning-Tool/blob/main/Bash-Tool/scripts/lib/utils.sh) | Shared helpers, safe concurrent file writes (`flock`) |
| [`lib/scan.sh`](https://github.com/MichaelNolan80/Network-Scanning-Tool/blob/main/Bash-Tool/scripts/lib/scan.sh) | `nmap`-based host discovery and service fingerprinting |
| [`lib/vuln.sh`](https://github.com/MichaelNolan80/Network-Scanning-Tool/blob/main/Bash-Tool/scripts/lib/vuln.sh) | NVD API v2 CVE lookups |
| [`lib/brute.sh`](https://github.com/MichaelNolan80/Network-Scanning-Tool/blob/main/Bash-Tool/scripts/lib/brute.sh) | Hydra-based credential brute-forcing |


---
| Page Jumper | What I built |
|---|---|
| [Penetration Tool Creation – Without Keys ](https://github.com/MichaelNolan80/Network-Scanning-Tool) | Custom tool development for penetration testing |
| [Without Keys - Stage-1-foundation](https://github.com/MichaelNolan80/Network-Scanning-Tool/tree/main/Bash-Tool/Stage-1-foundation) | Project scaffold, UI module, shared utilities |
| [Without Keys - Stage-2-scanning](https://github.com/MichaelNolan80/Network-Scanning-Tool/blob/main/Bash-Tool/Stage-2-Network-Scanning/readme.md) | Host discovery, TCP + OS scanning, port index files |
| [Without Keys - Stage-3-vulnerability](https://github.com/MichaelNolan80/Network-Scanning-Tool/tree/main/Bash-Tool/Stage-3-Vulnerability-Lookup) | NVD API integration, CVE reporting |
| [Without Keys - Stage-4-bruteforce](https://github.com/MichaelNolan80/Network-Scanning-Tool/tree/main/Bash-Tool/Stage-4-Credential-Brute-Force) | Hydra brute-force, credential reporting, host summary integration |
| [Back to the home page](https://github.com/MichaelNolan80/MichaelNolan80) | Home page |
