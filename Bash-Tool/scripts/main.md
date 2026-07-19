# Files

Here are the code for the program- 

<img width="907" height="415" alt="image" src="https://github.com/user-attachments/assets/dc808e9b-86fc-46bb-9466-a3eb25e943b6" />

network-scan/
├── main.sh
└── lib/
    ├── ui.sh
    ├── utils.sh
    ├── scan.sh
    ├── vuln
    └── brute

| File | Description |
|---|---|
| [`main.sh`](https://github.com/MichaelNolan80/Network-Scanning-Tool/blob/main/Bash-Tool/scripts/main.sh) | Orchestrator — collects input, drives the workflow |
| [`lib/ui.sh`](https://github.com/MichaelNolan80/Network-Scanning-Tool/blob/main/Bash-Tool/scripts/lib/ui.sh) | Terminal output, banners, formatting |
| [`lib/utils.sh`](https://github.com/MichaelNolan80/Network-Scanning-Tool/blob/main/Bash-Tool/scripts/lib/utils.sh) | Shared helpers, safe concurrent file writes (`flock`) |
| [`lib/scan.sh`](https://github.com/MichaelNolan80/Network-Scanning-Tool/blob/main/Bash-Tool/scripts/lib/scan.sh) | `nmap`-based host discovery and service fingerprinting |
| [`lib/vuln.sh`](https://github.com/MichaelNolan80/Network-Scanning-Tool/blob/main/Bash-Tool/scripts/lib/vuln.sh) | NVD API v2 CVE lookups |
| [`lib/brute.sh`](https://github.com/MichaelNolan80/Network-Scanning-Tool/blob/main/Bash-Tool/scripts/lib/brute.sh) | Hydra-based credential brute-forcing |
