# Domain OSINT Recon Automation

A Bash-based workflow for collecting external domain intelligence, building a hostname inventory, and (only after manual scope review and an explicit confirmation) performing low-rate HTTP and TLS verification.

> **Authorization required:** Use this tool only for domains and hostnames that you own or are explicitly authorized to assess. Passive discovery does not establish permission to test a discovered asset. The generated `authorized/authorized_hosts.txt` file is a **review/staging list**, not proof of authorization.

## Features

- Accepts domains interactively, as a comma-separated argument, or from a `.txt` file.
- Validates and normalizes supplied DNS domain names.
- Runs Subfinder passive subdomain discovery.
- Copies `subfinder.txt` to `authorized/authorized_hosts.txt` for manual review, as requested.
- Optionally collects additional intelligence using Amass, Certificate Transparency (`crt.sh`), DNS queries, `dnsx`, WHOIS, and `gau`.
- Merges and filters discovered hostnames so candidates remain beneath the supplied root domains.
- Can perform low-rate HTTP inventory, response-header collection, and TLS certificate inspection after manual review and an authorization confirmation.
- Records tool availability, run metadata, logs, a report template, and SHA-256 checksums.

## Repository contents

```text
.
├── osint_recon.sh       # Main automation script
└── README.md
```

The script creates a timestamped results directory in the **current working directory** for each run.

## Requirements

### Required

- Linux or another Unix-like environment with Bash.
- Python 3.
- ProjectDiscovery [Subfinder](https://github.com/projectdiscovery/subfinder).

The script stops if Python 3 or Subfinder is missing.

### Optional tools

The workflow detects these tools and skips the corresponding collection step when they are unavailable:

| Tool | Purpose |
|---|---|
| [Amass](https://github.com/owasp-amass/amass) | Additional passive enumeration |
| `curl` and `jq` | Certificate Transparency lookup through `crt.sh`; `curl` is also used for response headers |
| `dig` | DNS, email-security, and DNSSEC record queries |
| [dnsx](https://github.com/projectdiscovery/dnsx) | Resolve discovered candidates and collect A, AAAA, and CNAME data |
| `whois` | Registration information for supplied root domains |
| [gau](https://github.com/lc/gau) | Historical URLs from public sources |
| [ProjectDiscovery httpx](https://github.com/projectdiscovery/httpx) or `httpx-toolkit` | Low-rate HTTP asset verification |
| `openssl` | TLS certificate details |
| `sha256sum` | Evidence checksums |

Common supporting utilities such as `grep`, `sed`, `sort`, `awk`, `find`, `tee`, `xargs`, and `timeout` may also be used when available.

### Example installation on Debian / Ubuntu / Kali

Install the common system dependencies:

```bash
sudo apt update
sudo apt install -y python3 curl jq dnsutils whois openssl coreutils util-linux
```

Install Subfinder and the optional ProjectDiscovery tools using their official installation instructions. Tool installation methods and package availability can change, so use the upstream documentation linked above. `gau` and Amass are optional.

Check the required tools:

```bash
bash --version
python3 --version
subfinder -version
```

## Installation

Clone the repository:

```bash
git clone <REPOSITORY_URL>
cd <REPOSITORY_DIRECTORY>
```

Make the script executable:

```bash
chmod +x osint_recon.sh
```

## Usage

### 1. Interactive input

Run the script without arguments:

```bash
./osint_recon.sh
```

At the prompt, enter domains separated by commas:

```text
citybankplc.com,thecitybank.com,citytouch.com.bd,citygem.com.bd
```

### 2. Comma-separated argument

```bash
./osint_recon.sh "citybankplc.com,thecitybank.com,citytouch.com.bd,citygem.com.bd,citybrokerageltd.com,cbcrl.com,cblmoneytransfer.com,cityhongkong.com.hk,citycorp.com.bd,cb.bd,cbl.fyi,citytouch.bd,icitytouch.com.bd"
```

Quote the list so the shell passes it as one argument.

### 3. Input from a text file

Create `domains.txt` with one domain per line:

```text
citybankplc.com
thecitybank.com
citytouch.com.bd
citygem.com.bd
citybrokerageltd.com
cbcrl.com
cblmoneytransfer.com
cityhongkong.com.hk
citycorp.com.bd
cb.bd
cbl.fyi
citytouch.bd
icitytouch.com.bd
```

Then run:

```bash
./osint_recon.sh domains.txt
```

The input parser also accepts comma-separated entries in a text file. Blank lines and lines beginning with `#` are ignored; inline comments after `#` are also removed.

### 4. Passive collection only

To skip all HTTP and TLS requests:

```bash
./osint_recon.sh --passive-only domains.txt
```

The same option works with comma-separated input:

```bash
./osint_recon.sh --passive-only "example.com,example.org"
```

### 5. Help

```bash
./osint_recon.sh --help
```

## Input format and scope handling

Provide bare DNS domain names only. Do **not** include a scheme, URL path, port, wildcard, or IP address.

Valid examples:

```text
example.com
example.com,example.org
api.example.com
```

Invalid examples:

```text
https://example.com
example.com/login
*.example.com
example.com:8443
192.0.2.10
```

Each supplied domain is treated as a scope root. A discovered hostname is retained as a candidate only when it is the supplied root itself or ends in `.<supplied-root>`.

Only enter root domains that are included in your approved assessment scope. If an organization has subsidiaries, hosted services, vendors, or other third-party infrastructure, do not assume those assets are authorized just because they appear in discovery results.

## Workflow

The script runs the following collection stages:

1. **Input validation:** normalizes domains to lowercase, removes trailing dots, rejects malformed input, and deduplicates entries.
2. **Subfinder:** runs passive enumeration against the supplied roots and saves results to `subfinder.txt` and `passive/subfinder.txt`.
3. **Authorization staging copy:** copies `subfinder.txt` to `authorized/authorized_hosts.txt` for manual review. This copy is intentional, but does not mean the listed hosts have been authorized.
4. **Amass (optional):** performs passive enumeration when Amass is installed.
5. **Certificate Transparency (optional):** queries `crt.sh` for certificate names when both `curl` and `jq` are installed.
6. **Candidate processing:** merges root, Subfinder, Amass, and Certificate Transparency results, then filters candidates to the supplied roots.
7. **DNS and registration information:** queries root-domain DNS and email-security records; optionally resolves candidates with `dnsx` and queries WHOIS for the supplied roots.
8. **Historical URLs (optional):** uses `gau` to collect URLs indexed by public sources and extracts a small set of potentially relevant URL patterns.
9. **Optional HTTP/TLS verification:** only after manual review and an explicit confirmation, uses httpx, curl, and OpenSSL against the reviewed host list.
10. **Reporting:** writes a run summary, tool inventory, report template, log, and evidence checksums.

### HTTP/TLS verification safeguards

Unless `--passive-only` is used, the script may offer an active verification stage when it has an interactive terminal. Before proceeding, it:

- Opens `authorized/authorized_hosts.txt` in the configured `$EDITOR`, `nano`, or `vi` when available (otherwise it prints the file for manual review).
- Checks that each listed hostname is syntactically valid and belongs beneath one of the supplied roots.
- Requires the operator to type the exact word `AUTHORIZED`.
- Runs HTTP verification with a configured limit of **2 requests per second**, **2 threads**, and a **10-second timeout**.
- Collects HTTPS response headers and TLS certificate metadata at a low rate.

If there is no interactive terminal, validation fails, or the confirmation phrase is not entered exactly, HTTP/TLS checks are skipped.

**Important:** The script can verify that a hostname is beneath a supplied root, but it cannot determine whether the hostname is covered by your written authorization. Confirm every hostname against the approved scope document before entering `AUTHORIZED`. The confirmation prompt is an operational safeguard, not a substitute for permission.

## Output structure

Each run creates a directory similar to:

```text
osint-recon_20261109T010000Z/
├── roots.txt
├── subfinder.txt
├── candidates.txt
├── passive/
│   ├── subfinder.txt
│   ├── amass.txt
│   ├── crtsh.txt
│   ├── all-candidates-raw.txt
│   ├── archived-urls.txt
│   └── interesting-archived-urls.txt
├── dns/
│   ├── root-records.txt
│   ├── email-security.txt
│   ├── candidate-dns-records.txt
│   ├── whois-summary.txt
│   └── whois_<root-domain>.txt
├── authorized/
│   ├── authorized_hosts.txt
│   ├── web-assets.csv
│   ├── response-headers.txt
│   └── tls-certificates.txt
├── report/
│   ├── tool-inventory.txt
│   ├── run-summary.txt
│   ├── final-report-template.md
│   └── SHA256SUMS.txt
├── evidence/
└── logs/
    └── run.log
```

Some files are created only when the relevant optional tool is installed or the corresponding stage runs. The timestamp in the directory name is UTC.

### Key files

| File | Description |
|---|---|
| `roots.txt` | Normalized domains supplied by the operator |
| `subfinder.txt` | Subfinder output at the run-directory root |
| `passive/subfinder.txt` | Copy of Subfinder output under `passive/` |
| `candidates.txt` | Deduplicated, syntactically valid candidate hostnames filtered to the supplied roots |
| `authorized/authorized_hosts.txt` | Subfinder results copied for manual scope review; not an authorization record |
| `authorized/web-assets.csv` | HTTP inventory, when the active stage runs and httpx is available |
| `dns/` | DNS, email-security, candidate-resolution, and WHOIS results |
| `passive/archived-urls.txt` | URLs returned by `gau`, when installed |
| `report/run-summary.txt` | High-level run counts and status |
| `report/tool-inventory.txt` | Detected tool paths and available version output |
| `report/final-report-template.md` | Markdown template for documenting findings |
| `report/SHA256SUMS.txt` | SHA-256 hashes for collected files, when `sha256sum` is available |
| `logs/run.log` | Timestamped run log |

## Reporting guidance

Use `report/final-report-template.md` as the starting point for a formal assessment report. Before reporting an issue:

- Verify that the asset is in scope and the observation is reproducible.
- Separate confirmed findings from leads, inferred exposure, and unverified historical data.
- Record the hostname, observation date/time (UTC), collection method, evidence path, confidence, impact, and recommended remediation.
- Redact credentials, personal information, session tokens, internal addresses, and other sensitive information from evidence before sharing it.
- Avoid describing a technology fingerprint or an old archived URL as a vulnerability without independent validation.

## Limitations

This is an OSINT and basic asset-inventory workflow, not a comprehensive security assessment. It does **not** perform exploitation, vulnerability scanning, password attacks, directory brute forcing, port scanning, or authenticated testing. Public archive data may be incomplete or stale. Tool output depends on each tool's data sources, configuration, network connectivity, and any configured API keys.

DNS queries, WHOIS lookups, and requests to public services such as `crt.sh` and archive providers generate traffic to those services. Review organizational policy before running the workflow, even when using passive modes.

## Protecting results

Reconnaissance output can reveal an organization's external attack surface and should be treated as sensitive assessment material. Do not commit generated results, allowlists, logs, or raw evidence to a public repository.

Add entries like these to your repository's `.gitignore`:

```gitignore
osint-recon_*/
domains.txt
*.csv
```

Keep authorization records and findings in the approved location defined by your organization.

## Troubleshooting

**`python3 is required`**

Install Python 3 and confirm `python3` is in your `PATH`.

**`subfinder is required`**

Install ProjectDiscovery Subfinder and confirm `subfinder -version` works in the same shell.

**Optional tools are skipped**

Install the missing tool and rerun the script. Missing optional tools do not necessarily stop the workflow; the corresponding output file may be empty.

**No HTTP/TLS checks were performed**

The script skips active checks when `--passive-only` is set, when standard input is not an interactive terminal, when the allowlist is empty or invalid, or when the exact `AUTHORIZED` confirmation is not entered. Review the run log for details.

**No hostnames appear in `authorized_hosts.txt`**

Subfinder may not have returned results. Check `passive/subfinder.txt`, the Subfinder log output, network connectivity, and any provider/API configuration used by Subfinder.

## Responsible use

By using this project, you are responsible for ensuring that your activities comply with applicable laws, contracts, organizational policies, and written rules of engagement. Do not use it to enumerate or test domains outside your authorized scope.

---

## Disclaimer

This project is provided for lawful security research, defensive asset inventory, and authorized assessments only. It is provided **as is**, without warranty. The maintainers are not responsible for misuse, unauthorized activity, or any damage arising from use of the software.
