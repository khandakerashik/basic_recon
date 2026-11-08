#!/usr/bin/env bash
# Low-impact domain OSINT workflow.
# Passive discovery is automated. HTTP/TLS requests require an explicit scope confirmation.

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="${0##*/}"
PASSIVE_ONLY=0
INPUT_VALUE=""
INPUT_MODE=""

usage() {
  cat <<EOF
Usage:
  ./$SCRIPT_NAME
  ./$SCRIPT_NAME "example.com,example.org"
  ./$SCRIPT_NAME domains.txt
  ./$SCRIPT_NAME --passive-only "example.com,example.org"
  ./$SCRIPT_NAME --passive-only domains.txt

Input:
  - No argument: prompt for comma-separated domains or a .txt file path.
  - One argument: either a comma-separated domain list or a text-file path.
  - Text files may contain one domain per line or comma-separated entries.

Options:
  --passive-only   Skip HTTP/TLS checks, even if the operator confirms authorization.
  -h, --help       Show this help.

Output:
  Creates ./osint-recon_<UTC timestamp>/ with roots.txt, passive/, dns/,
  authorized/, report/, evidence/, and logs/.
EOF
}

log()  { printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }
warn() { printf '[%s] [WARN] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { printf '[%s] [ERROR] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; exit 1; }

# Parse flags and the optional single input argument.
while (($#)); do
  case "$1" in
    --passive-only) PASSIVE_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) die "Unknown option: $1 (see --help)" ;;
    *)
      [[ -z "$INPUT_VALUE" ]] || die "Provide only one input argument."
      INPUT_VALUE="$1"
      shift
      ;;
  esac
done
if (($#)); then
  [[ -z "$INPUT_VALUE" ]] || die "Provide only one input argument."
  INPUT_VALUE="$1"
  shift
fi
(($# == 0)) || die "Too many arguments."

if [[ -z "$INPUT_VALUE" ]]; then
  printf 'Enter domains (comma-separated) OR a .txt file path: '
  IFS= read -r INPUT_VALUE || die "No input received."
fi
[[ -n "${INPUT_VALUE//[[:space:]]/}" ]] || die "Input cannot be empty."

# Interpret the input as a file if that exact path exists; otherwise as comma-separated text.
if [[ -f "$INPUT_VALUE" ]]; then
  INPUT_MODE="file"
  INPUT_FILE="$INPUT_VALUE"
  [[ "$INPUT_FILE" = /* ]] || INPUT_FILE="$PWD/$INPUT_FILE"
else
  INPUT_MODE="string"
  INPUT_FILE="$INPUT_VALUE"
fi

command -v python3 >/dev/null 2>&1 || die "python3 is required for input validation and scope filtering."
command -v subfinder >/dev/null 2>&1 || die "subfinder is required. Install ProjectDiscovery Subfinder and ensure it is in PATH."

TMP_ROOTS="$(mktemp)"
cleanup() { rm -f "$TMP_ROOTS"; }
trap cleanup EXIT

# Split comma/newline/whitespace input, normalize and validate domains.
if ! python3 - "$INPUT_MODE" "$INPUT_FILE" > "$TMP_ROOTS" <<'PY'
import pathlib, re, sys
mode, value = sys.argv[1], sys.argv[2]
try:
    raw = pathlib.Path(value).read_text(encoding="utf-8", errors="replace") if mode == "file" else value
except OSError as exc:
    print(f"Cannot read input file: {exc}", file=sys.stderr)
    raise SystemExit(2)

seen = set()
invalid = []
for line_no, line in enumerate(raw.splitlines() or [raw], 1):
    line = line.split("#", 1)[0]
    for token in re.split(r"[\s,]+", line.strip()):
        if not token:
            continue
        domain = token.strip().lower().rstrip(".")
        # Accept DNS hostnames only: no scheme, URL path, wildcard, port or IP literal.
        labels = domain.split(".")
        valid = (
            len(domain) <= 253
            and len(labels) >= 2
            and all(1 <= len(label) <= 63 for label in labels)
            and re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain) is not None
        )
        if not valid:
            invalid.append((line_no, token))
        else:
            seen.add(domain)
if invalid:
    for line_no, token in invalid:
        print(f"Invalid domain on input line {line_no}: {token!r}", file=sys.stderr)
    raise SystemExit(2)
for domain in sorted(seen):
    print(domain)
PY
then
  die "Input validation failed. Use bare DNS domains (no https://, paths, ports or wildcards)."
fi

ROOT_COUNT="$(wc -l < "$TMP_ROOTS" | tr -d ' ')"
[[ "$ROOT_COUNT" -gt 0 ]] || die "No valid domains found in the input."

RUN_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTDIR="$PWD/osint-recon_${RUN_STAMP}"
mkdir -p "$OUTDIR"/{passive,dns,authorized,report,evidence,logs}
cp "$TMP_ROOTS" "$OUTDIR/roots.txt"
cd "$OUTDIR"
LOG_FILE="$OUTDIR/logs/run.log"
exec > >(tee -a "$LOG_FILE") 2>&1

log "Starting passive domain OSINT workflow."
log "Root domains: $ROOT_COUNT"
log "Output directory: $OUTDIR"
log "Scope roots saved to roots.txt"

# Record tool availability and versions for reproducibility.
{
  echo "Run started UTC: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo "Operator: ${USER:-unknown}"
  echo "Host: $(hostname 2>/dev/null || echo unknown)"
  echo ""
  for tool in subfinder amass dnsx gau dig curl jq whois httpx-toolkit httpx openssl sha256sum; do
    if command -v "$tool" >/dev/null 2>&1; then
      printf '%-16s %s\n' "$tool" "$(command -v "$tool")"
      case "$tool" in
        subfinder|amass|dnsx|gau|httpx-toolkit|httpx)
          "$tool" -version 2>&1 | head -n 1 || true
          ;;
      esac
    else
      printf '%-16s %s\n' "$tool" "NOT INSTALLED"
    fi
  done
} > report/tool-inventory.txt

# 1) Passive subdomain discovery with Subfinder.
log "[1/8] Running Subfinder passive discovery..."
: > subfinder.txt
if subfinder -dL roots.txt -all -silent -o subfinder.txt; then
  cp subfinder.txt passive/subfinder.txt
  log "Subfinder finished. Discovered $(wc -l < subfinder.txt | tr -d ' ') lines."
else
  cp subfinder.txt passive/subfinder.txt
  warn "Subfinder returned an error; continuing with any output it produced."
fi

# Required user-requested copy: this is a REVIEW/STAGING file, not proof of authorization.
cp subfinder.txt authorized/authorized_hosts.txt
log "Copied subfinder.txt to authorized/authorized_hosts.txt for manual scope review."

# 2) Optional passive Amass enumeration.
log "[2/8] Running Amass in passive mode (when installed)..."
: > passive/amass.txt
if command -v amass >/dev/null 2>&1; then
  if amass enum -passive -df roots.txt -o passive/amass.txt -timeout 10; then
    log "Amass finished."
  else
    warn "Amass returned an error; continuing."
  fi
else
  warn "Amass not installed; skipping."
fi

# 3) Certificate Transparency lookups.
log "[3/8] Collecting Certificate Transparency names from crt.sh (when curl+jq are installed)..."
: > passive/crtsh.txt
if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
  while IFS= read -r domain; do
    [[ -n "$domain" ]] || continue
    log "crt.sh query: $domain"
    { curl -fsS --retry 1 --connect-timeout 5 --max-time 25 \
        "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null \
        | jq -r '.[].name_value? // empty' 2>/dev/null \
        | tr '\r' '\n' \
        | sed 's/^\*\.//' \
        | tr '[:upper:]' '[:lower:]' \
        >> passive/crtsh.txt; } || warn "crt.sh lookup failed for $domain."
    sleep 0.5
  done < roots.txt
  sort -fu passive/crtsh.txt -o passive/crtsh.txt
else
  warn "curl and/or jq unavailable; skipping crt.sh collection."
fi

# 4) Merge discovery sources and strictly filter candidates to supplied root domains.
log "[4/8] Merging and scope-filtering candidate hostnames..."
cat roots.txt passive/subfinder.txt passive/amass.txt passive/crtsh.txt 2>/dev/null \
  | tr '[:upper:]' '[:lower:]' | sed 's/^\*\.//' | sed 's/\.$//' \
  | sort -fu > passive/all-candidates-raw.txt
python3 - roots.txt passive/all-candidates-raw.txt > candidates.txt <<'PY'
import pathlib, re, sys
roots = [x.strip().lower().rstrip('.') for x in pathlib.Path(sys.argv[1]).read_text().splitlines() if x.strip()]
raw = pathlib.Path(sys.argv[2]).read_text(errors="replace").splitlines()
valid_re = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
out = set()
for raw_host in raw:
    host = raw_host.strip().lower().removeprefix("*.").rstrip(".")
    if not valid_re.fullmatch(host):
        continue
    if any(host == root or host.endswith("." + root) for root in roots):
        out.add(host)
for host in sorted(out):
    print(host)
PY
log "Candidate inventory contains $(wc -l < candidates.txt | tr -d ' ') hostnames."

# 5) DNS records for each supplied root, using standard DNS queries only.
log "[5/8] Collecting root-domain DNS and email-security records..."
: > dns/root-records.txt
: > dns/email-security.txt
if command -v dig >/dev/null 2>&1; then
  while IFS= read -r domain; do
    [[ -n "$domain" ]] || continue
    {
      echo "===== $domain ====="
      for rr in A AAAA NS MX SOA TXT CAA; do
        echo "--- $rr ---"
        dig +time=2 +tries=1 +noall +answer "$domain" "$rr" 2>&1 || true
        sleep 0.1
      done
      echo "--- DS (DNSSEC) ---"
      dig +dnssec +time=2 +tries=1 +noall +answer "$domain" DS 2>&1 || true
      echo "--- DNSKEY (DNSSEC) ---"
      dig +dnssec +time=2 +tries=1 +noall +answer "$domain" DNSKEY 2>&1 || true
    } >> dns/root-records.txt
    {
      echo "===== $domain ====="
      echo "--- Root TXT / SPF candidate ---"
      dig +time=2 +tries=1 +short TXT "$domain" 2>&1 || true
      echo "--- DMARC ---"
      dig +time=2 +tries=1 +short TXT "_dmarc.$domain" 2>&1 || true
      echo "--- MTA-STS ---"
      dig +time=2 +tries=1 +short TXT "_mta-sts.$domain" 2>&1 || true
      echo "--- SMTP TLS reporting ---"
      dig +time=2 +tries=1 +short TXT "_smtp._tls.$domain" 2>&1 || true
    } >> dns/email-security.txt
    sleep 0.2
  done < roots.txt
else
  warn "dig not installed; skipping DNS record queries."
fi

# DNS resolution and CNAME mapping for discovered candidate names.
: > dns/candidate-dns-records.txt
if command -v dnsx >/dev/null 2>&1 && [[ -s candidates.txt ]]; then
  if dnsx -l candidates.txt -a -aaaa -cname -resp -rl 5 -silent \
      -o dns/candidate-dns-records.txt; then
    log "dnsx candidate resolution finished."
  else
    warn "dnsx returned an error; continuing."
  fi
else
  warn "dnsx unavailable or there are no candidates; skipping candidate DNS resolution."
fi

# WHOIS is queried only for the supplied root domains.
: > dns/whois-summary.txt
if command -v whois >/dev/null 2>&1; then
  while IFS= read -r domain; do
    [[ -n "$domain" ]] || continue
    safe_name="${domain//./_}"
    if command -v timeout >/dev/null 2>&1; then
      timeout 20 whois "$domain" > "dns/whois_${safe_name}.txt" 2>&1 || true
    else
      whois "$domain" > "dns/whois_${safe_name}.txt" 2>&1 || true
    fi
    printf '%s\t%s\n' "$domain" "dns/whois_${safe_name}.txt" >> dns/whois-summary.txt
    sleep 1
  done < roots.txt
else
  warn "whois not installed; skipping."
fi

# 6) Passive URL history from public archive/index sources.
log "[6/8] Collecting known historical URLs with gau (when installed)..."
: > passive/archived-urls.txt
: > passive/interesting-archived-urls.txt
if command -v gau >/dev/null 2>&1; then
  if cat roots.txt | gau --threads 3 --subs \
      --blacklist png,jpg,jpeg,gif,svg,woff,ttf,css \
      > passive/archived-urls.txt; then
    sort -u passive/archived-urls.txt -o passive/archived-urls.txt
    grep -Ei '\.(js|json|xml|txt|map)(\?|$)|/api([/?]|$)|/swagger|/openapi|/graphql' \
      passive/archived-urls.txt > passive/interesting-archived-urls.txt || true
    log "gau collected $(wc -l < passive/archived-urls.txt | tr -d ' ') URLs."
  else
    warn "gau returned an error; continuing."
  fi
else
  warn "gau not installed; skipping archived URL collection."
fi

# Create a basic report template before the optional active stage.
cat > report/final-report-template.md <<'EOF'
# External Domain OSINT Report

## 1. Executive Summary
- Assessment objective:
- Assessment window (UTC):
- Overall exposure summary:
- Highest-priority confirmed findings:

## 2. Scope and Authorization
- Root domains: see `roots.txt`
- Authorization / ticket reference:
- Approved hostnames: see `authorized/authorized_hosts.txt`
- Exclusions / third-party assets:

## 3. Methodology
- Passive discovery sources and tool versions: see `report/tool-inventory.txt`
- DNS and email-security collection: `dns/`
- Historical URL sources: `passive/archived-urls.txt`
- Active checks performed (if authorized): `authorized/`
- Rate limits and test window:

## 4. Attack-Surface Inventory
| Root | Hostname | DNS / CNAME | HTTP status | Title | Technology | Scope status | Evidence |
|---|---|---|---|---|---|---|---|

## 5. Findings
For each finding record: ID, title, affected asset, severity, confidence, observation, evidence, impact, remediation, owner, and retest status.

## 6. Limitations
Record unavailable sources, API-key limitations, stale archive data, excluded third parties, and untested assets.

## 7. Appendices
Include redacted evidence references and `report/SHA256SUMS.txt`.
EOF

# 7) Active HTTP/TLS checks: only after manual review + explicit written-authorization confirmation.
ACTIVE_RAN=0
if (( PASSIVE_ONLY )); then
  log "--passive-only selected; skipping all HTTP/TLS requests."
elif [[ ! -t 0 ]]; then
  warn "No interactive terminal detected; skipping active checks by default."
else
  printf '\n============================================================\n'
  printf 'HOSTNAME SCOPE REVIEW REQUIRED\n'
  printf 'The following file was copied from passive Subfinder results:\n  %s/authorized/authorized_hosts.txt\n' "$OUTDIR"
  printf 'A hostname in this file is NOT automatically authorized.\n'
  printf 'Remove all hosts that are not covered by written authorization.\n'
  printf '============================================================\n\n'

  # This script pipes normal output through tee for logging. Full-screen editors
  # must bypass that pipe and attach directly to the controlling terminal (/dev/tty),
  # otherwise nano/vi may look frozen or fail to redraw/respond correctly.
  if [[ -r /dev/tty && -w /dev/tty ]] && command -v nano >/dev/null 2>&1; then
    printf 'Opening nano for scope review. Controls: Ctrl+O, Enter = save; Ctrl+X = exit.\n'
    if nano authorized/authorized_hosts.txt </dev/tty >/dev/tty 2>&1; then
      log "Scope review editor closed."
    else
      warn "nano exited with a non-zero status; continuing to allow validation and safe skipping."
    fi
  elif [[ -r /dev/tty && -w /dev/tty ]] && command -v vi >/dev/null 2>&1; then
    printf 'Opening vi for scope review. Controls: press i to edit; Esc then :wq and Enter = save/exit.\n'
    if vi authorized/authorized_hosts.txt </dev/tty >/dev/tty 2>&1; then
      log "Scope review editor closed."
    else
      warn "vi exited with a non-zero status; continuing to allow validation and safe skipping."
    fi
  else
    warn "No usable interactive nano/vi terminal was found. Edit the file in another terminal, then return here."
    printf '\nCurrent staged hostnames (first 160 lines):\n'
    sed -n '1,160p' authorized/authorized_hosts.txt
    if [[ -r /dev/tty && -w /dev/tty ]]; then
      printf '\nEdit with: nano %q\n' "$OUTDIR/authorized/authorized_hosts.txt"
      read -r -p "Press Enter after saving the reviewed file, or type SKIP to skip active checks: " SCOPE_ACTION </dev/tty
      if [[ "${SCOPE_ACTION:-}" == "SKIP" ]]; then
        log "Operator selected SKIP; active HTTP/TLS checks will be skipped."
        PASSIVE_ONLY=1
      fi
    else
      warn "No controlling terminal available; skipping active HTTP/TLS checks."
      PASSIVE_ONLY=1
    fi
  fi

  # Validate every staged host is a syntactically valid hostname under one of the supplied roots.
  if (( PASSIVE_ONLY )); then
    log "Scope review skipped; passive discovery results are retained and active checks are disabled."
  elif python3 - roots.txt authorized/authorized_hosts.txt <<'PY'
import pathlib, re, sys
roots = [x.strip().lower().rstrip('.') for x in pathlib.Path(sys.argv[1]).read_text().splitlines() if x.strip()]
path = pathlib.Path(sys.argv[2])
raw = path.read_text(errors="replace")
valid_re = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
hosts, errors = set(), []
for line_no, line in enumerate(raw.splitlines(), 1):
    line = line.split("#", 1)[0]
    for token in re.split(r"[\s,]+", line.strip()):
        if not token:
            continue
        host = token.lower().rstrip('.')
        if not valid_re.fullmatch(host):
            errors.append(f"line {line_no}: invalid hostname {token!r}")
        elif not any(host == root or host.endswith('.' + root) for root in roots):
            errors.append(f"line {line_no}: outside supplied root scope: {host}")
        else:
            hosts.add(host)
if errors:
    print("Allowlist validation failed:", file=sys.stderr)
    print("\n".join(errors), file=sys.stderr)
    raise SystemExit(2)
if not hosts:
    print("Allowlist is empty; no active targets to check.", file=sys.stderr)
    raise SystemExit(3)
path.write_text("".join(h + "\n" for h in sorted(hosts)))
print(f"Validated {len(hosts)} hostname(s), all under supplied roots.")
PY
  then
    printf '\nOnly proceed if EACH hostname above is explicitly included in the written authorization.\n'
    read -r -p "Type AUTHORIZED to run low-rate HTTP/TLS checks against this exact file: " AUTH_CONFIRM
    if [[ "$AUTH_CONFIRM" == "AUTHORIZED" ]]; then
      HTTPX_BIN=""
      if command -v httpx-toolkit >/dev/null 2>&1; then
        HTTPX_BIN="httpx-toolkit"
      elif command -v httpx >/dev/null 2>&1; then
        # Avoid accidentally invoking an unrelated binary also named httpx.
        if httpx -h 2>&1 | grep -q -- '-status-code'; then
          HTTPX_BIN="httpx"
        fi
      fi

      if [[ -n "$HTTPX_BIN" ]]; then
        log "Running low-rate HTTP verification with $HTTPX_BIN (2 requests/sec, 2 threads)..."
        if "$HTTPX_BIN" -l authorized/authorized_hosts.txt \
            -sc -title -td -ip -cname -location \
            -rl 2 -t 2 -timeout 10 -csv \
            -o authorized/web-assets.csv; then
          log "HTTP inventory saved to authorized/web-assets.csv."
        else
          warn "HTTP verification returned an error; inspect the log and tool help."
        fi
      else
        warn "ProjectDiscovery httpx-toolkit/httpx not found; skipping HTTP inventory."
      fi

      if command -v curl >/dev/null 2>&1; then
        : > authorized/response-headers.txt
        while IFS= read -r host; do
          [[ -n "$host" ]] || continue
          {
            echo "===== $host ====="
            curl -sS --connect-timeout 5 --max-time 10 --max-redirs 0 \
              -D - -o /dev/null "https://${host}/" 2>&1 | sed -n '1,60p' || true
          } >> authorized/response-headers.txt
          sleep 1
        done < authorized/authorized_hosts.txt
      fi

      if command -v openssl >/dev/null 2>&1; then
        : > authorized/tls-certificates.txt
        while IFS= read -r host; do
          [[ -n "$host" ]] || continue
          {
            echo "===== $host ====="
            if command -v timeout >/dev/null 2>&1; then
              timeout 10 openssl s_client -connect "${host}:443" -servername "$host" \
                </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates \
                -ext subjectAltName 2>&1 || true
            else
              openssl s_client -connect "${host}:443" -servername "$host" \
                </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates \
                -ext subjectAltName 2>&1 || true
            fi
          } >> authorized/tls-certificates.txt
          sleep 1
        done < authorized/authorized_hosts.txt
      fi
      ACTIVE_RAN=1
    else
      log "Authorization phrase not provided; skipping all HTTP/TLS checks."
    fi
  else
    warn "Allowlist failed validation; skipping all HTTP/TLS checks."
  fi
fi

# 8) Engagement notes, report counts and evidence hashes.
SUBFINDER_COUNT="$(wc -l < passive/subfinder.txt | tr -d ' ')"
CANDIDATE_COUNT="$(wc -l < candidates.txt | tr -d ' ')"
APPROVED_COUNT="$(grep -cve '^[[:space:]]*$' authorized/authorized_hosts.txt 2>/dev/null || true)"
[[ -n "$APPROVED_COUNT" ]] || APPROVED_COUNT=0
HTTP_ROWS=0
if [[ -f authorized/web-assets.csv ]]; then
  HTTP_ROWS="$(awk 'END { n=NR-1; if (n<0) n=0; print n }' authorized/web-assets.csv)"
fi
{
  echo "Run completed UTC: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo "Root domains: $ROOT_COUNT"
  echo "Subfinder results: $SUBFINDER_COUNT"
  echo "Candidate hostnames: $CANDIDATE_COUNT"
  echo "Staged hostname entries in authorized_hosts.txt: $APPROVED_COUNT"
  echo "HTTP inventory data rows: $HTTP_ROWS"
  echo "Active checks executed: $ACTIVE_RAN"
  echo "Output directory: $OUTDIR"
} > report/run-summary.txt

if command -v sha256sum >/dev/null 2>&1; then
  find roots.txt subfinder.txt passive dns authorized -type f -print0 \
    | sort -z | xargs -0 -r sha256sum > report/SHA256SUMS.txt
else
  warn "sha256sum not installed; evidence checksums were not generated."
fi

log "Recon workflow completed."
log "Summary: report/run-summary.txt"
log "Report template: report/final-report-template.md"
log "Subfinder staging copy: authorized/authorized_hosts.txt"
log "Remember: 'authorized_hosts.txt' is only a staging filename; authorization comes from the written scope approval."
log "Output directory: $OUTDIR"
