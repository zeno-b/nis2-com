# NIS2 Belgian Companies Scanner + Contact Intelligence

This repository contains one main script: `scanner.py`.

It combines two workflows:

1. NIS2 scan workflow:
   - load Belgian KBO Open Data CSV files,
   - filter companies by NIS2 sector and/or NACE,
   - build target URLs,
   - run Nuclei templates,
   - generate coverage and summary reports.
2. Contact intelligence workflow:
   - collect contact clues from multiple OSINT sources,
   - score and rank candidates,
   - export CSV/JSON/HTML reports.

This README is written as a full step-by-step runbook so you can start from zero and run each mode safely.

---

## Table of contents

1. [What you need before running](#what-you-need-before-running)
2. [Step-by-step setup](#step-by-step-setup)
3. [Step-by-step usage](#step-by-step-usage)
4. [Detailed pipeline behavior](#detailed-pipeline-behavior)
5. [Configuration file mode (`--config`)](#configuration-file-mode---config)
6. [Power Automate webhook setup (step-by-step)](#power-automate-webhook-setup-step-by-step)
7. [Outputs and where files go](#outputs-and-where-files-go)
8. [Full CLI reference by category](#full-cli-reference-by-category)
9. [Troubleshooting](#troubleshooting)
10. [Testing and validation commands](#testing-and-validation-commands)
11. [Repository layout](#repository-layout)

---

## What you need before running

### Runtime requirements

- Python 3.10+ recommended.
- Linux/macOS/Windows supported.
- Internet access required for:
  - Nuclei templates/scans,
  - contact-intel HTTP sources,
  - optional auto-install behavior.

### Input datasets (KBO Open Data)

Download from:

- <https://kbopub.economie.fgov.be/kbo-open-data/>

Expected files:

- `activity.csv` (required)
- `contact.csv` (required)
- `denomination.csv` (optional but recommended)

By default, these filenames are expected in the current working directory unless overridden with CLI flags.

### Dependencies

`scanner.py` performs an automatic prerequisite check at startup (unless disabled). It can auto-install missing Python packages and may auto-install `nuclei` on Linux.

If you prefer manual installation:

- `pip install pandas tqdm colorama pyyaml tldextract openpyxl orjson requests beautifulsoup4 dnspython`

Optional deterministic mode for tests/automation:

- `SCANNER_SKIP_PREREQ_CHECK=1`

---

## Step-by-step setup

### Step 1: Open the project directory

- `cd /path/to/repo`

### Step 2: (Optional) create and activate a virtual environment

Linux/macOS:

- `python3 -m venv .venv`
- `source .venv/bin/activate`

Windows PowerShell:

- `python -m venv .venv`
- `.venv\Scripts\Activate.ps1`

### Step 3: Install dependencies (recommended for predictable startup)

- `pip install pandas tqdm colorama pyyaml tldextract openpyxl orjson requests beautifulsoup4 dnspython`

### Step 4: Ensure `~/.local/bin` is on `PATH` (Linux)

The script may place `nuclei` in `~/.local/bin`. Add it:

- `export PATH="$HOME/.local/bin:$PATH"`

### Step 5: Put KBO CSV files in your working directory

Required:

- `activity.csv`
- `contact.csv`

Recommended:

- `denomination.csv`

### Step 6: Verify CLI is available

- `python3 scanner.py --help`

If this prints help text, setup is complete.

---

## Step-by-step usage

This section is organized by common real-world flows.

### Flow A: Inspect sector names and NACE mappings first

Use this before scanning so your `--sector` values are valid:

- `python3 scanner.py --list-sectors`

### Flow B: Do a safe dry run (no active Nuclei requests)

Use this to validate filtering/target generation and preview the exact Nuclei command:

- `python3 scanner.py --sector Health --run-mode dryrun`

Optional useful flags during dry run:

- `--limit 100` (small sample)
- `--resolve-dns`
- `--resolve-urls`
- `--exclude exclude_domains.txt`

### Flow C: Run a normal NIS2 scan

Minimal scan:

- `python3 scanner.py --sector Health`

Practical scan with explicit performance controls:

- `python3 scanner.py --sector Health --rate 150 --concur 25 --timeout 10`

### Flow D: Run scan + enrich top affected companies with contact intel

Example:

- `python3 scanner.py --sector Health --enrich-contacts --contact-limit 20 --no-smtp`

Add optional API keys if available:

- `--hunter-key YOUR_HUNTER_KEY`
- `--apollo-key YOUR_APOLLO_KEY`

### Flow E: Contact intelligence only for one company (no NIS2 scan)

Use when you already know KBO number and domain:

- `python3 scanner.py --contact-only --kbo 0419649912 --domain bhak.be --no-smtp`

This writes contact artifacts for that single organization and an HTML report.

### Flow F: Generate summary only from existing scan results

Use after a previous run if `nuclei_results.json` already exists:

- `python3 scanner.py --output-dir nis2_scan_output --summary-only`

### Flow G: Run-mode options for dry-run and follow-up execution

- Dry-run target generation only:
  - `python3 scanner.py --sector Health --run-mode dryrun`
- Re-run dry-run but skip previously selected/scanned targets:
  - `python3 scanner.py --sector Health --run-mode dryrun-skip-selected`
- Run Nuclei using targets from a previous dry-run (`output-dir/targets.txt`):
  - `python3 scanner.py --sector Health --output-dir nis2_scan_output --run-mode run-from-dryrun`

Related controls:
- `--clear-checkpoint`: clear checkpoint and exit.
- `--force-refresh`: ignore cached `targets.txt` and regenerate targets now (ignored for `run-from-dryrun`).
- `--cache-minutes N`: target cache TTL (default 60).
- Legacy compatibility flags still work: `--dry-run`, `--resume`.

### Flow H: Run scan + deliver report via Power Automate webhook

Use this when you want email/report delivery from Power Automate:

- `python3 scanner.py --sector Health --power-automate-webhook "https://prod-00.westeurope.logic.azure.com/..." --outlook-to "soc@example.com;cto@example.com" --outlook-subject "NIS2 Health Scan" --attach-report-files`

---

## Detailed pipeline behavior

When running a full scan (non `--contact-only`), the script executes these stages:

1. **STEP 0 - Parse template checks**
   - Parses configured Nuclei templates and extracts matcher names for reporting.
2. **STEP 1 - Filter NIS2 entities**
   - Loads `activity.csv` and filters to sector/NACE scope.
3. **STEP 2 - Load websites for target set**
   - Loads `contact.csv` and collects WEB contacts for selected entities.
4. **STEP 3 - Join entities and websites**
   - Builds website coverage for target entities.
5. **STEP 4 - Company names**
   - Loads optional names from `denomination.csv`.
6. **STEP 5 - Process and write targets**
   - Deduplicate/normalize URLs,
   - optional DNS and URL pre-resolution,
   - optional exclude list filtering,
   - optional per-sector target files.
7. **STEP 6 - Nuclei scan**
   - Runs Nuclei unless in dry-run mode (`--run-mode dryrun` / `--run-mode dryrun-skip-selected` or legacy `--dry-run`).
8. **Summary/report generation**
   - Produces coverage summaries and optional Excel.
9. **Optional contact enrichment**
   - If `--enrich-contacts` is enabled, enriches top impacted companies.
10. **Optional report delivery**
   - Can call Power Automate / Outlook webhook delivery options.

For `--contact-only`, the scan stages are skipped and only single-target contact enrichment/export is executed.

---

## Configuration file mode (`--config`)

If you prefer YAML-based runs:

### 1) Generate an example config

- `python3 scanner.py --init-config campaign.yml`

### 2) Edit the generated file

Typical fields include:

- `sector`
- `nace`
- `templates`
- `severity`
- `rate`, `concur`, `timeout`
- `resolve_dns`, `resolve_urls`, `per_sector_dirs`
- `output_dir`
- optional delivery settings (`power_automate_webhook`, `outlook_to`, etc.)

### 3) Run with config

- `python3 scanner.py --config campaign.yml`

### CLI vs config precedence

CLI values win when explicitly set. Config values are applied only for arguments still at default/unset values.

---

## Power Automate webhook setup (step-by-step)

This section shows a practical flow configuration that matches the payload sent by `scanner.py`.

### 1) Create a Power Automate flow with HTTP trigger

In Power Automate:

1. Create an **Automated cloud flow**.
2. Use trigger: **When an HTTP request is received**.
3. Set request body JSON schema to:

```json
{
  "type": "object",
  "properties": {
    "source": { "type": "string" },
    "generated_at": { "type": "string" },
    "subject": { "type": "string" },
    "to": {
      "type": "array",
      "items": { "type": "string" }
    },
    "summary": { "type": "object" },
    "report": {
      "type": "object",
      "properties": {
        "path": { "type": "string" },
        "name": { "type": "string" },
        "html": { "type": "string" }
      }
    },
    "attachments": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "name": { "type": "string" },
          "path": { "type": "string" },
          "size_bytes": { "type": "integer" },
          "mime_type": { "type": "string" },
          "content_base64": { "type": "string" },
          "skipped": { "type": "string" }
        }
      }
    }
  },
  "required": [
    "source",
    "generated_at",
    "subject",
    "to",
    "summary",
    "report",
    "attachments"
  ]
}
```

After saving, copy the generated HTTP POST URL. Use it with `--power-automate-webhook`.

### 2) Add Outlook email action

Add **Office 365 Outlook - Send an email (V2)** (or equivalent mail action):

- **To**: use recipient list from payload, fallback to fixed address if empty.
  - Example expression: `if(empty(triggerBody()?['to']), 'soc@example.com', join(triggerBody()?['to'], ';'))`
- **Subject**: `triggerBody()?['subject']`
- **Body**: `triggerBody()?['report']?['html']`
- Enable HTML body rendering in the mail action.

### 3) Add optional attachment mapping

If you use `--attach-report-files`, payload entries include base64 file content.

Recommended pattern:

1. Initialize an array variable for email attachments.
2. Add **Apply to each** over `triggerBody()?['attachments']`.
3. Add condition: only include items where `content_base64` exists.
   - Example condition expression: `not(empty(item()?['content_base64']))`
4. Append object in expected mail-action format (`Name` and `ContentBytes` mapped from `name` and `content_base64`).
5. Pass that array variable into the email action attachment input.

Notes:

- `scanner.py` skips attachments larger than 5 MB and marks them with `"skipped": "too-large"`.
- The HTML report itself is always sent in `report.html` even when some file attachments are skipped.

### 4) Run scanner with webhook delivery flags

Scan + delivery:

- `python3 scanner.py --sector Health --power-automate-webhook "https://prod-00.westeurope.logic.azure.com/..." --outlook-to "soc@example.com;cto@example.com" --outlook-subject "Weekly NIS2 Report" --attach-report-files`

Contact-only + delivery:

- `python3 scanner.py --contact-only --kbo 0419649912 --domain bhak.be --no-smtp --power-automate-webhook "https://prod-00.westeurope.logic.azure.com/..." --outlook-to "soc@example.com"`

### 5) YAML config example for webhook mode

```yaml
power_automate_webhook: "https://prod-00.westeurope.logic.azure.com/..."
outlook_to: "soc@example.com;cto@example.com"
outlook_subject: "Weekly NIS2 Report"
power_automate_timeout: 20
attach_report_files: true
```

Run with:

- `python3 scanner.py --config campaign.yml`

### 6) Quick webhook diagnostics

Useful checks:

- Confirm flow run history in Power Automate for HTTP status and action errors.
- Increase timeout if needed:
  - `--power-automate-timeout 40`
- If recipients are not set, verify `--outlook-to` or your flow fallback logic.

---

## Outputs and where files go

Default output directory:

- `nis2_scan_output_YYYYMMDD_HHMMSS/` (timestamped per run)

Common artifacts:

- `targets.txt` - final target URLs for scanning
- `nuclei_results.json` - raw Nuclei output
- `nis2_companies_manifest.csv` - company-to-target mapping
- `full_coverage_report.csv` - coverage report
- `full_coverage_report.xlsx` - optional Excel export (`--export-xlsx`)
- `step_timings.json` - stage timing metrics
- `checkpoint.json` - resume state
- `retry_targets.txt` - retry candidates for failed targets
- `nis2_report.html` - contact-enrichment HTML summary (when enrichment runs)
- `contacts_<org>.csv` / `contacts_<org>.json` - contact-only outputs
- `report_<org>.html` - contact-only HTML report

---

## Full CLI reference by category

For complete auto-generated help:

- `python3 scanner.py --help`

### General/data paths

- `--config FILE`
- `--init-config [FILE]`
- `--activity FILE`
- `--contact FILE`
- `--denomination FILE`
- `--output-dir DIR`

### Filtering

- `--sector NAME` (repeatable)
- `--nace CODE` (repeatable; 4-5 digits)
- `--limit N`
- `--annex1-only`
- `--list-sectors`

### Target processing

- `--resolve-dns`
- `--resolve-urls`
- `--exclude FILE`
- `--per-sector-dirs`

### Nuclei execution

- `--templates PATH` (repeatable)
- `--severity LIST`
- `--rate N`
- `--concur N`
- `--timeout S`
- `--proxy URL`
- `--run-mode MODE` (`auto`, `dryrun`, `dryrun-skip-selected`, `run-from-dryrun`)
- `--update-nuclei`
- `--resume`
- `--clear-checkpoint`
- `--schedule N`
- `--no-retry`
- `--dry-run`
- `--verbose-nuclei`
- `--force-refresh`
- `--cache-minutes N`

### Reporting/terminal

- `--summary-only`
- `--export-xlsx`
- `--no-color`
- `--quiet`

### Contact intelligence

- `--contact-only`
- `--kbo NUM`
- `--domain DOMAIN`
- `--enrich-contacts`
- `--contact-limit N`
- `--hunter-key KEY`
- `--apollo-key KEY`
- `--serp-delay S`
- `--contact-workers N`
- `--no-smtp`
- `--contact-proxy URL`

### Power Automate / Outlook delivery

- `--power-automate-webhook URL`
- `--outlook-to EMAILS`
- `--outlook-subject TEXT`
- `--power-automate-timeout S`
- `--attach-report-files`

---

## Troubleshooting

### Error: file not found / file is empty

- Confirm `activity.csv` and `contact.csv` exist and are non-empty.
- Confirm delimiter/headers are intact from KBO export.

### Unknown sector error

- Run `python3 scanner.py --list-sectors` and copy the sector name exactly.

### No valid URLs to scan

- Check if the selected sector/NACE has website coverage in `contact.csv`.
- Remove overly strict `--exclude` rules.
- Try without `--resolve-dns` first to inspect raw target generation.

### Nuclei missing

- On Linux, script attempts auto-install.
- If still missing, install manually from:
  - <https://github.com/projectdiscovery/nuclei/releases>
- Ensure executable is on `PATH` (`~/.local/bin` often required).

### Contact-intel shape error (`NoneType` has no attribute `get`)

Historical note: this codebase had markdown corruption and reconstruction.
If this appears in contact-source helpers, validate helper return shapes and run regression tests in `tests/`.

### Auto-install behavior is not desired in CI

Use:

- `SCANNER_SKIP_PREREQ_CHECK=1`

Then install dependencies explicitly in your environment.

---

## Testing and validation commands

This repository does not include full CI pipelines. Use these checks:

1. Syntax compile check:
   - `python3 -c "compile(open('scanner.py').read(), 'scanner.py', 'exec')"`
2. Regression tests:
   - `SCANNER_SKIP_PREREQ_CHECK=1 python3 -m unittest discover -s tests -v`
3. CLI smoke:
   - `SCANNER_SKIP_PREREQ_CHECK=1 python3 scanner.py --help`

---

## Repository layout

- `scanner.py` - all scanner and contact-intel logic.
- `tests/test_contact_intel_regressions.py` - focused regression tests for fragile contact-intel paths.
- `README.md` - this runbook.
- `AGENTS.md` - cloud/dev execution notes for this repository.

