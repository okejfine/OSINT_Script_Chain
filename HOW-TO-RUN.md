# How to Run the Digital Footprint Audit on a New Machine

This guide walks you through setting up and running the Digital Footprint Audit script on a **macOS** machine from scratch.

---

## What This Script Does

The script runs a **personal digital footprint audit** using open-source OSINT (open-source intelligence) tools. You provide a username, email, phone number, and/or domain; the script runs several tools (Sherlock, Maigret, theHarvester, PhoneInfoga, SpiderFoot, Recon-ng, and Have I Been Pwned) and writes results into a timestamped report folder. An HTML summary opens in your browser when the run finishes.

**Use case:** Assessing what public information exists about you (or a consenting target) online, for privacy and security awareness.

---

## Prerequisites

- **macOS** (Apple Silicon or Intel). The script uses Homebrew and assumes macOS paths.
- **Homebrew** — [Install from https://brew.sh](https://brew.sh) if you don’t have it.
- **Python 3** — Install with `brew install python` if needed.
- **Network access** — Tools fetch data from the internet.

Optional but recommended:

- **pipx** — For installing Python CLI tools (e.g. Maigret) without touching system Python: `brew install pipx` then `pipx ensurepath`. Add `~/.local/bin` to your PATH if your shell doesn’t already.
- **Go** — Only needed if you install PhoneInfoga via Go instead of Homebrew; the script can install some tools via `brew` automatically.

---

## Step 1: Get the Script

Copy the single script file to the new machine:

- **File to copy:** `digital-footprint-audit.sh`
- Put it in a folder you’ll run from, e.g. `~/Sandbox` or `~/digital-footprint-audit`.

If you use git, you can clone the repo (if this is in one) and use the script from the clone.

---

## Step 2: Make It Executable

In Terminal:

```bash
cd /path/to/folder/containing/the/script
chmod +x digital-footprint-audit.sh
```

Replace `/path/to/folder/containing/the/script` with the actual path (e.g. `~/Sandbox`).

---

## Step 3: Run the Script

From that same folder:

```bash
./digital-footprint-audit.sh
```

**First run:** The script will check for each tool (Sherlock, Maigret, theHarvester, PhoneInfoga, SpiderFoot, Recon-ng). It will try to install missing ones via Homebrew, pipx, or pip. You may see warnings or failures for some tools (e.g. Maigret if pipx isn’t installed); the script will continue with whatever is available and will warn if fewer than three tools are ready.

**When prompted**, enter the target details (press Enter to skip any field):

- **Username** — e.g. a social/media handle to search.
- **Email** — Used for Have I Been Pwned and (if not a big provider) domain/email recon.
- **Phone** — With country code (e.g. `+14155551234`) for phone OSINT.
- **Domain** — A domain to recon (e.g. your personal or org domain).

You must provide at least one of these; the script will exit if all are empty.

---

## Step 4: Wait for Completion

The script runs each available tool in sequence. Duration depends on the tools and inputs (often several minutes). When it finishes:

- It prints a short summary and the report path.
- It **opens the HTML report in your default browser** automatically.

---

## Where the Report Lives

- **Directory:** `~/digital-footprint-reports/YYYY-MM-DD_HH-MM-SS/`
- **Summary:** `~/digital-footprint-reports/<timestamp>/index.html` (this is what opens in the browser).
- **Raw outputs:** Subfolders per tool: `hibp/`, `sherlock/`, `maigret/`, `theharvester/`, `phoneinfoga/`, `spiderfoot/`, `recon-ng/`.

To open the report again later:

```bash
open ~/digital-footprint-reports/<timestamp>/index.html
```

(Use the actual timestamp folder name.)

---

## Command-Line Options

| Option | Description |
|--------|-------------|
| `--tor` | Route tool traffic through Tor (requires Tor installed, e.g. `brew install tor`). |
| `--timeout=SECONDS` | Per-request timeout (default: 60). |
| `--hibp-key=KEY` | Have I Been Pwned API key for full breach/paste results. Get a key at [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key). Without it, HIBP runs in limited mode. |
| `--help`, `-h` | Show usage and options. |

Examples:

```bash
./digital-footprint-audit.sh --hibp-key=your-api-key
./digital-footprint-audit.sh --tor
./digital-footprint-audit.sh --help
```

---

## Troubleshooting

- **“Permission denied” when running the script**  
  Run: `chmod +x digital-footprint-audit.sh`

- **“Homebrew is required”**  
  Install Homebrew from [brew.sh](https://brew.sh).

- **Maigret fails to install**  
  The script prefers `pipx`. Install pipx and ensure `~/.local/bin` is on your PATH:
  ```bash
  brew install pipx
  pipx ensurepath
  ```
  Then restart Terminal and run the script again. You can still run the audit without Maigret (other tools will run).

- **“No target information provided”**  
  You must enter at least one of: username, email, phone, or domain. Re-run and fill at least one prompt.

- **HTML report didn’t open**  
  Open it manually:
  ```bash
  open ~/digital-footprint-reports/<timestamp>/index.html
  ```

- **Only a few tools run**  
  The script needs at least three tools. Install missing ones (e.g. via `brew install sherlock theharvester phoneinfoga recon-ng` and `pipx install maigret`), or fix Python/pipx so the script can auto-install them.

---

## Tools Used (Reference)

| Tool | Purpose |
|------|---------|
| **Have I Been Pwned** | Breach and paste check for the given email. |
| **Sherlock** | Username search across 400+ sites. |
| **Maigret** | Username search across 1000+ sites. |
| **theHarvester** | Email and domain reconnaissance. |
| **PhoneInfoga** | Phone number OSINT. |
| **SpiderFoot** | Multi-source aggregator (cloned to `~/spiderfoot` if not present). |
| **Recon-ng** | Modular recon (e.g. domain/host discovery). |

---

## Legal and Ethical Use

Use this only on yourself or with explicit consent. Respect platform terms of service and applicable laws. The script and this doc are for personal privacy and security awareness only.
