# README — Watchtower / Reflix Installation & Configuration (Quick Guide)

> **What the Watcher does**
>
> The watcher continuously monitors your monitored assets and bounty programs and notifies you about relevant changes. Key capabilities:
>
> * **New bug-bounty programs:** Automatically alerts when new programs are published.
> * **Wildcard monitoring:** Add wildcard assets (*.example.com) and schedule a task to run at your preferred interval. After each run the watcher executes **httpx** to detect live subdomains, performs asset discovery, and reports discovered live subdomains.
> * **CIDR support & port scanning:** You may register CIDR ranges for daily port scans. This is available but **not recommended** for wide use because it may trigger blocks by ISPs or the target organization.
> * **HTTPX change detection:** The `httpx change` flow notifies you about changes in targets — including new URLs discovered on assets, parameter discovery, and URL/content changes.
>
>   * **URL discovery:** The system performs daily URL discovery for assets and notifies when new URLs are found.
>   * **Parameter discovery:** It attempts to discover parameters on found URLs.
>   * **URL change detection:** Detects changes such as different JS resource hashes or changes in HTTP status codes and alerts accordingly.
>
> If you have questions, contact **@nexovir** (I haven’t had time to fully document everything yet). Reach out on **X** or **Telegram** with that handle for support.

---

## 1. Overview

This guide walks you through:

* Preparing PostgreSQL and setting DB credentials in the backend settings.
* Creating and activating a Python virtual environment and installing `requirements.txt`.
* Installing additional external tools required by the system.
* Admin panel manual configuration (Tools, Program Watchers, AssetWatchers).
* Adding a Periodic Task named `orchestrator` with your chosen schedule.

Use this document for initial setup and to ensure the admin panel contains the required monitoring entries.

---

## 2. Prerequisites

* Linux distribution (Ubuntu/Debian/CentOS or similar) with Python 3.8+.
* PostgreSQL server (create a database and a user for the application).
* `python3`, `virtualenv` and build tools as needed.
* Network connectivity for downloading tools and dependencies.

---

## 3. Database configuration

1. Install PostgreSQL and create a dedicated database and user (for example, `watchtower`).
2. Open the backend settings file and set the PostgreSQL connection values (username/password/host/name):

```
infodisclosure_backend/settings.py
```

Make sure you replace the DB username and password in that file with the PostgreSQL credentials you created. Verify connectivity with `psql` before proceeding.

---

## 4. Python virtual environment & requirements

1. Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Upgrade pip and install Python dependencies:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

3. Run database migrations and collect static files (project-specific commands may vary):

```bash
python manage.py migrate
python manage.py collectstatic --noinput
```

4. Start the application and verify logs to confirm DB connectivity and service health.

---

## 5. Additional external tools (must be installed and available in PATH)

In addition to `requirements.txt`, the following external tools must be installed on the host (or in the environment) and be executable by the application user. Some are installed via `go install`, others via package manager or prebuilt binaries. Ensure binaries are on the system `PATH` or configure explicit paths in the app settings.

**Required tools (one per line):**

* naabu
* nuclei
* fallparams
* x8
* reflix
* subfinder
* findomain
* httpx
* waybackurls
* dnsx
* awk
* unfurl
* dnsgen
* jq
* puredns
* amass

> Note: `x8` appeared twice in the original list — only one installation is required.

**Installation notes:**

* Most tools can be installed with `go install github.com/...@latest` or by downloading the release binary. Follow each tool's official installation instructions.
* Confirm each binary by running e.g. `naabu -h`, `nuclei -version`, etc.

---

## 6. Admin panel configuration (manual steps)

Login to the admin panel (e.g., `/admin`) and manually add the items listed below.

### 6.1 Asset_Monitor → Tools

Add the following tools as separate Tool entries (exact names):

* Daily Vulnerabilities Monitoring
* Daily Narrow Monitoring
* CRT.sh
* Wabackurls
* HTTPX
* DNS Bruteforce
* Amass
* Owned
* Findomain

### 6.2 Programs_Monitor → Program Watchers

Manually add the following Program Watchers. **The names are case-sensitive** and must be entered exactly as shown.

* **Yeswehack** : `https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/refs/heads/main/data/yeswehack_data.json`
* **Intigriti** : `https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/refs/heads/main/data/intigriti_data.json`
* **Hackerone** : `https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/refs/heads/main/data/hackerone_data.json`
* **Federacy** : `https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/refs/heads/main/data/federacy_data.json`
* **Bugcrowd** : `https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/refs/heads/main/data/bugcrowd_data.json`

> Make sure each URL is entered exactly (including `https://`).

### 6.3 Asset_Monitor → AssetWatchers

* Add your wildcard entries (e.g., `*.example.com`) in **AssetWatchers** as needed.
* **Recommendation:** Do **not** enable DNS brute forcing for wildcard entries unless you are certain it is safe and permitted for that asset. DNS brute force on wildcards can produce noisy and potentially harmful traffic.

**If the admin panel throws an error when saving wildcards:**

* Create two sample text files on the server (if not present):

  * `dns_bruteforce_static_wordlist.txt`
  * `dns_bruteforce_dynamic_wordlist.txt`
* Add a minimal sample entry in each file. These sample files are not used by the program logic but some admin panel versions expect them to exist to accept the wildcard configuration.

---

## 7. Periodic Tasks

Open the admin area for periodic tasks (e.g., `Periodic Tasks` → `Periodic tasks`) and add the following task:

* **Task name:** `orchestrator`
* **Schedule:** Set your preferred schedule (e.g., daily, hourly, cron expression). The task runner will execute according to the periodic schedule you choose.

> Make sure the task name is exactly `orchestrator` (case-sensitive) when adding it to the Periodic Tasks list.

---

## 8. Important notes & troubleshooting

* **Case sensitivity:** Several fields in the admin panel are case-sensitive (Program Watchers and task names). Enter them exactly as listed.
* **Tool PATH:** Ensure all external tool binaries are accessible by the application user and are on the `PATH` or configured in settings.
* **Logs:** If you encounter errors while saving admin entries or running the app, check application logs and Django/system logs for detailed error messages.
* **Security:** Use HTTPS/TLS for the admin panel, restrict admin access, and enable MFA for admin accounts in production.

---

## 9. Next steps (optional)

I can also provide:

* An English README in a different style (short checklist or full tutorial).
* An `install-tools.sh` sample script to install common tools automatically.
* A `systemd` unit example for running the web service and Celery/beat if used.

Tell me which of the above you want and I will prepare it.
