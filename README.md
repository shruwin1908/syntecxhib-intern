# Web Vulnerability Scanner (Reflected XSS)

A small, self-contained scanner for **Project 2**: it crawls a target site,
injects XSS payloads into forms and URL parameters, checks responses for
unescaped reflection, and writes a report of vulnerable endpoints.

> ⚠️ **Only run this against systems you own or are explicitly authorized to
> test** — e.g. DVWA, OWASP Juice Shop, or your own local test server.
> Scanning third-party websites without permission is illegal.

## Setup

```bash
git clone <this-folder-or-repo>
cd web-vuln-scanner
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Running it against DVWA (example)

1. Set up DVWA locally (e.g. via the [DVWA Docker image](https://github.com/digininja/DVWA)) and log in through your browser.
2. Set DVWA's security level to **low** for a first pass (Security tab in DVWA).
3. Copy your session cookie from the browser (DevTools → Application → Cookies) — you need `PHPSESSID` and `security`.
4. Run:

```bash
python scanner.py \
  --url http://localhost/dvwa \
  --cookie "PHPSESSID=<your-session-id>; security=low" \
  --max-pages 25
```

You'll be asked to confirm authorization (type `YES`), then the scanner will:

1. Crawl same-domain pages up to `--max-pages`.
2. Inject each payload from `payloads.py` into every form field and URL
   parameter it finds.
3. Flag any case where the exact payload comes back **unescaped** in the
   response (a sign of missing/broken sanitization).
4. Write `report.json` and `report.txt`.

## CLI options

| Flag           | Description                                      | Default       |
|----------------|---------------------------------------------------|---------------|
| `--url`        | Target base URL (required)                        | —             |
| `--max-pages`  | Max pages to crawl                                 | 20            |
| `--cookie`     | Cookie header for authenticated sessions           | none          |
| `--timeout`    | Per-request timeout (seconds)                      | 8             |
| `--yes`        | Skip the interactive authorization prompt          | off           |
| `--json-out`   | Output path for JSON report                        | report.json   |
| `--text-out`   | Output path for text report                        | report.txt    |

## Project layout

```
web-vuln-scanner/
├── scanner.py     # CLI entry point
├── crawler.py     # site crawling (forms, links with params)
├── injector.py    # payload injection + reflection detection
├── payloads.py    # XSS payload templates
├── report.py      # JSON/text report generation
├── requirements.txt
└── README.md
```

## How detection works

Each payload includes a unique marker (e.g. `xssmark3f9a2c1b`) so a "hit" is
tied to a specific injection, not just any `<script>` tag that happens to be
on the page already. A finding is only recorded if the *exact* payload
string — unescaped — shows up in the response body. If the app HTML-encodes
it (`&lt;script&gt;`), that's correctly treated as **not** vulnerable.

## Extending it

- Add more payloads in `payloads.py`.
- Add stored-XSS detection by re-visiting pages after submission.
- Add authentication flows (login form auto-submit) for apps that require login before reaching vulnerable pages.
- Swap the text/JSON report for an HTML report if you want something more presentable to submit.
