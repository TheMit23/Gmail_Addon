# Malicious Email Scorer — Gmail Add-on

A Gmail contextual add-on that scores an opened message for phishing and abuse signals, returns a **0–100 maliciousness score**, a **plain-language verdict** (Safe / Suspicious / Malicious), and **human-readable reasons** the user can sanity-check.

The add-on (Apps Script) collects message fields and calls a small **FastAPI** backend that combines header checks, sender heuristics, attachment metadata rules, and **Gemini**-based content analysis. Trade-offs favor **explainability**, **minimal Gmail scopes**, and **clear trust boundaries** over production completeness.

---

## Architecture

```text
Gmail (open message)
       │
       ▼
Apps Script (Addon/Code.js)
  • subject, plain body, From, Reply-To, Authentication-Results, Return-Path
  • attachment list: filename, mime_type, size_bytes (no file bytes)
  • POST JSON → POST /analyze
       │
       ▼
FastAPI (Backend/main.py)
  • Starts async Gemini task; in parallel runs sync analyzers, then merges:
  ├─ Analyze_headers.py   — SPF/DKIM/DMARC, Reply-To / Return-Path mismatch
  ├─ Analyze_sender.py    — typosquatting, display-name vs domain heuristics
  ├─ Analyze_attachments.py — metadata-only (extensions, MIME, archives, etc.)
  ├─ Analyze_content_ai.py — Gemini JSON → findings with category "Content - …"
  └─ Calculate_score.py — pillar score, diminishing repeats, verdict
       │
       ▼
Response: score, verdict, findings[] (INFO-severity rows are dropped here)
       │
       ▼
Card: score/100, verdict (color), finding descriptions + severity icons
```

**Why this split:** Apps Script cannot hold API keys safely; anything that needs **GEMINI_API_KEY** runs on the backend. The add-on is a thin HTTP client.

### Scoring (`Calculate_score.py`)

1. **Pillars:** `Authentication`, `Sender - …`, `Attachments`, anything starting with **`Content - …`**, and **`other`**.
2. **INFO ignored for scoring:** Findings with severity **INFO** (e.g. attachment count summary) add **no points** and are **not** grouped into pillars for math. They are still emitted by analyzers but **stripped from the HTTP response** in `main.py`, so the Gmail card only shows **LOW–CRITICAL** reasons.
3. **Within each pillar:** findings sorted by severity (strongest first). Each contributes `severity_weight × category_multiplier × diminish[index]`, where **diminish** is **1.0 → 0.8 → 0.6 → 0.4** for the 1st, 2nd, 3rd, 4th+ finding in that pillar.
4. **Per-pillar cap** on the pillar subtotal (separate caps for authentication, sender, attachments, content, other — see source).
5. **Cross-pillar bonus:** **+4** if two pillars have evidence, **+10** if three or more.
6. **Total** rounded and capped at **100**. Verdict: **≥75 Malicious**, **≥40 Suspicious**, else **Safe**.

**Content categories:** Gemini returns `category` / `description` / `severity`; each row is stored as **`Content - <tactic>`**. `Analyze_content.py` is a **keyword-only** alternative **not** imported by `main.py`; keep it if you want to swap or combine later.

### Content / LLM (`Analyze_content_ai.py`)

- **Empty mail:** if **body** is empty (after strip) and **subject** is empty or **`no subject`** / **`(no subject)`** (case-insensitive, matching the add-on default), the **Gemini call is skipped** and content findings are `[]`.
- **PII:** subject and body are anonymized before the model; **substrings inside `http://` / `https://` URL spans are left unchanged** so tracking IDs are not rewritten by phone/card-style regexes.
- **Model:** `gemini-2.5-flash`, JSON list response; failures are caught and logged (`print`), content findings empty for that request.

---

## What the scanner looks at

| Layer | Examples |
|--------|-----------|
| **Authentication** | SPF/DKIM/DMARC from `Authentication-Results`; Reply-To vs From; Return-Path domain vs From |
| **Sender** | Typosquatting vs listed domains; display-name branding vs actual domain / free-mail hosts |
| **Attachments** | Double extensions, dangerous extensions, risky MIME, **archives (.zip, .rar, …) as MEDIUM**, high attachment count, large total size (metadata only) |
| **Content (LLM)** | Manipulation tactics as **`Content - …`** rows with severities **1–4** |

There is **no** link-fetching or URL reputation layer in this repo.

---

## Security and trust boundaries

- **Scopes** (`Addon/appsscript.json`): Gmail add-on execute, **current message read-only**, `script.external_request`.
- **Untrusted mail:** no attachment bytes on the wire; no server-side URL crawling.
- **Secrets:** `GEMINI_API_KEY` in `Backend/.env` (gitignored). Copy from `.env.example`.
- **`POST /analyze`:** **unauthenticated** in this repo (demo-friendly). Production would add auth, rate limits, and safer logging.

---

## Prerequisites

- Python **3.10+** (3.9+ usually fine)
- Gmail + test add-on deployment
- [Google AI Studio](https://aistudio.google.com/) API key for Gemini
- **HTTPS** tunnel (e.g. [ngrok](https://ngrok.com/)) if the API runs on your laptop

---

## Backend: local setup

```bash
git clone https://github.com/TheMit23/Gmail_Addon.git
cd Gmail_Addon/Backend
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r ../requirements.txt
```

```bash
# From Backend/
cp ../.env.example .env
# Set GEMINI_API_KEY in Backend/.env
```

```bash
cd Backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Smoke test (no attachments):**

```bash
curl -s -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"sender":"\"PayPal\" <user@gmail.com>","subject":"Urgent verify account","body":"Click here now","reply_to":"bad@evil.com","auth_results":"","return_path":""}'
```

**Example with attachment metadata:**

```bash
curl -s -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"sender":"a@b.com","subject":"files","body":"see attached","attachments":[{"filename":"x.zip","mime_type":"application/zip","size_bytes":1024}]}'
```

Expose port **8000** with ngrok (or deploy the API), then set the add-on URL (below).

---

## Gmail Add-on: configure and deploy

1. [Apps Script](https://script.google.com/) — paste `Addon/Code.js` and manifest bits from `Addon/appsscript.json` per current Google UI.
2. In **`Code.js`**, set `url` to your HTTPS **`…/analyze`** endpoint (placeholder `YOUR-TUNNEL` must be replaced for real use; avoid committing private tunnel URLs if you prefer).
3. Deploy / install the Gmail add-on; open a message and run **Security Scan** from the sidebar.

---

## API contract

**`POST /analyze`** — body matches `EmailData` in `Backend/models.py`:

| Field | Required | Meaning |
|--------|----------|---------|
| `sender` | yes | Raw From |
| `subject` | yes | Subject |
| `body` | yes | Plain body (from `getPlainBody()` in the add-on) |
| `reply_to` | no | Reply-To |
| `auth_results` | no | `Authentication-Results` header |
| `return_path` | no | `Return-Path` header |
| `body_html` | no | Optional in schema; **Apps Script payload does not send it** |
| `attachments` | no | `[{ filename, mime_type, size_bytes }]` |

**Response:** `score`, `verdict`, `findings[]` where each finding has `category`, `description`, `severity` (**integer 0–4**; **INFO rows are omitted** from this array).

---

## Repository layout

```text
Addon/             Gmail card + UrlFetch client
Backend/           FastAPI app and analyzer modules
requirements.txt
.env.example

```

---

## Known limitations

- Attachments: metadata only (no AV / sandbox).
- No URL reputation or redirect analysis.
- Open `/analyze` endpoint.
- Gemini output is parsed with strict `json.loads` on the response text; invalid JSON or bad structure yields no content findings for that request. **`severity` should be numeric (1–4)** in each object—string labels like `"High"` can raise when building `Severity` and trigger the same empty fallback.

