````md
# DecisionGate Message Triage

Message Triage OS: canonicalize DMs/emails into evidence-backed decision cards (**PASS / DELAY / BLOCK**).

**Demo (Web):** https://shin4141.github.io/decisiongate-triage/scanner/

---

## What it does

Paste a DM/email and get a single **Decision Card**:

- 1-line summary
- Extract URLs/domains/emails/phones
- Gate: **PASS / DELAY / BLOCK** + evidence tags
- Search queries (X / Google / Reddit)
- Shareable short report

---

## Local-first & minimal-share

- **Local-first:** parsing/judgement runs offline in the browser.
- **Deep check (optional / later):** only minimal extracted tokens are queried (no full message upload).

---

## Output

- `Decision Card` JSON (canonical format)
- `Share report` (short + family-friendly one-liner)

---

## Security boundary

- Never send full message text to deep-check providers.
- Evidence is **monotonic** (union; never delete).
- Severity is **max** with ordering: `PASS < DELAY < BLOCK`
- `until` is **max** (latest wins)

---

## Run locally

From repo root:

```bash
python3 -m http.server 5173
````

Open:

* [http://localhost:5173/scanner/](http://localhost:5173/scanner/)

---

## Structure (PIC-style merge)

This project is designed to keep results stable under incremental evidence:

* `evidence = ∪` (union)
* `severity = max(PASS<DELAY<BLOCK)`
* `until = max(datetime)`
* rules + deepcheck + user notes can be merged without order dependence

---

## Milestones

* **M0:** Local card (extract + gate + search links + share report)
* **M1:** Rules `10 → 30` (reduce false positives / improve coverage)
* **M2:** Deep check sources (minimal-share evidence enrichment)

---

## License

MIT


