# DecisionGate Message Triage

Message Triage OS: canonicalize DMs/emails into evidence-backed decision cards (PASS/DELAY/BLOCK).
- Local-first: parsing/judgement runs offline.
- Deep check (optional): only minimal extracted tokens are queried (no full message upload).

## Output
A single "Decision Card" JSON + shareable short report.

## Security boundary
- Never send full message text to deep-check providers.
- Evidence is monotonic (union); severity is max(PASS<DELAY<BLOCK); until is max.

## Milestones
- M0: Local card (extract + gate + search links + share report)
- M1: Rules 10 → 30
- M2: Deep check sources
