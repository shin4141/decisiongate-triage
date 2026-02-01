# Decision Card Schema (SSOT)

## Top-level
- id: string
- summary_1l: string
- intent: string
- asks: string[]
- risk_factors: string[]
- extracted: object
- gate: object
- search: object
- share_report: object
- deepcheck: object

## Gate
- severity: PASS | DELAY | BLOCK
- until_iso: string | null
- reasons: string[]        # rule ids
- evidence: string[]       # monotonic union (never delete)

## Merge rule (PIC)
- severity = max(PASS<DELAY<BLOCK)
- until_iso = max(datetime)
- evidence = union(set)
- reasons = union(set)
