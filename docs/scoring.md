# Deterministic scoring and coverage

## Separate security posture from collection completeness

A `finding` is a rule violation; `unknown`, `error`, and `not_run` indicate missing evidence. Treating network failures as passed checks is prohibited.

Initial category weights (configuration can override via versioned policy):

| Category | Weight |
|---|---:|
| TLS | 30% |
| HTTP headers | 30% |
| Cookies | 15% |
| DNS + email | 25% |

Domain, location, ASN, timing, and discovery evidence are informational unless explicitly assigned scored rules. This makes scores comparable without pretending every data field is a vulnerability.

## Algorithm v1

1. For each rule, determine `applicable` based on target type and observed features **independently of pass/fail**.
2. Assign stable rule weight (for example, 1–5) and evaluate `pass`, `fail`, `not_applicable`, `unknown`, `error`, or `not_run`.
3. `evaluable_weight` = sum of weights for `pass`/`fail`; `failed_weight` = sum of weighted penalties for `fail` (cap penalty at rule weight). `category_raw_score = 100 × (1 - failed_weight/evaluable_weight)`.
4. `category_coverage = evaluable_applicable_weight / expected_applicable_weight`, where expected is planned applicable weight including unknown/error/not_run. If applicability could not be determined, count as coverage deficiency in planned evaluation estimates rather than dropping it silently.
5. Compute `coverage` across all planned scored rules as the total evaluable weight / total planned applicable-or-undetermined weight.
6. If overall coverage < configured `minimum_score_coverage` (default 0.80), return `score: null`, `score_status: insufficient_evidence`. Never silently renormalize away an entire requested category.
7. For eligible scores, categories with applicable evaluable rules are normalized to sum to 1, **subject to** the coverage minimum. `overall_score = round(sum(effective_category_weight × category_raw_score))`.
8. Always output category score, coverage, rule counts, original policy version and effective policy for auditability.

**Example:** TLS 90 at 30%, headers 70 at 30%, cookies 80 at 15%, DNS/email 60 at 25% yields `75`. But if HTTP checks fail to execute and the scan falls below coverage threshold, score is `null`, not a possibly misleading higher number.

## CI policy

`--fail-on high`: exit 1 for any `high` or `critical` finding. `--min-coverage 0.85`: exit 3 if coverage < 0.85, independent of finding threshold. Handle explicit scanner failure separately from findings; the score does not determine CI exit code unless an explicitly named future `--fail-below-score` flag is added.

Rule catalog and scoring algorithm must be versioned, deterministic and golden-tested. A policy can disable a rule but the report must reflect it as excluded from scoring, with clear reason.
