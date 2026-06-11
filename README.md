# Trooth Pre-Flight — Compliance-as-Code

Catch compliance gaps in your **pull request**, before code reaches production. Trooth Pre-Flight analyzes the **declared intent** of your infrastructure (a `terraform show -json` plan) against **SOC 2, ISO 27001, and the EU AI Act**, and gives you a Compliance Delta with a one-click Fix-It on every finding.

- **No cloud access required** — it reads your plan, not your environment.
- **Advisory & non-custodial** — Trooth proposes; you merge. We never apply changes to your infrastructure. Your Git history is the rollback.
- **Audit-ready evidence** — every result is hashed and signable, feeding your Trooth Trust Profile and auto-filling CAIQ/SIG questionnaires.

> Pre-Flight proves your declared **intent** is compliant. Pair it with Trooth's read-only drift check (Silver/Gold) to attest that production still matches.

## GitHub Action

```yaml
# .github/workflows/trooth-preflight.yml
name: Trooth Pre-Flight
on:
  pull_request:
    paths: ["**/*.tf", "**/*.tf.json"]
permissions:
  contents: read
  pull-requests: write
jobs:
  preflight:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - run: |
          terraform init -backend=false
          terraform plan -out tf.plan || true
          terraform show -json tf.plan > plan.json
      - uses: dheggietrooth/preflight-action@v1
        with:
          plan-json: plan.json
          comment: "true"     # post the Compliance Delta as a PR comment
          strict: "false"     # advisory; "true" gates the merge
```

## CLI

```bash
terraform plan -out tf.plan && terraform show -json tf.plan > plan.json
npx trooth-preflight plan.json            # human report
npx trooth-preflight plan.json --md        # markdown (PR comment)
npx trooth-preflight plan.json --json      # the Compliance Delta as JSON
npx trooth-preflight plan.json --strict    # exit 1 if verdict is "fail"
```

## API

```
POST https://api.trooth.co/v1/preflight   body: { "plan": <terraform show -json> }
→ { delta, evidence: { digest, signedAt, issuer } }
```

## What it checks (v1)
S3 public access · S3 encryption · RDS encryption · RDS public access · EBS encryption · open SSH/RDP security groups · IAM wildcard-admin · HTTP load balancers · CloudWatch log encryption. Each maps to SOC 2 CC#, ISO 27001 Annex A, and EU AI Act articles, with a Fix-It remediation. Catalog: [`controls.json`](./controls.json).

## License
Apache-2.0. © 2026 Trooth, LLC. "Trooth" and the Trooth marks are trademarks of Trooth, LLC.
