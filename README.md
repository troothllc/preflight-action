# Trooth Pre-Flight

Catch security and compliance gaps in your infrastructure plan inside the **pull request**, before code reaches production. Trooth Pre-Flight reads the **declared intent** of your infrastructure (a `terraform show -json` plan) against **SOC 2, ISO 27001, and the EU AI Act**, and returns a Compliance Delta with a one-click Fix-It on every finding.

| Property | What it means |
| --- | --- |
| No cloud access | It reads your plan, not your environment. |
| Advisory and non-custodial | Trooth proposes; you merge. We never apply changes to your infrastructure. Your Git history is the rollback. |
| Signable evidence | Every result is hashed and signable, feeding your Trooth trust record and auto-filling CAIQ and SIG questionnaires. |

Pre-Flight reads your declared intent. Pair it with Trooth's read-only drift check to confirm that production still matches.

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
      - uses: troothllc/preflight-action@v1
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
-> { delta, evidence: { digest, signedAt, issuer } }
```

## What it checks (v1)
S3 public access · S3 encryption · RDS encryption · RDS public access · EBS encryption · open SSH/RDP security groups · IAM wildcard-admin · HTTP load balancers · CloudWatch log encryption. Each maps to SOC 2 CC#, ISO 27001 Annex A, and EU AI Act articles, with a Fix-It remediation. Catalog: [`controls.json`](./controls.json).

## About Trooth

Trooth is the witnessed trust network for software and AI companies. Pre-Flight is the build side; the read side is a public trust record buyers and their AI agents check with no login. Get witnessed at [trooth.co/signup](https://trooth.co/signup).

## License
Apache-2.0. © 2026 Trooth, LLC. "Trooth" and the Trooth marks are trademarks of Trooth, LLC.
