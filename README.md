# E2E Vulnerable App

Minimal Node.js app with **intentional** security issues for testing the Constantine pipeline end-to-end (ingest → detect → review → exploit → patch → report).

**Do not use in production.**

## Vulnerabilities

- **Command injection** in `/ping` (query param `host` passed to `exec()`).
- **Command injection** in `/whoami` (query param `user` concatenated into `execSync("id " + user)`).

CWE-78 (OS Command Injection).

## Running the full pipeline

From the Constantine repo root:

```bash
# Full pipeline (ingest → detect → review → exploit → patch → report)
go run ./cmd/constantine run \
  -t "$(pwd)/tests/e2e-vulnerable-app" \
  -c configs/deltascan-repo-full.yaml
```

Output goes to `runs/<run_id>/`. After the run completes, verify stage outputs:

```bash
./scripts/verify_e2e_run.sh runs/<run_id>
```

Expected flow:

| Stage   | Outputs |
|---------|---------|
| Ingest  | `ingest/deltascan-repo/files.json`, `diff.json`, `chunks.json` |
| Detect  | `detect/deltascan-scanner/findings.json` (file_path, line_range, cwe_id, type) |
| Review  | `review/deltascan-reviewer/verified_findings.json`, `review_summary.json` |
| Exploit | `exploit/deltascan-exploiter/exploit_results.json`, `evidence/`, `manifest.json` |
| Patch   | `patch/llm-patcher/patch_index.json`, `patches/*.patch` (only if any finding is EXPLOITABLE) |
| Report  | `report/markdown-report/report.json`, `report.md` (findings + exploit results + review status) |
