# Test Artifacts

This directory contains synthetic fixtures for local smoke testing. Values are intentionally fake and are used to exercise Vault token, AppRole, AWS IAM, and Database Secrets Engine detection paths.

Run:

```bash
python main.py --hijack-path ./test-artifacts --no-git-history --min-severity HIGH
```
