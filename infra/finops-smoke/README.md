# FinOps smoke (Terraform)

Minimal Terraform used to keep **format**, **validate**, and optional **Infracost**
breakdown in CI. No cloud resources are created (random provider only).

- **GitHub Actions:** [`.github/workflows/finops.yml`](../../.github/workflows/finops.yml)
- **Infracost:** set repository secret `INFRACOST_API_KEY` (free tier at
  [infracost.io](https://www.infracost.io/)) to enable cost breakdown; without
  it, CI still runs `terraform fmt` / `validate`.
