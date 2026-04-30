# No billable cloud resources — Infracost / validate wiring only.
resource "random_id" "finops_smoke" {
  byte_length = 4
}

output "finops_smoke_hex" {
  description = "Stable dummy output for CI smoke."
  value       = random_id.finops_smoke.hex
}
