# oidc_reach (Go reference consumer)

Single-file Go program that reads a taudit authority-graph JSON and emits
CSV rows for every OIDC-capable identity that is reachable by a step in a
different trust zone (`third_party`).

## Build

```sh
cd examples/consumers/go
go build -o oidc_reach .
```

No third-party dependencies — `encoding/json`, `encoding/csv`, `os`,
`sort`, `strings`, `fmt` only. Standard library Go 1.21+.

## Run

```sh
taudit graph path/to/pipeline.yml --format json > /tmp/g.json
./oidc_reach /tmp/g.json
```

Output (CSV with header):

```
identity_name,oidc_audience,reachable_third_party_steps
GITHUB_TOKEN,true,build[0]
```

## What it proves

The schema is consumable in a strongly-typed language using only the
documented field names — no taudit Rust code is linked, no shared types
are imported. If this program stops working without a `schema_version`
bump to `2.x`, taudit broke its semver promise.
