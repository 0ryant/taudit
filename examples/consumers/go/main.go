// oidc_reach: reference consumer for taudit's authority graph.
//
// Targets schema: authority-graph v1.0.0
//   https://github.com/0ryant/taudit/schemas/authority-graph.v1.json
//
// Question answered:
//   "Which Identity nodes have OIDC metadata AND reach a third-party Step?"
//
// Why this matters: an OIDC-capable identity (e.g. GITHUB_TOKEN with
// id-token: write) that is reachable by a third_party step means the
// short-lived federated credential could be minted and consumed inside
// code you do not own. That is the cross-trust OIDC propagation pattern
// downstream tools want to flag.
//
// Output: CSV with one row per (identity, reachable third-party step) pair.
//   identity_name,oidc_audience,reachable_third_party_steps
//
// "oidc_audience" is taken from metadata["audience"] when present (a
// future schema-additive field) and falls back to the documented
// metadata["oidc"] flag value, so the column is meaningful today and
// forward-compatible.
//
// No third-party deps. Build:
//   go build -o oidc_reach .
// Run:
//   taudit graph pipeline.yml --format json | ./oidc_reach /dev/stdin
package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type node struct {
	ID        int               `json:"id"`
	Kind      string            `json:"kind"`
	Name      string            `json:"name"`
	TrustZone string            `json:"trust_zone"`
	Metadata  map[string]string `json:"metadata"`
}

type edge struct {
	ID   int    `json:"id"`
	From int    `json:"from"`
	To   int    `json:"to"`
	Kind string `json:"kind"`
}

type graph struct {
	Nodes []node `json:"nodes"`
	Edges []edge `json:"edges"`
}

type document struct {
	SchemaVersion string `json:"schema_version"`
	Graph         graph  `json:"graph"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <graph.json>\n", os.Args[0])
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var doc document
	if err := json.Unmarshal(raw, &doc); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !strings.HasPrefix(doc.SchemaVersion, "1.") {
		fmt.Fprintf(os.Stderr, "unsupported schema_version: %s (need 1.x)\n", doc.SchemaVersion)
		os.Exit(1)
	}

	g := doc.Graph

	// Forward index: for each identity id, which steps has_access_to it?
	stepsByIdentity := map[int][]int{}
	for _, e := range g.Edges {
		if e.Kind != "has_access_to" {
			continue
		}
		// from is a step (or another identity); to is what's accessed.
		stepsByIdentity[e.To] = append(stepsByIdentity[e.To], e.From)
	}

	w := csv.NewWriter(os.Stdout)
	defer w.Flush()
	_ = w.Write([]string{"identity_name", "oidc_audience", "reachable_third_party_steps"})

	type row struct {
		name, aud string
		reach     []string
	}
	var rows []row

	for _, n := range g.Nodes {
		if n.Kind != "identity" {
			continue
		}
		if n.Metadata["oidc"] != "true" {
			continue
		}
		aud := n.Metadata["audience"]
		if aud == "" {
			aud = n.Metadata["oidc"] // fallback: the flag value itself
		}
		var thirdParty []string
		for _, sid := range stepsByIdentity[n.ID] {
			if g.Nodes[sid].Kind == "step" && g.Nodes[sid].TrustZone == "third_party" {
				thirdParty = append(thirdParty, g.Nodes[sid].Name)
			}
		}
		if len(thirdParty) == 0 {
			continue
		}
		sort.Strings(thirdParty)
		rows = append(rows, row{n.Name, aud, thirdParty})
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
	for _, r := range rows {
		_ = w.Write([]string{r.name, r.aud, strings.Join(r.reach, ";")})
	}
}
