# Demo talk track

## One sentence

taudit maps what executable code can reach after it starts running.

## The doorway

The GitHub poisoned VS Code extension incident is not a taudit claim of prevention. It is a clear market example of the same structural risk: trusted environments often delegate real authority to mutable third-party executable code.

## What the graph shows

The workflow in this demo grants a mutable third-party deploy action:

- repository write authority through `GITHUB_TOKEN`
- package write authority
- OIDC token minting authority
- production secrets
- an artifact produced by an earlier job
- network-capable runner execution

That is not just "an unpinned action." It is production authority delegated to mutable external code.

## Decision rule

Danger condition:

```text
mutable executable + trust-boundary crossing + inherited authority
```

taudit's current CI/CD graph already has the primitives needed to expose this in GitHub Actions, Azure DevOps, GitLab CI, and Bitbucket Pipelines.

## Design-partner prompt

We are mapping how authority flows through CI/CD, developer tools, and agentic coding workflows.

The recent developer-tool compromise story is a useful example of the real failure mode: the problem is not only the malicious object. The problem is the authority it inherits once it starts running.

For CI/CD, that often means mutable third-party actions, reusable workflows, containers, package scripts, or downloaded tools receiving secrets, write tokens, OIDC, deploy, package, or signing authority.

Would it be useful if we mapped one workflow or developer-tool path in your environment and showed exactly what it can reach, what evidence exists, and what would need to rotate if it were compromised?
