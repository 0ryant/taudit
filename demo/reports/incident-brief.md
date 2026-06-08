# GitHub poisoned VS Code extension incident brief

Date prepared: 2026-05-20

## Bottom line

Current evidence supports this wording:

> GitHub reported unauthorized access to GitHub-internal repositories after an employee device was compromised through a poisoned VS Code extension.

Do not call it a confirmed customer data leak unless GitHub publishes new evidence. GitHub's public line, as reported by multiple sources, is that it currently has no evidence of impact to customer information stored outside GitHub-internal repositories.

## Confirmed / strongly supported

- GitHub investigated unauthorized access to internal repositories on 2026-05-19 / 2026-05-20.
- GitHub said the incident involved a compromised employee device and a poisoned VS Code extension.
- GitHub said it removed the malicious extension version, isolated the endpoint, and began incident response.
- GitHub said the attacker claim of roughly 3,800 repositories was directionally consistent with its investigation.
- GitHub said critical secrets were rotated and follow-on activity was being monitored.

## Claimed / provisional

- TeamPCP claimed access to roughly 4,000 private/internal GitHub repositories and offered data for sale.
- The exact extension name/version has not been publicly named by GitHub in the sources reviewed.
- A direct Mini Shai-Hulud link is plausible context from security blogs, but not official attribution.
- Final blast radius, credential exposure, and customer impact remain pending until GitHub publishes a fuller report.

## Why this is taudit-shaped

The VS Code extension case is an endpoint/developer-tool compromise, so current taudit should not claim direct detection.

The structural failure is still the taudit problem:

```text
mutable executable code
  + trusted execution context
  + inherited file/token/repo/network authority
  = hidden authority path
```

For CI/CD, the clean demo version is:

```text
mutable third-party action
  + secrets
  + write token
  + OIDC
  + package/deploy authority
  = production authority delegated to mutable external code
```

## Sources

- [GitHub initial X statement](https://x.com/github/status/2056884788179726685): primary source; text visible via secondary embeds.
- [GitHub follow-up X thread](https://x.com/github/status/2056949169701720157): primary source; text visible via secondary embeds.
- [BleepingComputer, 2026-05-20](https://www.bleepingcomputer.com/news/security/github-confirms-breach-of-3-800-repos-via-malicious-vscode-extension/amp/): reports GitHub confirmation, roughly 3,800 internal repos, endpoint isolation, extension removal, and no evidence of customer data impact outside affected repos.
- [Aikido, 2026-05-20](https://www.aikido.dev/blog/github-breached-vs-code-extension): contextualizes developer-device and extension-marketplace risk; useful but vendor-positioned.
- [Hive Security, 2026-05-20](https://hivesecurity.gitlab.io/blog/github-breach-vscode-extension-teampcp-2026/): separates confirmed facts from actor claims; treats Mini Shai-Hulud linkage as unconfirmed.
- [GitHub Actions secure-use docs](https://docs.github.com/en/actions/reference/security/secure-use): GitHub says full-length SHA pinning is currently the only immutable release method for actions and warns mutable tags can move.
- [VS Code extension runtime security](https://code.visualstudio.com/docs/configure/extensions/extension-runtime-security): VS Code docs say extensions run with the same permissions as VS Code, including file, network, process, and workspace-setting authority.
- [VS Code enterprise extension controls](https://code.visualstudio.com/docs/enterprise/extensions): VS Code documents allowed-extension controls by publisher, extension, version, and platform.
