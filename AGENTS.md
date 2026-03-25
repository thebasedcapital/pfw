# pfw — Agent Instructions

You are an AI coding agent on the user's macOS machine. This file tells you how to install and use pfw (Package Firewall) to protect against supply chain attacks.

## Why This Matters

Every `npm install`, `pip install`, `cargo add` you run could install malicious code. The litellm attack exfiltrated SSH keys, AWS creds, and crypto wallets via a single `pip install`. You are running these commands dozens of times per session — without checking.

pfw intercepts all package installs and checks them against 4 vulnerability databases before allowing installation.

## Install pfw

```bash
# Step 1: Install pfw globally
npm install -g github:thebasedcapital/pfw

# Step 2: Start the daemon (checks packages against vuln databases)
pfw daemon start

# Step 3: Activate full enforcement (relocates binaries, requires sudo)
pfw install --yes
```

After install, every `npm install`, `pip install`, `cargo add` etc. is automatically routed through pfw — including yours. No prefix needed.

## Check a Package Before Installing

If you want to manually verify a package before installing:

```bash
pfw check npm <package>@<version>
pfw check pypi <package>@<version>
pfw check cargo <package>@<version>
```

Exit code 0 = clean. Exit code 2 = blocked.

## What Gets Checked

Every install command is checked against these sources in parallel (~200ms):

- **OSV.dev** — known CVEs across all ecosystems
- **GitHub Advisory** — GHSA advisories with severity ratings
- **deps.dev** — OpenSSF Scorecard (flags unmaintained packages)
- **CISA KEV** — actively exploited vulnerabilities

Plus a local blocklist in `~/.pfw.config` (instant, no network).

## If pfw Blocks Something

If you see `[pfw] BLOCKED`, do NOT try to bypass it. The package has a known vulnerability or is on the blocklist. Instead:

1. Tell the user which package was blocked and why
2. Check if a newer, patched version exists
3. Look for an alternative package

## Daemon Management

```bash
pfw daemon start    # start the proxy daemon
pfw daemon status   # check if running
pfw daemon stop     # stop the daemon
```

## Uninstall

```bash
pfw uninstall --yes   # restores original binaries, removes all hooks
```

## Do NOT

- Do not set `PFW_BYPASS=1` — it requires a root-owned token you don't have
- Do not call binaries from `/usr/local/libexec/pfw-real/` directly
- Do not modify `~/.pfw.config` without telling the user
- Do not uninstall pfw without the user explicitly asking
