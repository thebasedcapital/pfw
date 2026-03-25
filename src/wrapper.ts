#!/usr/bin/env node

/**
 * PFW Wrapper — intercepts package manager calls and routes install operations
 * through the pfw proxy daemon for vulnerability scanning.
 *
 * Compiled to a standalone binary and symlinked as npm/pip/cargo/etc.
 * Intercepts ALL invocations: interactive, scripts, CI, cron, rogue agents.
 *
 * Design: zero heavy imports, raw Node.js only, <10ms overhead for non-install paths.
 */

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { basename, join } from "node:path";
import { request } from "node:http";

// ---------------------------------------------------------------------------
// 1. Determine which package manager we're impersonating
// ---------------------------------------------------------------------------

// Resolve which binary we're impersonating from argv[0] (set by exec/symlink),
// NOT argv[1] which could be the script path when run as `node wrapper.js npm`
const invoked = basename(process.argv[1] || process.argv[0]);
// Guard: if invoked name isn't a known package manager, we were called wrong
const KNOWN_MANAGERS = new Set(["npm", "npx", "yarn", "pnpm", "pip", "pip3", "uv", "cargo", "bun", "bunx"]);
if (!KNOWN_MANAGERS.has(invoked)) {
  process.stderr.write(
    `\x1b[31m[pfw] wrapper called as '${invoked}' — not a known package manager.\x1b[0m\n` +
    `\x1b[31m[pfw] This binary must be symlinked as npm/pip/cargo/etc.\x1b[0m\n`
  );
  process.exit(1);
}

// ---------------------------------------------------------------------------
// 2. Install-subcommand detection per package manager
// ---------------------------------------------------------------------------

const INSTALL_COMMANDS: Record<string, Set<string>> = {
  npm:  new Set(["install", "i", "add", "ci", "exec"]),
  npx:  new Set(),  // ALL npx invocations fetch packages — always route through proxy
  yarn: new Set(["add", "install", "dlx"]),
  pnpm: new Set(["add", "install", "i", "dlx"]),
  pip:  new Set(["install"]),
  pip3: new Set(["install"]),
  uv:   new Set(["install", "add"]),   // "uv pip install" handled below
  cargo: new Set(["install", "add"]),
  bun:  new Set(["add", "install", "i"]),
  bunx: new Set(),  // ALL bunx invocations fetch packages — always route through proxy
};

const args = process.argv.slice(2);

function isInstallCommand(): boolean {
  const known = INSTALL_COMMANDS[invoked];
  if (!known) return false;

  // npx/bunx: ALL invocations are install-like (they fetch remote packages)
  if (invoked === "npx" || invoked === "bunx") return true;

  const sub = args[0];
  if (!sub) return false;

  // Special case: `uv pip install ...`
  if (invoked === "uv" && sub === "pip" && args[1] === "install") return true;

  return known.has(sub);
}

// ---------------------------------------------------------------------------
// 3. Resolve the REAL binary
// ---------------------------------------------------------------------------

const realDir = process.env.PFW_REAL_DIR || "/usr/local/libexec/pfw-real";
const realBin = join(realDir, invoked);

function execReal(extraEnv?: Record<string, string>): never {
  if (!existsSync(realBin)) {
    process.stderr.write(
      `\x1b[31m[pfw] Real binary not found: ${realBin}\x1b[0m\n` +
      `\x1b[31m[pfw] Run \`pfw install\` to set up wrapper symlinks and move original binaries.\x1b[0m\n`
    );
    process.exit(127);
  }

  const env = extraEnv ? { ...process.env, ...extraEnv } : process.env;

  try {
    // Use execFileSync in inherit mode — replaces stdio, preserves signals.
    // We can't use actual execvp from pure JS, but sync + inherit + exit is
    // functionally equivalent for wrapper purposes.
    const result = execFileSync(realBin, args, {
      env,
      stdio: "inherit",
      maxBuffer: Infinity,
    });
    process.exit(0);
  } catch (err: any) {
    // execFileSync throws on non-zero exit. Propagate the real exit code.
    process.exit(err.status ?? 1);
  }
}

// ---------------------------------------------------------------------------
// 4. Fast path: non-install commands — zero overhead, immediate exec
// ---------------------------------------------------------------------------

if (!isInstallCommand()) {
  execReal();
}

// ---------------------------------------------------------------------------
// 5. Install path — check bypass, probe daemon, set up proxy
// ---------------------------------------------------------------------------

// PFW_BYPASS requires a token from a root-owned file to prevent rogue agent bypass
if (process.env.PFW_BYPASS === "1") {
  const tokenFile = "/etc/pfw-bypass.token";
  const expectedToken = (() => {
    try { return require("node:fs").readFileSync(tokenFile, "utf-8").trim(); } catch { return null; }
  })();
  if (expectedToken && process.env.PFW_BYPASS_TOKEN === expectedToken) {
    execReal();
  } else {
    process.stderr.write(
      `\x1b[33m[pfw] PFW_BYPASS ignored — requires valid PFW_BYPASS_TOKEN from ${tokenFile}\x1b[0m\n`
    );
  }
}

const DAEMON_URL = "http://127.0.0.1:9338/pfw/health";
const FAIL_ACTION = process.env.PFW_FAIL_ACTION || "warn";

function probeHealth(): Promise<boolean> {
  return new Promise((resolve) => {
    const req = request(DAEMON_URL, { method: "GET", timeout: 500 }, (res) => {
      // Any 2xx from health endpoint = daemon is alive
      resolve(res.statusCode !== undefined && res.statusCode >= 200 && res.statusCode < 300);
      res.resume(); // drain
    });
    req.on("error", () => resolve(false));
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });
    req.end();
  });
}

function proxyEnvForManager(): Record<string, string> {
  const base: Record<string, string> = {
    HTTP_PROXY: "http://127.0.0.1:9338",
    HTTPS_PROXY: "http://127.0.0.1:9338",
    http_proxy: "http://127.0.0.1:9338",
    https_proxy: "http://127.0.0.1:9338",
  };

  // npm/pnpm/yarn registry config
  if (invoked === "npm" || invoked === "pnpm" || invoked === "npx") {
    base["npm_config_registry"] = "http://127.0.0.1:9338";
  }
  if (invoked === "yarn") {
    base["npm_config_registry"] = "http://127.0.0.1:9338";
    base["YARN_REGISTRY"] = "http://127.0.0.1:9338";
  }

  // pip: index-url via env
  if (invoked === "pip" || invoked === "pip3" || invoked === "uv") {
    base["PIP_INDEX_URL"] = "http://127.0.0.1:9338/pypi/simple";
    base["PIP_TRUSTED_HOST"] = "127.0.0.1";
  }

  return base;
}

async function main(): Promise<never> {
  const healthy = await probeHealth();

  if (healthy) {
    // Daemon running — route through proxy
    execReal(proxyEnvForManager());
  }

  // Daemon NOT running — apply fail action
  switch (FAIL_ACTION) {
    case "block":
      process.stderr.write(
        `\x1b[31m[pfw] Package firewall daemon is not running and PFW_FAIL_ACTION=block.\x1b[0m\n` +
        `\x1b[31m[pfw] Refusing to install packages without vulnerability scanning.\x1b[0m\n` +
        `\x1b[31m[pfw] Start the daemon with \`pfw start\` or set PFW_BYPASS=1 to override.\x1b[0m\n`
      );
      process.exit(1);
      break; // unreachable but satisfies TS

    case "allow":
      execReal();
      break; // unreachable

    case "warn":
    default:
      process.stderr.write(
        `\x1b[33m[pfw] Warning: package firewall daemon is not running.\x1b[0m\n` +
        `\x1b[33m[pfw] Packages will be installed WITHOUT vulnerability scanning.\x1b[0m\n` +
        `\x1b[33m[pfw] Start the daemon with \`pfw start\` to enable protection.\x1b[0m\n`
      );
      execReal();
      break; // unreachable
  }

  // Should never reach here, but TypeScript needs it
  process.exit(1);
}

main();
