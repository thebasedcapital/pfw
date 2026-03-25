/**
 * PFW Installer — sets up airtight package manager interception on macOS.
 *
 * `pfw install`   — wrapper symlinks, PATH enforcement, registry hooks, launchd daemon
 * `pfw uninstall` — reverses everything cleanly
 *
 * Requires sudo for /usr/local and /etc operations.
 * Pass --yes to skip confirmation prompts.
 */

import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const HOME = os.homedir();
const WRAPPER_DIR = "/usr/local/libexec/pfw";
const REAL_DIR = "/usr/local/libexec/pfw-real";
const PATHS_D_FILE = "/etc/paths.d/00-pfw";
const LAUNCHD_LABEL = "com.user.pfw";
const LAUNCHD_PLIST = path.join(HOME, "Library/LaunchAgents", `${LAUNCHD_LABEL}.plist`);
const DAEMON_LOG = path.join(HOME, ".pfw/daemon.log");
const PFW_BIN = path.join(HOME, ".local/bin/pfw");
const WRAPPER_BIN = path.join(HOME, ".local/bin/pfw-wrapper");
const PROXY_PORT = 9338;
const PROXY_HOST = "127.0.0.1";

const PACKAGE_MANAGERS = [
  "npm", "npx", "yarn", "pnpm", "pip", "pip3", "uv", "cargo", "bun", "bunx",
] as const;

type PkgMgr = (typeof PACKAGE_MANAGERS)[number];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface StepResult {
  step: string;
  ok: boolean;
  message: string;
}

const results: StepResult[] = [];

function record(step: string, ok: boolean, message: string): void {
  results[results.length] = { step, ok, message };
  const icon = ok ? "\x1b[32m✓\x1b[0m" : "\x1b[31m✗\x1b[0m";
  console.log(`  ${icon} ${step}: ${message}`);
}

function run(cmd: string, opts?: { sudo?: boolean; ignoreError?: boolean }): string {
  const full = opts?.sudo ? `sudo ${cmd}` : cmd;
  try {
    return execSync(full, { encoding: "utf-8", stdio: ["inherit", "pipe", "pipe"] }).trim();
  } catch (err: any) {
    if (opts?.ignoreError) return "";
    throw err;
  }
}

function whichBin(name: string): string | null {
  try {
    // Use /usr/bin/which to avoid hitting our own wrappers
    const result = execSync(`/usr/bin/which ${name}`, {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
      env: {
        ...process.env,
        // Strip our wrapper dir from PATH so we find the real binary
        PATH: (process.env.PATH || "")
          .split(":")
          .filter((p) => p !== WRAPPER_DIR)
          .join(":"),
      },
    }).trim();
    return result || null;
  } catch {
    return null;
  }
}

function resolveSymlink(p: string): string {
  try {
    return fs.realpathSync(p);
  } catch {
    return p;
  }
}

function ensureDir(dir: string): void {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

// ---------------------------------------------------------------------------
// Install steps
// ---------------------------------------------------------------------------

function createDirectories(): void {
  try {
    run(`mkdir -p ${WRAPPER_DIR}`, { sudo: true });
    run(`mkdir -p ${REAL_DIR}`, { sudo: true });
    // Restrict real binary dir: root-only listing prevents rogue agents from discovering binary names
    // 0711 = owner rwx, group/others execute-only (can exec if you know the path, can't list)
    run(`chmod 0711 ${REAL_DIR}`, { sudo: true });
    record("Create directories", true, `${WRAPPER_DIR} + ${REAL_DIR} (0711: no listing)`);
  } catch (err: any) {
    record("Create directories", false, err.message);
  }
}

function relocateBinaries(): void {
  const found: string[] = [];
  const missing: string[] = [];

  for (const name of PACKAGE_MANAGERS) {
    const loc = whichBin(name);
    if (!loc) {
      missing.push(name);
      continue;
    }

    const realPath = resolveSymlink(loc);
    const dest = path.join(REAL_DIR, name);

    // Don't overwrite if already copied (idempotent)
    if (fs.existsSync(dest)) {
      found.push(name);
      continue;
    }

    try {
      run(`cp "${realPath}" "${dest}"`, { sudo: true });
      run(`chmod +x "${dest}"`, { sudo: true });
      found.push(name);
    } catch (err: any) {
      record(`Copy ${name}`, false, err.message);
    }
  }

  if (found.length > 0) {
    record("Relocate binaries", true, `Copied: ${found.join(", ")}`);
  }
  if (missing.length > 0) {
    record("Relocate binaries (skipped)", true, `Not found: ${missing.join(", ")}`);
  }
}

function installWrapperSymlinks(): void {
  if (!fs.existsSync(WRAPPER_BIN)) {
    record("Wrapper symlinks", false, `Wrapper binary not found at ${WRAPPER_BIN}`);
    return;
  }

  const linked: string[] = [];

  for (const name of PACKAGE_MANAGERS) {
    const dest = path.join(WRAPPER_DIR, name);
    try {
      // Atomic symlink replace: create temp, then rename (mv is atomic on same fs)
      const tmp = `${dest}.pfw-tmp`;
      run(`ln -sf "${WRAPPER_BIN}" "${tmp}"`, { sudo: true });
      run(`mv -f "${tmp}" "${dest}"`, { sudo: true });
      linked.push(name);
    } catch (err: any) {
      record(`Symlink ${name}`, false, err.message);
    }
  }

  if (linked.length > 0) {
    record("Wrapper symlinks", true, linked.join(", "));
  }
}

function enforcePathsD(): void {
  try {
    run(`bash -c 'echo "${WRAPPER_DIR}" | sudo tee ${PATHS_D_FILE} > /dev/null'`);
    record("PATH enforcement", true, `${PATHS_D_FILE} → ${WRAPPER_DIR}`);
  } catch (err: any) {
    record("PATH enforcement", false, err.message);
  }
}

function enforceLaunchctlPath(): void {
  const pathStr = `${WRAPPER_DIR}:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin`;
  try {
    run(`launchctl config user path ${pathStr}`, { sudo: true });
    record("launchctl PATH", true, "Persistent across reboots");
  } catch (err: any) {
    record("launchctl PATH", false, err.message);
  }
}

function configureNpmRegistry(): void {
  const npmrcPath = path.join(HOME, ".npmrc");
  const registryLine = `registry=http://${PROXY_HOST}:${PROXY_PORT}`;

  try {
    let content = "";
    if (fs.existsSync(npmrcPath)) {
      content = fs.readFileSync(npmrcPath, "utf-8");
    }

    // Remove existing registry line, then add ours
    const lines = content.split("\n").filter((l) => !l.startsWith("registry="));
    lines.push(registryLine);
    fs.writeFileSync(npmrcPath, lines.filter((l) => l.trim() !== "" || lines.indexOf(l) === lines.length - 1).join("\n") + "\n");
    record("npm registry", true, `${npmrcPath} → ${registryLine}`);
  } catch (err: any) {
    record("npm registry", false, err.message);
  }
}

function configurePipIndex(): void {
  const pipDir = path.join(HOME, ".config/pip");
  const pipConf = path.join(pipDir, "pip.conf");

  try {
    ensureDir(pipDir);

    const content = `[global]
index-url = http://${PROXY_HOST}:${PROXY_PORT}/simple/
trusted-host = ${PROXY_HOST}
`;

    fs.writeFileSync(pipConf, content);
    record("pip index", true, pipConf);
  } catch (err: any) {
    record("pip index", false, err.message);
  }
}

function configureCargoProxy(): void {
  const cargoConfig = path.join(HOME, ".cargo/config.toml");

  try {
    let content = "";
    if (fs.existsSync(cargoConfig)) {
      content = fs.readFileSync(cargoConfig, "utf-8");
    }

    const proxyBlock = `\n[http]\nproxy = "http://${PROXY_HOST}:${PROXY_PORT}"\n`;

    // Don't duplicate if already present
    if (content.includes(`proxy = "http://${PROXY_HOST}:${PROXY_PORT}"`)) {
      record("cargo proxy", true, "Already configured");
      return;
    }

    fs.writeFileSync(cargoConfig, content + proxyBlock);
    record("cargo proxy", true, cargoConfig);
  } catch (err: any) {
    record("cargo proxy", false, err.message);
  }
}

function installLaunchdPlist(): void {
  const plistContent = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${PFW_BIN}</string>
        <string>daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${DAEMON_LOG}</string>
    <key>StandardErrorPath</key>
    <string>${DAEMON_LOG}</string>
</dict>
</plist>
`;

  try {
    // Ensure log directory exists
    ensureDir(path.dirname(DAEMON_LOG));

    // Ensure LaunchAgents directory exists
    ensureDir(path.dirname(LAUNCHD_PLIST));

    // Unload existing if loaded (ignore errors)
    run(`launchctl unload "${LAUNCHD_PLIST}"`, { ignoreError: true });

    fs.writeFileSync(LAUNCHD_PLIST, plistContent);
    run(`launchctl load "${LAUNCHD_PLIST}"`);
    record("launchd daemon", true, `${LAUNCHD_LABEL} loaded`);
  } catch (err: any) {
    record("launchd daemon", false, err.message);
  }
}

// ---------------------------------------------------------------------------
// Uninstall steps
// ---------------------------------------------------------------------------

function unloadDaemon(): void {
  try {
    run(`launchctl unload "${LAUNCHD_PLIST}"`, { ignoreError: true });
    record("Stop daemon", true, `${LAUNCHD_LABEL} unloaded`);
  } catch (err: any) {
    record("Stop daemon", false, err.message);
  }
}

function removePathsD(): void {
  try {
    if (fs.existsSync(PATHS_D_FILE)) {
      run(`rm "${PATHS_D_FILE}"`, { sudo: true });
    }
    record("Remove paths.d", true, PATHS_D_FILE);
  } catch (err: any) {
    record("Remove paths.d", false, err.message);
  }
}

function removeWrapperDir(): void {
  try {
    if (fs.existsSync(WRAPPER_DIR)) {
      run(`rm -rf "${WRAPPER_DIR}"`, { sudo: true });
    }
    record("Remove wrappers", true, WRAPPER_DIR);
  } catch (err: any) {
    record("Remove wrappers", false, err.message);
  }
}

function unconfigureNpmRegistry(): void {
  const npmrcPath = path.join(HOME, ".npmrc");

  try {
    if (!fs.existsSync(npmrcPath)) {
      record("Restore npm registry", true, "No .npmrc found");
      return;
    }

    const content = fs.readFileSync(npmrcPath, "utf-8");
    const filtered = content
      .split("\n")
      .filter((l) => !l.startsWith(`registry=http://${PROXY_HOST}:${PROXY_PORT}`))
      .join("\n");

    fs.writeFileSync(npmrcPath, filtered);
    record("Restore npm registry", true, "Removed pfw registry override");
  } catch (err: any) {
    record("Restore npm registry", false, err.message);
  }
}

function unconfigurePipIndex(): void {
  const pipConf = path.join(HOME, ".config/pip/pip.conf");

  try {
    if (!fs.existsSync(pipConf)) {
      record("Restore pip config", true, "No pip.conf found");
      return;
    }

    const content = fs.readFileSync(pipConf, "utf-8");
    // If the file is entirely our config, remove it
    if (content.includes(`index-url = http://${PROXY_HOST}:${PROXY_PORT}`)) {
      fs.unlinkSync(pipConf);
      record("Restore pip config", true, "Removed pfw pip.conf");
    } else {
      record("Restore pip config", true, "pip.conf not modified by pfw");
    }
  } catch (err: any) {
    record("Restore pip config", false, err.message);
  }
}

function unconfigureCargoProxy(): void {
  const cargoConfig = path.join(HOME, ".cargo/config.toml");

  try {
    if (!fs.existsSync(cargoConfig)) {
      record("Restore cargo config", true, "No config.toml found");
      return;
    }

    const content = fs.readFileSync(cargoConfig, "utf-8");
    const proxyBlock = `\n[http]\nproxy = "http://${PROXY_HOST}:${PROXY_PORT}"\n`;

    if (content.includes(proxyBlock)) {
      fs.writeFileSync(cargoConfig, content.replace(proxyBlock, ""));
      record("Restore cargo config", true, "Removed pfw proxy block");
    } else {
      // Try a more lenient match
      const lines = content.split("\n");
      const filtered: string[] = [];
      let skipSection = false;

      for (const line of lines) {
        if (line.trim() === "[http]") {
          skipSection = true;
          continue;
        }
        if (skipSection && line.trim().startsWith("proxy =") && line.includes(`${PROXY_HOST}:${PROXY_PORT}`)) {
          skipSection = false;
          continue;
        }
        if (skipSection && line.trim().startsWith("[")) {
          skipSection = false;
        }
        if (!skipSection) {
          filtered.push(line);
        }
      }

      fs.writeFileSync(cargoConfig, filtered.join("\n"));
      record("Restore cargo config", true, "Removed pfw proxy entry");
    }
  } catch (err: any) {
    record("Restore cargo config", false, err.message);
  }
}

function removePlist(): void {
  try {
    if (fs.existsSync(LAUNCHD_PLIST)) {
      fs.unlinkSync(LAUNCHD_PLIST);
    }
    record("Remove plist", true, LAUNCHD_PLIST);
  } catch (err: any) {
    record("Remove plist", false, err.message);
  }
}

// ---------------------------------------------------------------------------
// Lulu Firewall Integration (Layer 3: network-level enforcement)
// ---------------------------------------------------------------------------

const LULU_CLI = "/opt/homebrew/bin/lulu-cli";

function hasLulu(): boolean {
  try {
    execSync(`${LULU_CLI} list 2>/dev/null`, { encoding: "utf-8", stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

/**
 * Block real binaries from making outbound connections directly.
 * Only the pfw proxy (which runs checks) should talk to registries.
 * If a rogue agent calls /usr/local/libexec/pfw-real/npm directly,
 * Lulu blocks it at the network level.
 */
function configureLuluRules(): void {
  if (!hasLulu()) {
    record("Lulu firewall", false, "lulu-cli not found — install with: brew install woop/tap/lulu-cli");
    return;
  }

  const blocked: string[] = [];
  const skipped: string[] = [];

  for (const name of PACKAGE_MANAGERS) {
    const realBin = path.join(REAL_DIR, name);
    if (!fs.existsSync(realBin)) {
      skipped.push(name);
      continue;
    }

    // Resolve symlinks to get the actual binary path (Lulu matches on real path)
    let targetPath = realBin;
    try {
      targetPath = fs.realpathSync(realBin);
    } catch {
      // Use as-is if realpath fails
    }

    try {
      // Add block rule: deny all outbound from the real binary
      run(
        `${LULU_CLI} add --key "${targetPath}" --path "${targetPath}" --action block --addr "*" --port "*"`,
        { sudo: true }
      );
      blocked.push(name);
    } catch {
      // Rule may already exist — not an error
      skipped.push(name);
    }
  }

  // Also block common bypass tools from reaching registry domains
  // (curl, wget can download tarballs directly)
  const bypassTools = ["/usr/bin/curl", "/usr/bin/wget", "/opt/homebrew/bin/wget"];
  const registryAddrs = [
    // npm
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    // pypi
    "pypi.org",
    "files.pythonhosted.org",
    // cargo/rust
    "crates.io",
    "static.crates.io",
    "index.crates.io",
    "static.rust-lang.org",
    // go
    "proxy.golang.org",
    "sum.golang.org",
    // ruby
    "rubygems.org",
    // maven
    "repo.maven.apache.org",
    "repo1.maven.org",
    // nuget
    "api.nuget.org",
  ];

  for (const tool of bypassTools) {
    if (!fs.existsSync(tool)) continue;
    for (const addr of registryAddrs) {
      try {
        run(
          `${LULU_CLI} add --key "${tool}" --path "${tool}" --action block --addr "${addr}" --port "443"`,
          { sudo: true }
        );
      } catch {
        // May already exist
      }
    }
  }

  // Reload Lulu to apply rules
  try {
    run(`${LULU_CLI} reload`, { sudo: true });
  } catch {
    // Reload failure is non-fatal — rules apply on next Lulu restart
  }

  if (blocked.length > 0) {
    record("Lulu firewall", true, `Blocked direct network for: ${blocked.join(", ")}. Registry domains blocked for curl/wget.`);
  } else {
    record("Lulu firewall", true, "Rules already configured (skipped: " + skipped.join(", ") + ")");
  }
}

function unconfigureLuluRules(): void {
  if (!hasLulu()) {
    record("Lulu firewall", false, "lulu-cli not found — skipping");
    return;
  }

  const removed: string[] = [];

  for (const name of PACKAGE_MANAGERS) {
    const realBin = path.join(REAL_DIR, name);
    let targetPath = realBin;
    try { targetPath = fs.realpathSync(realBin); } catch {}

    try {
      run(`${LULU_CLI} delete --key "${targetPath}"`, { sudo: true });
      removed.push(name);
    } catch {
      // Rule may not exist
    }
  }

  // Remove registry blocks from curl/wget
  const bypassTools = ["/usr/bin/curl", "/usr/bin/wget", "/opt/homebrew/bin/wget"];
  for (const tool of bypassTools) {
    try {
      // Delete only pfw-added rules (by matching registry addresses)
      const registryAddrs = [
        "registry.npmjs.org", "registry.yarnpkg.com",
        "pypi.org", "files.pythonhosted.org",
        "crates.io", "static.crates.io", "index.crates.io", "static.rust-lang.org",
        "proxy.golang.org", "sum.golang.org",
        "rubygems.org",
        "repo.maven.apache.org", "repo1.maven.org",
        "api.nuget.org",
      ];
      for (const addr of registryAddrs) {
        run(`${LULU_CLI} delete-match --key "${tool}" --action block --addr "${addr}" --port "443"`, { sudo: true });
      }
    } catch {
      // Not found — fine
    }
  }

  try {
    run(`${LULU_CLI} reload`, { sudo: true });
  } catch {}

  record("Lulu firewall", true, removed.length > 0 ? `Removed rules for: ${removed.join(", ")}` : "No rules to remove");
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function install(flags: { yes?: boolean }): Promise<void> {
  console.log("\n\x1b[1m[pfw] Installing package firewall enforcement\x1b[0m\n");

  if (!flags.yes) {
    console.log("This will:");
    console.log(`  1. Create ${WRAPPER_DIR} and ${REAL_DIR}`);
    console.log(`  2. Copy real package manager binaries to ${REAL_DIR}`);
    console.log(`  3. Install wrapper symlinks in ${WRAPPER_DIR}`);
    console.log(`  4. Add ${PATHS_D_FILE} for PATH priority`);
    console.log(`  5. Configure launchctl persistent PATH`);
    console.log(`  6. Set npm/pip/cargo to route through pfw proxy`);
    console.log(`  7. Install and load launchd daemon`);
    console.log(`  8. Configure Lulu firewall rules (if installed)`);
    console.log("");
    console.log("\x1b[33mRequires sudo for system-level operations.\x1b[0m");
    console.log("Run with --yes to skip this prompt.\n");
    process.exit(1);
  }

  // Pre-flight checks
  if (!fs.existsSync(WRAPPER_BIN)) {
    console.error(`\x1b[31m[pfw] Wrapper binary not found at ${WRAPPER_BIN}\x1b[0m`);
    console.error(`[pfw] Build and install it first (e.g. npm run build && npm link)`);
    process.exit(1);
  }

  if (!fs.existsSync(PFW_BIN)) {
    console.error(`\x1b[31m[pfw] pfw binary not found at ${PFW_BIN}\x1b[0m`);
    console.error(`[pfw] Install pfw first`);
    process.exit(1);
  }

  // Step 1-2: Directories
  createDirectories();

  // Step 3: Locate and copy real binaries
  relocateBinaries();

  // Step 4: Wrapper symlinks
  installWrapperSymlinks();

  // Step 5: PATH enforcement
  enforcePathsD();

  // Step 6: launchctl PATH
  enforceLaunchctlPath();

  // Step 7: Package manager config hooks
  configureNpmRegistry();
  configurePipIndex();
  configureCargoProxy();

  // Step 8: launchd daemon
  installLaunchdPlist();

  // Step 9: Lulu firewall (Layer 3 — network-level enforcement)
  configureLuluRules();

  // Summary
  printSummary("Install");

  // Post-install verification: prove it works
  if (results.every(r => r.ok)) {
    console.log("\x1b[1m[pfw] Verification — testing against known-malicious package...\x1b[0m\n");
    try {
      const { checkPackage } = await import('./api.js');
      const { loadConfig } = await import('./config.js');
      const config = loadConfig();

      const testPkg = { name: 'event-stream', version: '3.3.6', kind: 'npm' as const, purl: 'pkg:npm/event-stream@3.3.6' };
      const decision = await checkPackage(testPkg, config);
      if (decision.action === 'block') {
        console.log("  \x1b[32m✓\x1b[0m event-stream@3.3.6 → \x1b[31mBLOCKED\x1b[0m (known supply chain attack)");
      } else {
        console.log("  \x1b[33m!\x1b[0m event-stream@3.3.6 → " + decision.action + " (expected block — check .pfw.config)");
      }

      const cleanPkg = { name: 'express', version: '4.21.0', kind: 'npm' as const, purl: 'pkg:npm/express@4.21.0' };
      const cleanDecision = await checkPackage(cleanPkg, config);
      if (cleanDecision.action === 'allow') {
        console.log("  \x1b[32m✓\x1b[0m express@4.21.0     → \x1b[32mALLOWED\x1b[0m (clean package)");
      } else {
        console.log("  \x1b[33m!\x1b[0m express@4.21.0     → " + cleanDecision.action);
      }

      console.log("\n  \x1b[32mPackage firewall is working.\x1b[0m Ready to protect.\n");
    } catch {
      console.log("  \x1b[33m!\x1b[0m Verification skipped (daemon not reachable yet — starts on next boot)\n");
    }
  }
}

export async function uninstall(flags: { yes?: boolean }): Promise<void> {
  console.log("\n\x1b[1m[pfw] Uninstalling package firewall enforcement\x1b[0m\n");

  if (!flags.yes) {
    console.log("This will:");
    console.log("  1. Stop and unload the launchd daemon");
    console.log(`  2. Remove ${PATHS_D_FILE}`);
    console.log(`  3. Remove wrapper symlinks from ${WRAPPER_DIR}`);
    console.log(`  4. Keep real binaries in ${REAL_DIR} (safe)`);
    console.log("  5. Remove npm/pip/cargo registry overrides");
    console.log("  6. Remove the launchd plist");
    console.log("  7. Remove Lulu firewall rules (if configured)");
    console.log("");
    console.log("\x1b[33mRequires sudo for system-level operations.\x1b[0m");
    console.log("Run with --yes to skip this prompt.\n");
    process.exit(1);
  }

  // Step 1: Stop daemon
  unloadDaemon();

  // Step 2: Remove paths.d
  removePathsD();

  // Step 3: Remove wrapper dir
  removeWrapperDir();

  // Step 4: Keep pfw-real — nothing to do
  record("Keep real binaries", true, `${REAL_DIR} preserved`);

  // Step 5: Remove registry overrides
  unconfigureNpmRegistry();
  unconfigurePipIndex();
  unconfigureCargoProxy();

  // Step 6: Remove plist
  removePlist();

  // Step 7: Remove Lulu rules
  unconfigureLuluRules();

  // Summary
  printSummary("Uninstall");
}

function printSummary(operation: string): void {
  const failed = results.filter((r) => !r.ok);
  const passed = results.filter((r) => r.ok);

  console.log(`\n\x1b[1m[pfw] ${operation} summary\x1b[0m`);
  console.log(`  ${passed.length} succeeded, ${failed.length} failed\n`);

  if (failed.length > 0) {
    console.log("\x1b[31mFailed steps:\x1b[0m");
    for (const f of failed) {
      console.log(`  - ${f.step}: ${f.message}`);
    }
    console.log("");
  }

  if (operation === "Install" && failed.length === 0) {
    console.log("\x1b[32m╔══════════════════════════════════════════════════════╗\x1b[0m");
    console.log("\x1b[32m║  Package firewall is now enforcing.                  ║\x1b[0m");
    console.log("\x1b[32m╚══════════════════════════════════════════════════════╝\x1b[0m");
    console.log("");
    console.log("  All package installs (npm/pip/cargo/etc) are routed through pfw.");
    console.log("  Restart your shell or open a new terminal for PATH changes.\n");
  }

  if (operation === "Uninstall" && failed.length === 0) {
    console.log("\x1b[32mPackage firewall enforcement removed.\x1b[0m");
    console.log("Original binaries are still available and will be found via normal PATH.\n");
  }
}
