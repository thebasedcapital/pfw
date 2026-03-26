#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { loadConfig } from './config.js';
import { generateCaKeyPair, loadCaCert } from './tls.js';
import { startProxy, getProxyEnv } from './proxy.js';
import { checkPackage } from './api.js';
import type { PackageRef, RegistryKind } from './types.js';
import { queryAudit, auditStats } from './audit.js';

const VERSION = '0.2.0';
const NAME = 'pfw'; // Package Firewall
const DAEMON_PORT = 9338;
const PFW_DIR = join(homedir(), '.pfw');
const PID_FILE = join(PFW_DIR, 'daemon.pid');

// ── Daemon helpers ──────────────────────────────────────────────────

function ensurePfwDir(): void {
  if (!existsSync(PFW_DIR)) mkdirSync(PFW_DIR, { recursive: true });
}

function readPid(): number | null {
  try {
    const raw = readFileSync(PID_FILE, 'utf-8').trim();
    const pid = parseInt(raw, 10);
    return Number.isFinite(pid) ? pid : null;
  } catch {
    return null;
  }
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0); // signal 0 = existence check
    return true;
  } catch {
    return false;
  }
}

function cleanupPidFile(): void {
  try { unlinkSync(PID_FILE); } catch {}
}

// ── Subcommands ─────────────────────────────────────────────────────

async function runDaemon(subArgs: string[]): Promise<void> {
  const sub = subArgs[0];

  if (sub === 'status') {
    const pid = readPid();
    if (pid && isProcessAlive(pid)) {
      console.log(`[pfw] daemon running (pid ${pid}, port ${DAEMON_PORT})`);
    } else {
      if (pid) cleanupPidFile(); // stale pid file
      console.log('[pfw] daemon not running');
      process.exit(1);
    }
    return;
  }

  if (sub === 'stop') {
    const pid = readPid();
    if (!pid || !isProcessAlive(pid)) {
      console.log('[pfw] daemon not running');
      if (pid) cleanupPidFile();
      return;
    }
    process.kill(pid, 'SIGTERM');
    console.log(`[pfw] sent SIGTERM to pid ${pid}`);
    return;
  }

  // Default: start daemon in foreground
  if (sub && sub !== 'start') {
    console.error(`[pfw] unknown daemon subcommand: ${sub}`);
    console.error('Usage: pfw daemon [start|status|stop]');
    process.exit(1);
  }

  // Check if already running
  const existingPid = readPid();
  if (existingPid && isProcessAlive(existingPid)) {
    console.error(`[pfw] daemon already running (pid ${existingPid})`);
    process.exit(1);
  }

  ensurePfwDir();

  const config = loadConfig();
  config.port = DAEMON_PORT;

  const { caCertPath, caKeyPath } = resolveCa(config);
  const caCert = loadCaCert(caCertPath, caKeyPath);
  const { server, address, port } = await startProxy(config, caCert.cert, caCert.key);

  // Write PID file AFTER successful port bind — avoids stale PID from crashed startup
  writeFileSync(PID_FILE, String(process.pid));

  console.log(`[pfw] daemon started (pid ${process.pid}, ${address}:${port})`);
  if (config.localPolicyOnly) {
    console.log('[pfw] Local policy only mode — no external API calls');
  } else {
    console.log('[pfw] Sources: OSV.dev + GitHub Advisory + deps.dev + CISA KEV');
  }

  // Graceful shutdown on SIGTERM/SIGINT
  const shutdown = () => {
    console.log('\n[pfw] shutting down daemon...');
    cleanupPidFile();
    server.close(() => process.exit(0));
    // Force exit after 3s if close hangs
    setTimeout(() => process.exit(0), 3000).unref();
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

async function runCheck(args: string[]): Promise<void> {
  if (args.length < 2) {
    console.error('Usage: pfw check <ecosystem> <package>@<version>');
    console.error('  e.g. pfw check npm lodash@4.17.21');
    process.exit(1);
  }

  const ecosystem = args[0] as RegistryKind;
  const pkgArg = args[1];
  const atIdx = pkgArg.lastIndexOf('@');

  if (atIdx <= 0) {
    console.error(`[pfw] invalid format: ${pkgArg} (expected name@version)`);
    process.exit(1);
  }

  const name = pkgArg.slice(0, atIdx);
  const version = pkgArg.slice(atIdx + 1);

  const pkg: PackageRef = {
    name,
    version,
    kind: ecosystem,
    purl: `pkg:${ecosystem}/${name}@${version}`,
  };

  const config = loadConfig();
  console.log(`[pfw] checking ${pkg.purl} ...`);

  const decision = await checkPackage(pkg, config);

  if (decision.alerts.length === 0) {
    console.log(`[pfw] ${pkg.purl}: CLEAN (${decision.latencyMs}ms)`);
  } else {
    for (const alert of decision.alerts) {
      const icon = alert.action === 'block' ? 'BLOCK' : alert.action === 'warn' ? 'WARN' : 'ALLOW';
      console.log(`[pfw] [${icon}] [${alert.severity}] ${alert.summary} (${alert.source})`);
    }
    console.log(`[pfw] decision: ${decision.action.toUpperCase()} (${decision.latencyMs}ms)`);
    if (decision.action === 'block') process.exit(2);
  }
}

async function runInstall(): Promise<void> {
  const { install } = await import('./installer.js');
  const useYes = process.argv.includes('--yes');
  await install({ yes: useYes });
}

async function runUninstall(): Promise<void> {
  const { uninstall } = await import('./installer.js');
  const useYes = process.argv.includes('--yes');
  await uninstall({ yes: useYes });
}

// ── Shared helpers ──────────────────────────────────────────────────

function resolveCa(config: ReturnType<typeof loadConfig>): { caCertPath: string; caKeyPath: string } {
  if (config.caCertPath && config.caKeyPath) {
    return { caCertPath: config.caCertPath, caKeyPath: config.caKeyPath };
  }
  const ca = generateCaKeyPair();
  if (!ca) {
    console.error('[pfw] Failed to generate CA certificates');
    process.exit(1);
  }
  return { caCertPath: ca.caCertPath, caKeyPath: ca.caKeyPath };
}

// ── Main ────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  // Handle flags
  if (args.includes('--help') || args.includes('-h')) {
    printHelp();
    return;
  }
  if (args.includes('--version') || args.includes('-v')) {
    console.log(`${NAME} ${VERSION}`);
    return;
  }

  if (args.length === 0) {
    printHelp();
    process.exit(1);
  }

  const cmd = args[0];

  // ── Built-in subcommands ──
  if (cmd === 'daemon') {
    await runDaemon(args.slice(1));
    return;
  }
  if (cmd === 'check') {
    await runCheck(args.slice(1));
    return;
  }
  if (cmd === 'install') {
    await runInstall();
    return;
  }
  if (cmd === 'uninstall') {
    await runUninstall();
    return;
  }
  if (cmd === 'log') {
    runLog(args.slice(1));
    return;
  }

  // ── Wrapper mode: pfw <command> [args...] ──
  const config = loadConfig();
  const { caCertPath, caKeyPath } = resolveCa(config);
  const caCert = loadCaCert(caCertPath, caKeyPath);
  const { server, address, port } = await startProxy(config, caCert.cert, caCert.key);

  if (!config.silent) {
    console.log(`[pfw] Proxy listening on ${address}:${port}`);
    if (config.localPolicyOnly) {
      console.log('[pfw] Local policy only mode — no external API calls');
    } else {
      console.log('[pfw] Sources: OSV.dev + GitHub Advisory + deps.dev + CISA KEV');
    }
  }

  // Build env for child process
  const proxyEnv = getProxyEnv(address, port, caCertPath);
  const childEnv = { ...process.env, ...proxyEnv };

  // For npm/yarn/pnpm: override registry to use our local HTTP server directly
  const cmdArgs = args.slice(1);
  const localRegistry = `http://${address}:${port}`;

  if (['npm', 'npx', 'yarn', 'pnpm'].includes(cmd)) {
    childEnv['npm_config_registry'] = localRegistry;
    childEnv['YARN_REGISTRY'] = localRegistry;
    if (config.debug) {
      console.log(`[pfw] Redirecting ${cmd} registry to ${localRegistry}`);
    }
  }

  // Spawn the wrapped command
  const child = spawn(cmd, cmdArgs, {
    stdio: 'inherit',
    env: childEnv,
  });

  child.on('exit', (code, signal) => {
    server.close();
    if (signal) {
      process.kill(process.pid, signal);
    } else {
      process.exit(code ?? 0);
    }
  });

  child.on('error', (err) => {
    console.error(`[pfw] Failed to start '${cmd}': ${err.message}`);
    server.close();
    process.exit(1);
  });

  // Forward signals
  for (const sig of ['SIGINT', 'SIGTERM'] as const) {
    process.on(sig, () => {
      child.kill(sig);
    });
  }
}

function runLog(args: string[]): void {
  const sub = args[0];

  // pfw log stats
  if (sub === 'stats') {
    const s = auditStats();
    console.log(`\n\x1b[1m[pfw] Audit Statistics\x1b[0m\n`);
    console.log(`  Total checks:  ${s.total}`);
    console.log(`  Blocked:       \x1b[31m${s.blocked}\x1b[0m`);
    console.log(`  Warned:        \x1b[33m${s.warned}\x1b[0m`);
    console.log(`  Allowed:       \x1b[32m${s.allowed}\x1b[0m`);
    if (s.topBlocked.length) {
      console.log(`\n  \x1b[1mTop blocked packages:\x1b[0m`);
      for (const t of s.topBlocked) {
        console.log(`    ${t.name} (${t.count}x)`);
      }
    }
    if (s.ecosystems.length) {
      console.log(`\n  \x1b[1mBy ecosystem:\x1b[0m`);
      for (const e of s.ecosystems) {
        console.log(`    ${e.ecosystem}: ${e.count}`);
      }
    }
    console.log('');
    return;
  }

  // Parse flags
  const opts: { name?: string; ecosystem?: string; action?: string; since?: string; limit?: number; json?: boolean } = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if ((arg === '--name' || arg === '-n') && args[i + 1]) { opts.name = args[++i]; }
    else if ((arg === '--eco' || arg === '-e') && args[i + 1]) { opts.ecosystem = args[++i]; }
    else if ((arg === '--action' || arg === '-a') && args[i + 1]) { opts.action = args[++i]; }
    else if ((arg === '--since' || arg === '-s') && args[i + 1]) { opts.since = args[++i]; }
    else if ((arg === '--limit' || arg === '-l') && args[i + 1]) { opts.limit = parseInt(args[++i], 10); }
    else if (arg === '--json') { opts.json = true; }
    else if (arg === '--blocked') { opts.action = 'block'; }
    else if (arg === '--warned') { opts.action = 'warn'; }
    else if (arg === '--allowed') { opts.action = 'allow'; }
    else if (arg === 'stats') { /* handled above */ }
    else if (!arg.startsWith('-') && !opts.name) { opts.name = arg; } // bare arg = name search
  }

  const rows = queryAudit(opts);

  if (opts.json) {
    console.log(JSON.stringify(rows, null, 2));
    return;
  }

  if (rows.length === 0) {
    console.log('[pfw] No audit records found.');
    return;
  }

  // Table output
  console.log('');
  console.log(`  \x1b[1m${'Timestamp'.padEnd(20)} ${'Package'.padEnd(30)} ${'Ver'.padEnd(12)} ${'Eco'.padEnd(6)} ${'Action'.padEnd(8)} Sources\x1b[0m`);
  console.log(`  ${'─'.repeat(20)} ${'─'.repeat(30)} ${'─'.repeat(12)} ${'─'.repeat(6)} ${'─'.repeat(8)} ${'─'.repeat(20)}`);
  for (const row of rows) {
    const ts = (row.ts as string).slice(0, 19);
    const name = (row.name as string).slice(0, 29).padEnd(30);
    const ver = (row.version as string).slice(0, 11).padEnd(12);
    const eco = (row.ecosystem as string).padEnd(6);
    const action = row.action as string;
    const sources = (row.sources as string) || '-';
    const color = action === 'block' ? '\x1b[31m' : action === 'warn' ? '\x1b[33m' : '\x1b[32m';
    console.log(`  ${ts} ${name} ${ver} ${eco} ${color}${action.padEnd(8)}\x1b[0m ${sources}`);
  }
  console.log(`\n  ${rows.length} record(s)\n`);
}

function printHelp(): void {
  console.log(`
${NAME} — Package Firewall (self-hosted, zero telemetry)

Usage:
  ${NAME} <command> [args...]     Wrap a command through the firewall
  ${NAME} daemon [start|status|stop]  Run as a persistent daemon (port ${DAEMON_PORT})
  ${NAME} check <eco> <pkg>@<ver>     Manual package vulnerability check
  ${NAME} log [options]               Query the audit log
  ${NAME} log stats                   Show audit statistics
  ${NAME} install                     Set up pfw (CA trust, shell, launchd)

Examples:
  ${NAME} npm install lodash
  ${NAME} pip install requests
  ${NAME} cargo build
  ${NAME} daemon start
  ${NAME} daemon status
  ${NAME} check npm lodash@4.17.21
  ${NAME} log                          Last 50 checks
  ${NAME} log --blocked                Show blocked packages
  ${NAME} log --name lodash            Search by name
  ${NAME} log --eco npm --limit 100    Filter by ecosystem
  ${NAME} log --since 2026-03-25       Since date
  ${NAME} log --json                   JSON output (for agents)
  ${NAME} log stats                    Summary statistics

Options:
  --help, -h       Show this help
  --version, -v    Show version

Environment:
  PFW_DEBUG=true              Verbose logging
  PFW_SILENT=true             Suppress all output
  PFW_FAIL_ACTION=block       Block when API unreachable (default: allow)
  PFW_LOCAL_POLICY_ONLY=true  No external API calls, local rules only
  PFW_OSV_ENABLED=false       Disable OSV.dev queries
  PFW_CA_CERT_PATH=<path>     Custom CA certificate
  PFW_CA_KEY_PATH=<path>      Custom CA key

Config file: .pfw.config (searched from cwd to root, then ~/.pfw.config)

  # Block specific packages
  BLOCK=event-stream
  BLOCK=colors
  BLOCK=ua-parser-js

  # Warn on patterns
  WARN=@deprecated/*

  # Always allow
  ALLOW=lodash
`);
}

main().catch(err => {
  console.error(`[pfw] Fatal: ${err.message}`);
  process.exit(1);
});
