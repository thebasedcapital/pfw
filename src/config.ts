import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import type { FirewallConfig, RegistryConfig, RegistryKind, PolicyRule, BlockAction } from './types.js';

const DEFAULT_REGISTRIES: [string, RegistryKind][] = [
  ['registry.npmjs.org', 'npm'],
  ['registry.yarnpkg.com', 'npm'],
  ['pypi.org', 'pypi'],
  ['files.pythonhosted.org', 'pypi'],
  ['static.crates.io', 'cargo'],
  ['index.crates.io', 'wrap'],
  ['rubygems.org', 'gem'],
  ['api.nuget.org', 'nuget'],
  ['proxy.golang.org', 'golang'],
  ['sum.golang.org', 'golang'],
  ['repo.maven.apache.org', 'maven'],
  ['repo1.maven.org', 'maven'],
  ['github.com', 'wrap'],
  ['api.github.com', 'wrap'],
  ['codeload.github.com', 'wrap'],
  ['static.rust-lang.org', 'wrap'],
  ['nodejs.org', 'wrap'],
];

/** Parse .pfw.config (our config format, dotenv-style with extensions) */
function parseConfigFile(filePath: string): Partial<FirewallConfig> {
  if (!fs.existsSync(filePath)) return {};
  const content = fs.readFileSync(filePath, 'utf-8');
  const config: Partial<FirewallConfig> = {};
  const policies: PolicyRule[] = [];

  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const [key, ...valueParts] = trimmed.split('=');
    const value = valueParts.join('=').trim();

    switch (key.trim()) {
      case 'DEBUG': config.debug = value === 'true'; break;
      case 'SILENT': config.silent = value === 'true'; break;
      case 'FAIL_ACTION': config.failAction = value as BlockAction; break;
      case 'UNKNOWN_HOST_ACTION': config.unknownHostAction = value as BlockAction; break;
      case 'CA_CERT_PATH': config.caCertPath = value; break;
      case 'CA_KEY_PATH': config.caKeyPath = value; break;
      case 'CACHE_TTL_MS': config.cacheTtlMs = parseInt(value); break;
      case 'STALE_TTL_MS': config.staleTtlMs = parseInt(value); break;
      case 'OSV_ENABLED': config.osvEnabled = value !== 'false'; break;
      case 'LOCAL_POLICY_ONLY': config.localPolicyOnly = value === 'true'; break;
      case 'BLOCK':
        policies.push({ pattern: value, action: 'block', reason: 'local policy' });
        break;
      case 'WARN':
        policies.push({ pattern: value, action: 'warn', reason: 'local policy' });
        break;
      case 'ALLOW':
        policies.push({ pattern: value, action: 'allow', reason: 'local policy' });
        break;
    }
  }

  if (policies.length) config.policies = policies;
  return config;
}

/** Check if a config file is safe to load (owned by current user or root, not world-writable) */
function isConfigFileSafe(filePath: string): boolean {
  try {
    const stat = fs.statSync(filePath);
    const uid = process.getuid?.() ?? 0;
    if (stat.uid !== uid && stat.uid !== 0) return false;
    if (stat.mode & 0o002) return false; // world-writable = untrusted
    return true;
  } catch {
    return false;
  }
}

/** Search for config files walking up from cwd */
function findConfigFiles(): string[] {
  const files: string[] = [];
  let dir = process.cwd();

  while (true) {
    const candidate = path.join(dir, '.pfw.config');
    if (fs.existsSync(candidate) && isConfigFileSafe(candidate)) {
      files.push(candidate);
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }

  // Home directory config
  const homeConfig = path.join(os.homedir(), '.pfw.config');
  if (fs.existsSync(homeConfig) && !files.includes(homeConfig) && isConfigFileSafe(homeConfig)) {
    files.push(homeConfig);
  }

  return files;
}

/** Build default registry map */
function buildRegistryMap(): Map<string, RegistryConfig> {
  const map = new Map<string, RegistryConfig>();
  for (const [fqdn, kind] of DEFAULT_REGISTRIES) {
    map.set(fqdn, { fqdn, kind, protocol: 'https' });
  }
  return map;
}

/** Load full config from env + files */
export function loadConfig(): FirewallConfig {
  const env = process.env;

  const config: FirewallConfig = {
    debug: env.PFW_DEBUG === 'true',
    silent: env.PFW_SILENT === 'true',
    failAction: (env.PFW_FAIL_ACTION as BlockAction) || 'allow',
    unknownHostAction: (env.PFW_UNKNOWN_HOST_ACTION as BlockAction) || 'warn',
    caCertPath: env.PFW_CA_CERT_PATH,
    caKeyPath: env.PFW_CA_KEY_PATH,
    policies: [],
    allowedRegistries: buildRegistryMap(),
    cacheTtlMs: parseInt(env.PFW_CACHE_TTL_MS || '600000'),
    staleTtlMs: parseInt(env.PFW_STALE_TTL_MS || '86400000'),
    osvEnabled: env.PFW_OSV_ENABLED !== 'false',
    localPolicyOnly: env.PFW_LOCAL_POLICY_ONLY === 'true',
  };

  // Merge config files (closest to cwd wins)
  const configFiles = findConfigFiles();
  for (const file of configFiles.reverse()) {
    const fileConfig = parseConfigFile(file);
    Object.assign(config, fileConfig);
    if (fileConfig.policies) {
      config.policies = [...config.policies, ...fileConfig.policies];
    }
  }

  return config;
}
