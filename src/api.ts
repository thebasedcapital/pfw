import type { PackageRef, BlockDecision, VulnerabilityAlert, BlockAction, FirewallConfig, PolicyRule } from './types.js';
import { BlockCache } from './cache.js';
import { queryAllSources } from './sources.js';

const cache = new BlockCache();

/** Check local policy rules */
export function checkLocalPolicy(pkg: PackageRef, policies: PolicyRule[]): VulnerabilityAlert | null {
  for (const rule of policies) {
    const escaped = rule.pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp('^' + escaped.replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
    if (regex.test(pkg.name)) {
      return {
        id: `policy:${rule.pattern}`,
        summary: rule.reason || `Matched policy rule: ${rule.pattern}`,
        severity: rule.action === 'block' ? 'CRITICAL' : rule.action === 'warn' ? 'MODERATE' : 'LOW',
        action: rule.action,
        source: 'local-policy',
      };
    }
  }
  return null;
}

/** Main entry: check a package against all sources */
export async function checkPackage(pkg: PackageRef, config: FirewallConfig): Promise<BlockDecision> {
  const start = Date.now();

  // 1. Check cache
  const cached = cache.get(pkg.purl);
  if (cached && !cached.isStale) return cached.decision;

  // 2. Local policy (immediate, no network)
  const policyAlert = checkLocalPolicy(pkg, config.policies);
  if (policyAlert && policyAlert.action === 'block') {
    const decision: BlockDecision = { action: 'block', alerts: [policyAlert], cached: false, latencyMs: Date.now() - start };
    cache.set(pkg.purl, decision);
    return decision;
  }

  // 3. Local-only mode — skip all external sources
  if (config.localPolicyOnly) {
    const decision: BlockDecision = {
      action: policyAlert?.action || 'allow',
      alerts: policyAlert ? [policyAlert] : [],
      cached: false,
      latencyMs: Date.now() - start,
    };
    cache.set(pkg.purl, decision);
    return decision;
  }

  // 4. Query all external sources in parallel (OSV + GHSA + deps.dev + CISA KEV)
  const result = await queryAllSources(pkg);
  const alerts = [...result.alerts];
  if (policyAlert) alerts.push(policyAlert);

  // 5. If ALL sources failed and no policy alerts, use failAction
  const EXPECTED_SOURCES = 3; // osv + ghsa + deps.dev (update if adding sources)
  const allSourcesFailed = result.errors.length >= EXPECTED_SOURCES;
  if (allSourcesFailed && alerts.length === 0) {
    const decision: BlockDecision = {
      action: config.failAction,
      alerts: config.failAction === 'block' ? [{
        id: 'all-sources-failed',
        summary: `All vulnerability sources unreachable (${result.errors.join(', ')}) — ${config.failAction}`,
        severity: 'CRITICAL',
        action: 'block',
        source: 'pfw',
      }] : [],
      cached: false,
      latencyMs: Date.now() - start,
    };
    cache.set(pkg.purl, decision);
    return decision;
  }

  // 6. Determine action (worst alert wins)
  let action: BlockAction = 'allow';
  for (const alert of alerts) {
    if (alert.action === 'block') { action = 'block'; break; }
    if (alert.action === 'warn') action = 'warn';
  }

  // Log source errors in debug mode (non-fatal — other sources may have succeeded)
  if (result.errors.length > 0 && config.debug) {
    console.error(`[pfw] source errors: ${result.errors.join(', ')} (${result.errors.length}/3 failed)`);
  }

  const decision: BlockDecision = { action, alerts, cached: false, latencyMs: Date.now() - start };
  cache.set(pkg.purl, decision);
  return decision;
}

/** Flush the cache */
export function flushCache(): void {
  cache.flush();
}
