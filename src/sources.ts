/**
 * Vulnerability data sources — all free, no auth required.
 * Each source is queried in parallel for maximum speed.
 */
import type { PackageRef, VulnerabilityAlert, BlockAction } from './types.js';

// ─── Shared Helpers ──────────────────────────────────────────

function mapCvssToSeverity(score: number): VulnerabilityAlert['severity'] {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MODERATE';
  return 'LOW';
}

function severityToAction(severity: VulnerabilityAlert['severity']): BlockAction {
  if (severity === 'CRITICAL' || severity === 'HIGH') return 'block';
  if (severity === 'MODERATE') return 'warn';
  return 'allow';
}

function purlToOsvEcosystem(kind: string): string {
  const map: Record<string, string> = {
    npm: 'npm', pypi: 'PyPI', cargo: 'crates.io',
    gem: 'RubyGems', golang: 'Go', maven: 'Maven', nuget: 'NuGet',
  };
  return map[kind] || kind;
}

function purlToGhsaEcosystem(kind: string): string {
  const map: Record<string, string> = {
    npm: 'npm', pypi: 'pip', cargo: 'rust',
    gem: 'rubygems', golang: 'go', maven: 'maven', nuget: 'nuget',
  };
  return map[kind] || kind;
}

export interface SourceResult {
  source: string;
  alerts: VulnerabilityAlert[];
  error: boolean;
  latencyMs: number;
}

// ─── 1. OSV.dev (Google) ─────────────────────────────────────

const OSV_API = 'https://api.osv.dev/v1/query';

export async function queryOsv(pkg: PackageRef): Promise<SourceResult> {
  const start = Date.now();
  try {
    const res = await fetch(OSV_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        package: { name: pkg.name, ecosystem: purlToOsvEcosystem(pkg.kind) },
        version: pkg.version,
      }),
      signal: AbortSignal.timeout(10_000),
    });

    if (!res.ok) return { source: 'osv', alerts: [], error: true, latencyMs: Date.now() - start };

    const data = await res.json() as {
      vulns?: Array<{ id: string; summary?: string; severity?: Array<{ type: string; score: string }> }>
    };

    const alerts: VulnerabilityAlert[] = (data.vulns || []).map(vuln => {
      const cvssEntry = vuln.severity?.find(s => s.type === 'CVSS_V3');
      const score = cvssEntry ? parseFloat(cvssEntry.score) : 5.0;
      const severity = mapCvssToSeverity(score);
      return { id: vuln.id, summary: vuln.summary || vuln.id, severity, action: severityToAction(severity), source: 'osv' };
    });

    return { source: 'osv', alerts, error: false, latencyMs: Date.now() - start };
  } catch {
    return { source: 'osv', alerts: [], error: true, latencyMs: Date.now() - start };
  }
}

// ─── 2. GitHub Advisory Database (GHSA) ──────────────────────

const GHSA_API = 'https://api.github.com/advisories';

export async function queryGhsa(pkg: PackageRef): Promise<SourceResult> {
  const start = Date.now();
  try {
    const ecosystem = purlToGhsaEcosystem(pkg.kind);
    const params = new URLSearchParams({
      ecosystem,
      affects: `${pkg.name}@${pkg.version}`,
      per_page: '20',
    });

    const res = await fetch(`${GHSA_API}?${params}`, {
      headers: {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      signal: AbortSignal.timeout(10_000),
    });

    if (!res.ok) return { source: 'ghsa', alerts: [], error: true, latencyMs: Date.now() - start };

    const data = await res.json() as Array<{
      ghsa_id: string;
      summary?: string;
      severity?: string;
      cvss?: { score?: number };
    }>;

    const alerts: VulnerabilityAlert[] = data.map(adv => {
      const score = adv.cvss?.score || 0;
      // GitHub uses string severity: critical, high, medium, low
      let severity: VulnerabilityAlert['severity'];
      if (adv.severity === 'critical' || score >= 9.0) severity = 'CRITICAL';
      else if (adv.severity === 'high' || score >= 7.0) severity = 'HIGH';
      else if (adv.severity === 'medium' || score >= 4.0) severity = 'MODERATE';
      else severity = 'LOW';

      return {
        id: adv.ghsa_id,
        summary: adv.summary || adv.ghsa_id,
        severity,
        action: severityToAction(severity),
        source: 'ghsa',
      };
    });

    return { source: 'ghsa', alerts, error: false, latencyMs: Date.now() - start };
  } catch {
    return { source: 'ghsa', alerts: [], error: true, latencyMs: Date.now() - start };
  }
}

// ─── 3. deps.dev (Google Open Source Insights) ───────────────

const DEPS_API = 'https://api.deps.dev/v3alpha';

function purlToDepsSystem(kind: string): string {
  const map: Record<string, string> = {
    npm: 'npm', pypi: 'pypi', cargo: 'cargo',
    golang: 'go', maven: 'maven', nuget: 'nuget',
  };
  return map[kind] || '';
}

export interface DepsDevInfo {
  scorecard?: { overallScore: number };
  advisoryKeys?: string[];
  projectType?: string;
}

/** Query deps.dev for package metadata: OpenSSF Scorecard + advisory keys */
export async function queryDepsDev(pkg: PackageRef): Promise<SourceResult & { meta?: DepsDevInfo }> {
  const start = Date.now();
  const system = purlToDepsSystem(pkg.kind);
  if (!system) return { source: 'deps.dev', alerts: [], error: false, latencyMs: 0 };

  try {
    const encodedName = encodeURIComponent(pkg.name);
    const encodedVersion = encodeURIComponent(pkg.version);
    const url = `${DEPS_API}/systems/${system}/packages/${encodedName}/versions/${encodedVersion}`;

    const res = await fetch(url, {
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(10_000),
    });

    if (!res.ok) return { source: 'deps.dev', alerts: [], error: true, latencyMs: Date.now() - start };

    const data = await res.json() as {
      advisoryKeys?: Array<{ id: string }>;
      scorecardV2?: { overallScore?: number; date?: string };
    };

    const alerts: VulnerabilityAlert[] = [];

    // Low OpenSSF Scorecard = warn (unmaintained/risky project)
    if (data.scorecardV2?.overallScore !== undefined && data.scorecardV2.overallScore < 4.0) {
      alerts.push({
        id: 'scorecard-low',
        summary: `OpenSSF Scorecard: ${data.scorecardV2.overallScore.toFixed(1)}/10 (low quality/maintenance)`,
        severity: data.scorecardV2.overallScore < 2.0 ? 'HIGH' : 'MODERATE',
        action: data.scorecardV2.overallScore < 2.0 ? 'block' : 'warn',
        source: 'deps.dev',
      });
    }

    // Advisory keys from deps.dev — fetch actual CVSS score for each
    if (data.advisoryKeys?.length) {
      const advisoryResults = await Promise.all(
        data.advisoryKeys.map(async (key) => {
          try {
            const advRes = await fetch(`https://api.deps.dev/v3alpha/advisories/${encodeURIComponent(key.id)}`, {
              signal: AbortSignal.timeout(5_000),
            });
            if (advRes.ok) {
              const advData = await advRes.json() as { cvss3Score?: number; title?: string };
              const score = advData.cvss3Score ?? 5.0;
              const severity = mapCvssToSeverity(score);
              return {
                id: key.id,
                summary: advData.title || `Advisory from deps.dev: ${key.id}`,
                severity,
                action: severityToAction(severity),
                source: 'deps.dev',
              } as VulnerabilityAlert;
            }
          } catch { /* ignore individual advisory fetch failures */ }
          // Fallback: unknown severity → warn, don't block
          return {
            id: key.id,
            summary: `Advisory from deps.dev: ${key.id}`,
            severity: 'MODERATE' as const,
            action: 'warn' as BlockAction,
            source: 'deps.dev',
          } as VulnerabilityAlert;
        })
      );
      alerts.push(...advisoryResults);
    }

    const meta: DepsDevInfo = {
      scorecard: data.scorecardV2 ? { overallScore: data.scorecardV2.overallScore || 0 } : undefined,
      advisoryKeys: data.advisoryKeys?.map(k => k.id),
    };

    return { source: 'deps.dev', alerts, error: false, latencyMs: Date.now() - start, meta };
  } catch {
    return { source: 'deps.dev', alerts: [], error: true, latencyMs: Date.now() - start };
  }
}

// ─── 4. CISA KEV (Known Exploited Vulnerabilities) ──────────

const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/** In-memory CISA KEV cache — loaded once, refreshed every 6 hours */
let kevCache: Map<string, { cveId: string; product: string; shortDescription: string }> | null = null;
let kevLastFetch = 0;
const KEV_TTL = 6 * 60 * 60 * 1000; // 6 hours

async function loadKev(): Promise<typeof kevCache> {
  if (kevCache && Date.now() - kevLastFetch < KEV_TTL) return kevCache;

  try {
    const res = await fetch(CISA_KEV_URL, { signal: AbortSignal.timeout(15_000) });
    if (!res.ok) return kevCache; // keep stale cache if refresh fails

    const data = await res.json() as {
      vulnerabilities?: Array<{
        cveID: string;
        product: string;
        shortDescription: string;
        vendorProject: string;
      }>
    };

    kevCache = new Map();
    for (const v of data.vulnerabilities || []) {
      kevCache.set(v.cveID, {
        cveId: v.cveID,
        product: `${v.vendorProject} ${v.product}`,
        shortDescription: v.shortDescription,
      });
    }
    kevLastFetch = Date.now();
    return kevCache;
  } catch {
    return kevCache; // keep stale
  }
}

/** Check if any of the CVE IDs from other sources are in CISA KEV */
export async function checkCisaKev(cveIds: string[]): Promise<VulnerabilityAlert[]> {
  const kev = await loadKev();
  if (!kev) return [];

  const alerts: VulnerabilityAlert[] = [];
  for (const cveId of cveIds) {
    const entry = kev.get(cveId);
    if (entry) {
      alerts.push({
        id: `KEV:${entry.cveId}`,
        summary: `CISA KEV (actively exploited): ${entry.shortDescription}`,
        severity: 'CRITICAL',
        action: 'block',
        source: 'cisa-kev',
      });
    }
  }
  return alerts;
}

// ─── 5. npm Age + Download Count (New Package Detection) ─────

const NPM_REGISTRY_API = 'https://registry.npmjs.org';
const NPM_DOWNLOADS_API = 'https://api.npmjs.org/downloads/point/last-week';

export interface NpmAgeInfo {
  publishedAt: Date;
  ageHours: number;
  weeklyDownloads: number;
  packageCreatedAt: Date;
  packageAgeHours: number;
}

export interface NpmAgeThresholds {
  newPkgMaxAgeHours: number;   // default 24
  newPkgMinDownloads: number;  // default 500
  newVersionMaxAgeHours: number; // default 2
}

/** Fetch npm publish time for a specific version + weekly downloads.
 *  Detects the axios/plain-crypto-js attack pattern:
 *  brand-new package + low downloads = likely supply chain implant. */
export async function queryNpmAge(
  pkg: PackageRef,
  thresholds: NpmAgeThresholds = { newPkgMaxAgeHours: 24, newPkgMinDownloads: 500, newVersionMaxAgeHours: 2 },
): Promise<SourceResult & { ageInfo?: NpmAgeInfo }> {
  if (pkg.kind !== 'npm') return { source: 'npm-age', alerts: [], error: false, latencyMs: 0 };

  const start = Date.now();
  try {
    const [metaRes, dlRes] = await Promise.all([
      fetch(`${NPM_REGISTRY_API}/${encodeURIComponent(pkg.name)}`, {
        headers: { 'Accept': 'application/json' },
        signal: AbortSignal.timeout(8_000),
      }),
      fetch(`${NPM_DOWNLOADS_API}/${encodeURIComponent(pkg.name)}`, {
        signal: AbortSignal.timeout(8_000),
      }),
    ]);

    if (!metaRes.ok) return { source: 'npm-age', alerts: [], error: true, latencyMs: Date.now() - start };

    const meta = await metaRes.json() as {
      time?: Record<string, string>; // version → ISO date, plus 'created' / 'modified' keys
    };
    const dlData = dlRes.ok ? await dlRes.json() as { downloads?: number } : { downloads: 0 };

    const versionTime = meta.time?.[pkg.version];
    const packageCreated = meta.time?.['created'];
    if (!versionTime) return { source: 'npm-age', alerts: [], error: false, latencyMs: Date.now() - start };

    const publishedAt = new Date(versionTime);
    const packageCreatedAt = packageCreated ? new Date(packageCreated) : publishedAt;
    const nowMs = Date.now();
    const ageHours = (nowMs - publishedAt.getTime()) / 3_600_000;
    const packageAgeHours = (nowMs - packageCreatedAt.getTime()) / 3_600_000;
    const weeklyDownloads = dlData.downloads ?? 0;

    const ageInfo: NpmAgeInfo = { publishedAt, ageHours, weeklyDownloads, packageCreatedAt, packageAgeHours };
    const alerts: VulnerabilityAlert[] = [];

    const { newPkgMaxAgeHours, newPkgMinDownloads, newVersionMaxAgeHours } = thresholds;

    // HARD BLOCK: brand-new package with near-zero downloads
    // Exact fingerprint of the axios/plain-crypto-js 2026-03-31 attack.
    if (packageAgeHours < newPkgMaxAgeHours && weeklyDownloads < newPkgMinDownloads) {
      alerts.push({
        id: 'npm-new-package',
        summary: `New package: created ${packageAgeHours.toFixed(1)}h ago, ${weeklyDownloads} weekly downloads — matches supply chain implant pattern`,
        severity: 'CRITICAL',
        action: 'block',
        source: 'npm-age',
      });
    // HARD BLOCK: very recent version on a low-adoption package — covers injected versions on hijacked accounts
    } else if (ageHours < newVersionMaxAgeHours && weeklyDownloads < 10_000) {
      alerts.push({
        id: 'npm-new-version',
        summary: `Version published ${ageHours.toFixed(1)}h ago, low adoption (${weeklyDownloads} dl/week) — possible hijack window`,
        severity: 'HIGH',
        action: 'block',
        source: 'npm-age',
      });
    // WARN: version is very recent (<6h) on any package
    } else if (ageHours < 6) {
      alerts.push({
        id: 'npm-very-recent-version',
        summary: `Version published ${ageHours.toFixed(1)}h ago — verify integrity before use`,
        severity: 'MODERATE',
        action: 'warn',
        source: 'npm-age',
      });
    }

    return { source: 'npm-age', alerts, error: false, latencyMs: Date.now() - start, ageInfo };
  } catch {
    return { source: 'npm-age', alerts: [], error: true, latencyMs: Date.now() - start };
  }
}

// ─── Aggregator: query all sources in parallel ───────────────

export async function queryAllSources(
  pkg: PackageRef,
  opts: { npmAgeEnabled?: boolean; ageThresholds?: NpmAgeThresholds } = {},
): Promise<{
  alerts: VulnerabilityAlert[];
  errors: string[];
  latencyMs: number;
}> {
  const start = Date.now();
  const npmAgeEnabled = opts.npmAgeEnabled !== false;

  // Fire all sources in parallel (CISA KEV runs after to cross-reference CVE IDs)
  const [osvResult, ghsaResult, depsResult, ageResult] = await Promise.all([
    queryOsv(pkg),
    queryGhsa(pkg),
    queryDepsDev(pkg),
    npmAgeEnabled ? queryNpmAge(pkg, opts.ageThresholds) : Promise.resolve({ source: 'npm-age', alerts: [], error: false, latencyMs: 0 }),
  ]);

  // Collect all alerts, deduplicate by normalized ID
  const alertMap = new Map<string, VulnerabilityAlert>();
  const errors: string[] = [];
  const allResults = [osvResult, ghsaResult, depsResult, ageResult];

  for (const result of allResults) {
    if (result.error) errors.push(result.source);
    for (const alert of result.alerts) {
      const normalizedId = alert.id.toUpperCase(); // GHSA-123 === ghsa-123
      const existing = alertMap.get(normalizedId);
      // Keep the more severe version if duplicate
      if (!existing || severityRank(alert.severity) > severityRank(existing.severity)) {
        alertMap.set(normalizedId, alert);
      }
    }
  }

  // Cross-reference CVE IDs against CISA KEV
  const allIds = [...alertMap.keys()];
  // Also extract CVE IDs from alert summaries (OSV often includes them)
  const cveIds = allIds.filter(id => id.startsWith('CVE-'));
  if (cveIds.length > 0) {
    const kevAlerts = await checkCisaKev(cveIds);
    for (const alert of kevAlerts) {
      alertMap.set(alert.id, alert); // KEV always wins (CRITICAL)
    }
  }

  return {
    alerts: [...alertMap.values()],
    errors,
    latencyMs: Date.now() - start,
  };
}

function severityRank(s: VulnerabilityAlert['severity']): number {
  switch (s) {
    case 'CRITICAL': return 4;
    case 'HIGH': return 3;
    case 'MODERATE': return 2;
    case 'LOW': return 1;
  }
}
