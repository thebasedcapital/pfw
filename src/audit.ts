/**
 * PFW Audit Log — SQLite-based install history.
 * Records every package check with decision, alerts, source, latency.
 * Queryable via `pfw log` CLI.
 */
import { DatabaseSync } from 'node:sqlite';
import { existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { PackageRef, BlockDecision, VulnerabilityAlert } from './types.js';

const PFW_DIR = join(homedir(), '.pfw');
const DB_PATH = join(PFW_DIR, 'audit.db');

let db: DatabaseSync | null = null;

function getDb(): DatabaseSync {
  if (db) return db;
  if (!existsSync(PFW_DIR)) mkdirSync(PFW_DIR, { recursive: true });
  db = new DatabaseSync(DB_PATH);
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT NOT NULL DEFAULT (datetime('now')),
      name TEXT NOT NULL,
      version TEXT NOT NULL,
      ecosystem TEXT NOT NULL,
      purl TEXT NOT NULL,
      action TEXT NOT NULL,
      alerts TEXT,
      sources TEXT,
      latency_ms INTEGER,
      caller TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_audit_name ON audit(name);
    CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
    CREATE INDEX IF NOT EXISTS idx_audit_action ON audit(action);
    CREATE INDEX IF NOT EXISTS idx_audit_ecosystem ON audit(ecosystem);
  `);
  return db;
}

/** Record a package check to the audit log */
export function recordAudit(
  pkg: PackageRef,
  decision: BlockDecision,
  caller?: string,
): void {
  try {
    const d = getDb();
    const alertsJson = JSON.stringify(decision.alerts.map(a => ({
      id: a.id,
      summary: a.summary,
      severity: a.severity,
      source: a.source,
    })));
    const sources = [...new Set(decision.alerts.map(a => a.source))].join(',');
    d.prepare(`
      INSERT INTO audit (name, version, ecosystem, purl, action, alerts, sources, latency_ms, caller)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(pkg.name, pkg.version, pkg.kind, pkg.purl, decision.action, alertsJson, sources, decision.latencyMs, caller ?? null);
  } catch {
    // Audit logging must never break installs
  }
}

/** Query audit log — returns rows as objects */
export function queryAudit(opts: {
  name?: string;
  ecosystem?: string;
  action?: string;
  since?: string;
  limit?: number;
}): Record<string, unknown>[] {
  const d = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (opts.name) {
    conditions.push('name LIKE ?');
    params.push(`%${opts.name}%`);
  }
  if (opts.ecosystem) {
    conditions.push('ecosystem = ?');
    params.push(opts.ecosystem);
  }
  if (opts.action) {
    conditions.push('action = ?');
    params.push(opts.action);
  }
  if (opts.since) {
    conditions.push("ts >= datetime(?, 'utc')");
    params.push(opts.since);
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  const limit = opts.limit ?? 50;
  params.push(limit);

  return d.prepare(`
    SELECT id, ts, name, version, ecosystem, action, alerts, sources, latency_ms, caller
    FROM audit ${where}
    ORDER BY ts DESC
    LIMIT ?
  `).all(...(params as Array<string | number | null>)) as Record<string, unknown>[];
}

/** Get summary stats */
export function auditStats(): {
  total: number;
  blocked: number;
  warned: number;
  allowed: number;
  topBlocked: { name: string; count: number }[];
  ecosystems: { ecosystem: string; count: number }[];
} {
  const d = getDb();
  const total = (d.prepare('SELECT COUNT(*) as c FROM audit').get() as any).c;
  const blocked = (d.prepare("SELECT COUNT(*) as c FROM audit WHERE action='block'").get() as any).c;
  const warned = (d.prepare("SELECT COUNT(*) as c FROM audit WHERE action='warn'").get() as any).c;
  const allowed = (d.prepare("SELECT COUNT(*) as c FROM audit WHERE action='allow'").get() as any).c;
  const topBlocked = d.prepare(
    "SELECT name, COUNT(*) as count FROM audit WHERE action='block' GROUP BY name ORDER BY count DESC LIMIT 10"
  ).all() as { name: string; count: number }[];
  const ecosystems = d.prepare(
    'SELECT ecosystem, COUNT(*) as count FROM audit GROUP BY ecosystem ORDER BY count DESC'
  ).all() as { ecosystem: string; count: number }[];

  return { total, blocked, warned, allowed, topBlocked, ecosystems };
}

/** Close the database */
export function closeAudit(): void {
  if (db) { db.close(); db = null; }
}
