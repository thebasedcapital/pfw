// All shared types for the package firewall

export type RegistryKind = 'npm' | 'pypi' | 'cargo' | 'gem' | 'golang' | 'maven' | 'nuget' | 'wrap' | 'block';

export interface RegistryConfig {
  fqdn: string;
  kind: RegistryKind;
  protocol?: 'https' | 'http';
  ca?: string;
}

export interface PackageRef {
  name: string;
  version: string;
  kind: RegistryKind;
  purl: string; // pkg:npm/lodash@4.17.21
}

export type BlockAction = 'block' | 'warn' | 'allow';

export interface VulnerabilityAlert {
  id: string;
  summary: string;
  severity: 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW';
  action: BlockAction;
  source: string; // 'osv' | 'local-policy'
}

export interface BlockDecision {
  action: BlockAction;
  alerts: VulnerabilityAlert[];
  cached: boolean;
  latencyMs: number;
}

export interface PolicyRule {
  pattern: string; // glob pattern for package name
  action: BlockAction;
  reason?: string;
}

export interface FirewallConfig {
  debug: boolean;
  silent: boolean;
  failAction: BlockAction; // what to do when API unreachable
  unknownHostAction: BlockAction;
  caCertPath?: string;
  caKeyPath?: string;
  policies: PolicyRule[];
  allowedRegistries: Map<string, RegistryConfig>;
  cacheTtlMs: number;
  staleTtlMs: number;
  osvEnabled: boolean;
  localPolicyOnly: boolean; // true = no external API calls at all
  port?: number; // fixed port override (default: random)
}
