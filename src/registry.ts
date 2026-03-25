import type { PackageRef, RegistryKind } from './types.js';

/** Parse npm tarball URL: /@scope/name/-/name-version.tgz or /name/-/name-version.tgz */
export function parseNpmUrl(urlPath: string): PackageRef | null {
  // Scoped: /@scope/name/-/name-name-version.tgz
  const scopedMatch = urlPath.match(/^\/@([^/]+)\/([^/]+)\/-\/\2-(.+)\.tgz$/);
  if (scopedMatch) {
    const name = `@${scopedMatch[1]}/${scopedMatch[2]}`;
    return { name, version: scopedMatch[3], kind: 'npm', purl: `pkg:npm/${encodeURIComponent(name)}@${scopedMatch[3]}` };
  }
  // Unscoped: /name/-/name-version.tgz
  const unscopedMatch = urlPath.match(/^\/([^@/][^/]*)\/-\/\1-(.+)\.tgz$/);
  if (unscopedMatch) {
    const name = unscopedMatch[1];
    return { name, version: unscopedMatch[2], kind: 'npm', purl: `pkg:npm/${name}@${unscopedMatch[2]}` };
  }
  return null;
}

/** Parse PyPI download URL: filename like name-version.whl or name-version.tar.gz */
export function parsePypiUrl(urlPath: string): PackageRef | null {
  const filename = urlPath.split('/').pop() || '';
  // Wheel: name-version(-tags).whl
  const wheelMatch = filename.match(/^([A-Za-z0-9_.-]+?)-(\d+[^-]*?)(?:-[^.]+)*\.whl$/);
  if (wheelMatch) {
    const name = wheelMatch[1].replace(/_/g, '-').toLowerCase();
    return { name, version: wheelMatch[2], kind: 'pypi', purl: `pkg:pypi/${name}@${wheelMatch[2]}` };
  }
  // Sdist: name-version.tar.gz or .zip
  const sdistMatch = filename.match(/^([A-Za-z0-9_.-]+?)-(\d+\S+?)\.(?:tar\.gz|zip)$/);
  if (sdistMatch) {
    const name = sdistMatch[1].replace(/_/g, '-').toLowerCase();
    return { name, version: sdistMatch[2], kind: 'pypi', purl: `pkg:pypi/${name}@${sdistMatch[2]}` };
  }
  return null;
}

/** Parse crates.io download URL: /crates/name/version/download */
export function parseCargoUrl(urlPath: string): PackageRef | null {
  const match = urlPath.match(/^\/crates\/([^/]+)\/([^/]+)\/download$/);
  if (!match) return null;
  return { name: match[1], version: match[2], kind: 'cargo', purl: `pkg:cargo/${match[1]}@${match[2]}` };
}

/** Parse RubyGems URL: /gems/name-version.gem */
export function parseGemUrl(urlPath: string): PackageRef | null {
  const match = urlPath.match(/^\/gems\/([^/]+?)-(\d+\S+?)\.gem$/);
  if (!match) return null;
  return { name: match[1], version: match[2], kind: 'gem', purl: `pkg:gem/${match[1]}@${match[2]}` };
}

/** Parse Go module URL: /module/@v/vVersion.{mod,zip,info} */
export function parseGoUrl(urlPath: string): PackageRef | null {
  const match = urlPath.match(/^\/(.+)\/@v\/v([^/]+)\.(mod|zip|info)$/);
  if (!match) return null;
  return { name: match[1], version: match[2], kind: 'golang', purl: `pkg:golang/${match[1]}@${match[2]}` };
}

/** Parse Maven URL: /maven2/group/artifact/version/filename */
export function parseMavenUrl(urlPath: string): PackageRef | null {
  const match = urlPath.match(/^\/maven2\/(.+)\/([^/]+)\/([^/]+)\/[^/]+$/);
  if (!match) return null;
  const groupId = match[1].replace(/\//g, '.');
  return { name: `${groupId}:${match[2]}`, version: match[3], kind: 'maven', purl: `pkg:maven/${groupId}/${match[2]}@${match[3]}` };
}

/** Parse NuGet URL: /v3-flatcontainer/name/version/name.version.nupkg */
export function parseNugetUrl(urlPath: string): PackageRef | null {
  const match = urlPath.match(/^\/v3-flatcontainer\/([^/]+)\/([^/]+)\/[^/]+\.nupkg$/);
  if (!match) return null;
  return { name: match[1], version: match[2], kind: 'nuget', purl: `pkg:nuget/${match[1]}@${match[2]}` };
}

/** Route a URL to the correct parser based on registry kind */
export function parsePackageUrl(kind: RegistryKind, urlPath: string): PackageRef | null {
  // Strip query params and hash before parsing — prevents ?bypass=1 evasion
  const cleanPath = urlPath.split('?')[0].split('#')[0];
  switch (kind) {
    case 'npm': return parseNpmUrl(cleanPath);
    case 'pypi': return parsePypiUrl(cleanPath);
    case 'cargo': return parseCargoUrl(cleanPath);
    case 'gem': return parseGemUrl(cleanPath);
    case 'golang': return parseGoUrl(cleanPath);
    case 'maven': return parseMavenUrl(cleanPath);
    case 'nuget': return parseNugetUrl(cleanPath);
    case 'wrap': return null; // passthrough, no parsing
    case 'block': return null;
    default: return null;
  }
}
