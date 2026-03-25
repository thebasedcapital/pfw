import forge from 'node-forge';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const CA_SUBJECT = [
  { name: 'commonName', value: 'Package Firewall CA' },
  { name: 'organizationName', value: 'Package Firewall (Local)' },
];

const CA_EXTENSIONS = [
  { cA: true, critical: true, name: 'basicConstraints' },
  { critical: true, keyCertSign: true, name: 'keyUsage' },
  { name: 'subjectKeyIdentifier' },
];

/** Host cert cache — keyed by hostname */
const hostCertCache = new Map<string, { cert: string; key: string }>();

/** Generate a new CA keypair, write to disk */
export function generateCaKeyPair(
  outputDir?: string,
  prefix = 'pfwCa',
  force = false,
  keySize = 2048
): { caCertPath: string; caKeyPath: string; isTemporary: boolean } | null {
  const isTemp = !outputDir;
  if (!outputDir) outputDir = path.join(os.homedir(), '.pfw', 'certs');

  const keyPath = path.join(outputDir, `${prefix}.key`);
  const certPath = path.join(outputDir, `${prefix}.crt`);

  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  if (!force && fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    return { caCertPath: certPath, caKeyPath: keyPath, isTemporary: isTemp };
  }

  const keypair = forge.pki.rsa.generateKeyPair(keySize);
  const cert = forge.pki.createCertificate();

  cert.publicKey = keypair.publicKey;
  cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));

  const now = new Date();
  cert.validity.notBefore = now;
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(now.getFullYear() + 1);

  cert.setSubject(CA_SUBJECT);
  cert.setIssuer(CA_SUBJECT);
  cert.setExtensions(CA_EXTENSIONS);
  cert.sign(keypair.privateKey, forge.md.sha256.create());

  const certPem = forge.pki.certificateToPem(cert);
  const keyPem = forge.pki.privateKeyToPem(keypair.privateKey);

  fs.writeFileSync(certPath, certPem);
  fs.writeFileSync(keyPath, keyPem);

  return { caCertPath: certPath, caKeyPath: keyPath, isTemporary: isTemp };
}

/** Generate a per-host certificate signed by our CA */
export function getHostCert(
  hostname: string,
  caCertPem: string,
  caKeyPem: string
): { cert: string; key: string } {
  const cacheKey = hostname;
  const cached = hostCertCache.get(cacheKey);
  if (cached) return cached;

  const caCert = forge.pki.certificateFromPem(caCertPem);
  const caKey = forge.pki.privateKeyFromPem(caKeyPem);
  const keypair = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();

  cert.publicKey = keypair.publicKey;
  cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));

  const now = new Date();
  cert.validity.notBefore = now;
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(now.getFullYear() + 1);

  cert.setSubject([{ name: 'commonName', value: hostname }]);
  cert.setIssuer(caCert.subject.attributes);
  cert.setExtensions([
    { cA: false, name: 'basicConstraints' },
    { digitalSignature: true, keyEncipherment: true, name: 'keyUsage' },
    { name: 'extKeyUsage', serverAuth: true },
    { altNames: [{ type: 2, value: hostname }], name: 'subjectAltName' },
  ]);

  cert.sign(caKey, forge.md.sha256.create());

  const result = {
    cert: forge.pki.certificateToPem(cert),
    key: forge.pki.privateKeyToPem(keypair.privateKey),
  };

  hostCertCache.set(cacheKey, result);
  return result;
}

/** Load existing CA cert+key from paths */
export function loadCaCert(certPath: string, keyPath: string): { cert: string; key: string } {
  return {
    cert: fs.readFileSync(certPath, 'utf-8'),
    key: fs.readFileSync(keyPath, 'utf-8'),
  };
}
