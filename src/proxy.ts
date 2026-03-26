import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import net from 'node:net';
import type { FirewallConfig, RegistryConfig } from './types.js';
import { parsePackageUrl } from './registry.js';
import { checkPackage, checkLocalPolicy, flushCache } from './api.js';
import { getHostCert } from './tls.js';

/** Create and start the proxy server */
export async function startProxy(config: FirewallConfig, caCert: string, caKey: string): Promise<{
  server: http.Server;
  address: string;
  port: number;
}> {
  const httpHandler = createHttpHandler(config);
  const server = http.createServer(httpHandler);

  // CONNECT handler for HTTPS traffic
  server.on('connect', (req: http.IncomingMessage, clientSocket: net.Socket, head: Buffer) => {
    handleConnect(req, clientSocket, head, config, caCert, caKey, httpHandler).catch(err => {
      if (config.debug) console.error('[proxy] CONNECT error:', err.message);
      clientSocket.destroy();
    });
  });

  server.on('clientError', (err: any) => {
    if (err?.code !== 'ECONNRESET' && config.debug) {
      console.error('[proxy] clientError:', err.message);
    }
  });

  const listenPort = config.port ?? 0;
  await new Promise<void>(resolve => server.listen(listenPort, '127.0.0.1', resolve));
  const addr = server.address() as net.AddressInfo;
  return { server, address: addr.address, port: addr.port };
}

/** Unified HTTP request handler — used for both direct HTTP and MITM'd HTTPS */
function createHttpHandler(config: FirewallConfig): http.RequestListener {
  return async (req: http.IncomingMessage, res: http.ServerResponse) => {
    try {
      // Health check for wrapper liveness detection
      if (req.url === '/pfw/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true,"version":"0.2.0"}');
        return;
      }

      if (req.method === 'POST' && req.url === '/pfw/flush-cache') {
        flushCache();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
        return;
      }

      const hostHeader = req.headers.host || '';
      let hostname = hostHeader.split(':')[0];
      let urlPath = req.url || '/';

      // In direct proxy mode, req.url is the full URL (http://host/path)
      // Extract just the path component
      if (urlPath.startsWith('http://') || urlPath.startsWith('https://')) {
        const parsed = new URL(urlPath);
        urlPath = parsed.pathname + parsed.search;
      }

      // When npm points directly at us (registry override), hostname is 127.0.0.1
      // Route to the default npm registry
      if (hostname === '127.0.0.1' || hostname === 'localhost') {
        hostname = 'registry.npmjs.org';
      }

      if (config.debug) {
        console.error(`[proxy] ${req.method} ${hostname}${urlPath}`);
      }

      if (!hostname) {
        res.writeHead(400);
        res.end('Missing Host header');
        return;
      }

      const registry = config.allowedRegistries.get(hostname);
      if (!registry || registry.kind === 'wrap') {
        return forwardRequest(req, res, hostname, 443, urlPath);
      }

      if (registry.kind === 'block') {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Registry blocked by policy');
        return;
      }

      // Check metadata requests against local policy (e.g. GET /is-odd for npm)
      if (registry.kind === 'npm' && req.method === 'GET') {
        const metadataMatch = urlPath.match(/^\/((?:@[^/]+\/)?[^/]+)$/);
        if (metadataMatch) {
          const pkgName = metadataMatch[1];
          const metaPkg = { name: pkgName, version: '*', kind: 'npm' as const, purl: `pkg:npm/${pkgName}` };
          const policyHit = checkLocalPolicy(metaPkg, config.policies);
          if (policyHit && policyHit.action === 'block') {
            if (!config.silent) {
              console.error(`\x1b[31m[BLOCKED]\x1b[0m ${pkgName} — ${policyHit.summary}`);
            }
            res.writeHead(403, { 'Content-Type': 'text/plain', 'X-Block-Reason': policyHit.id });
            res.end(`Package blocked: ${policyHit.summary}\n`);
            return;
          }
        }
      }

      // Check tarball downloads against local policy + vuln sources
      const pkg = parsePackageUrl(registry.kind, urlPath);
      if (pkg) {
        // Local policy (blocklist) = hard block always
        const policyHit = checkLocalPolicy(pkg, config.policies);
        if (policyHit && policyHit.action === 'block') {
          if (!config.silent) {
            console.error(`\x1b[31m[BLOCKED]\x1b[0m ${pkg.purl} — ${policyHit.summary}`);
          }
          res.writeHead(403, { 'Content-Type': 'text/plain', 'X-Block-Reason': policyHit.id });
          res.end(`Package blocked: ${policyHit.summary}\n`);
          return;
        }

        // Vuln DB check = warn on tarball downloads (transitive deps)
        // Hard-blocking transitive deps breaks too many installs.
        // The vulnerability is still logged for the user to see.
        const decision = await checkPackage(pkg, config);
        if (decision.alerts.length > 0 && !config.silent) {
          const reasons = decision.alerts.map(a => `[${a.severity}] ${a.id}: ${a.summary}`).join(', ');
          console.warn(`\x1b[33m[VULN]\x1b[0m ${pkg.purl} — ${reasons}`);
        }
      }

      // Forward to real registry
      return forwardRequest(req, res, hostname, 443, urlPath);
    } catch (err: any) {
      if (config.debug) console.error('[proxy] handler error:', err.message);
      if (!res.headersSent) {
        res.writeHead(502);
        res.end('Internal proxy error');
      }
    }
  };
}

/** Handle CONNECT tunneling — TLS MITM for HTTPS registries */
async function handleConnect(
  req: http.IncomingMessage,
  clientSocket: net.Socket,
  head: Buffer,
  config: FirewallConfig,
  caCert: string,
  caKey: string,
  httpHandler: http.RequestListener,
): Promise<void> {
  const [hostname, portStr] = (req.url || '').split(':');
  const port = parseInt(portStr) || 443;

  const registry = config.allowedRegistries.get(hostname);

  if (!registry) {
    if (config.unknownHostAction === 'block') {
      clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\nUnknown host blocked\r\n');
      clientSocket.destroy();
      return;
    }
    if (config.unknownHostAction === 'warn' && !config.silent) {
      console.warn(`[pfw] unknown host: ${hostname} — passing through`);
    }
    return tunnelDirect(clientSocket, hostname, port, head);
  }

  if (registry.kind === 'wrap') {
    return tunnelDirect(clientSocket, hostname, port, head);
  }

  if (registry.kind === 'block') {
    clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\nRegistry blocked\r\n');
    clientSocket.destroy();
    return;
  }

  // MITM: intercept HTTPS traffic
  clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

  const hostCert = getHostCert(hostname, caCert, caKey);
  const secureContext = tls.createSecureContext({ cert: hostCert.cert, key: hostCert.key });

  const tlsSocket = new tls.TLSSocket(clientSocket, {
    isServer: true,
    secureContext,
    ALPNProtocols: ['http/1.1'],
  });

  if (head.length) tlsSocket.unshift(head);

  tlsSocket.on('error', (err: any) => {
    if (err?.code !== 'ECONNRESET' && config.debug) {
      console.error(`[proxy] TLS error for ${hostname}:`, err.message);
    }
  });

  // Feed the decrypted TLS stream into an HTTP parser via emit('connection')
  const innerServer = http.createServer((innerReq, innerRes) => {
    innerReq.headers.host = `${hostname}:${port}`;
    httpHandler(innerReq, innerRes);
  });

  innerServer.on('error', (err: any) => {
    if (config.debug) console.error('[proxy] inner server error:', err.message);
  });

  innerServer.emit('connection', tlsSocket);
}

/** Forward request to upstream registry via HTTPS */
function forwardRequest(
  clientReq: http.IncomingMessage,
  clientRes: http.ServerResponse,
  hostname: string,
  port: number,
  path: string,
): Promise<void> {
  return new Promise((resolve) => {
    const options: https.RequestOptions = {
      hostname,
      port,
      path,
      method: clientReq.method,
      headers: { ...clientReq.headers, host: hostname },
    };

    const upstream = https.request(options, (upstreamRes) => {
      clientRes.writeHead(upstreamRes.statusCode || 502, upstreamRes.headers);
      upstreamRes.pipe(clientRes);
      upstreamRes.on('end', resolve);
    });

    upstream.on('error', (err) => {
      if (!clientRes.headersSent) {
        clientRes.writeHead(502, { 'Content-Type': 'text/plain' });
        clientRes.end(`Upstream error: ${err.message}`);
      }
      resolve();
    });

    clientReq.pipe(upstream);
  });
}

/** Direct tunnel — no inspection, just pipe bytes */
function tunnelDirect(clientSocket: net.Socket, hostname: string, port: number, head: Buffer): void {
  const upstream = net.connect(port, hostname, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head.length) upstream.write(head);
    upstream.pipe(clientSocket);
    clientSocket.pipe(upstream);
  });

  upstream.on('error', () => clientSocket.destroy());
  clientSocket.on('error', () => upstream.destroy());
}

/** Build env vars to inject into the child process */
export function getProxyEnv(address: string, port: number, caCertPath: string): Record<string, string> {
  const proxyUrl = `http://${address}:${port}`;
  return {
    HTTP_PROXY: proxyUrl,
    HTTPS_PROXY: proxyUrl,
    http_proxy: proxyUrl,
    https_proxy: proxyUrl,
    NODE_EXTRA_CA_CERTS: caCertPath,
    PIP_CERT: caCertPath,
    SSL_CERT_FILE: caCertPath,
    CARGO_HTTP_PROXY: proxyUrl,
    CARGO_HTTP_CAINFO: caCertPath,
    YARN_HTTP_PROXY: proxyUrl,
    YARN_HTTPS_PROXY: proxyUrl,
  };
}
