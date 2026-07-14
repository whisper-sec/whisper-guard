// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The hermetic e2e network: ONE forward proxy the whole browser is pointed
// at, so every byte that would leave the machine is captured and answered
// locally. Plain-HTTP requests arrive as absolute-URI requests; HTTPS
// arrives as CONNECT and is terminated by a local TLS server with a
// self-signed certificate (the browser runs --ignore-certificate-errors).
//
// Because the browser's ONLY route to the network is this proxy, the
// captured request log is a COMPLETE record of everything that left the
// browser: the privacy invariant ("only the hostname, only to the graph")
// is asserted against the full set, not a sample.

import * as http from "node:http";
import * as https from "node:https";
import * as net from "node:net";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface CapturedRequest {
  scheme: "http" | "https" | "connect";
  method: string;
  host: string;
  path: string;
  body: string;
  at: number;
}

export interface Verdict {
  band: string;
  coverage: string | null;
  label: string | null;
}

export type GraphMode = "mock" | "down" | "http500" | "slow";

interface DeviceFlowMockState {
  pollsUntilApproved: number;
  polls: number;
  apiKey: string;
  approveVisited: boolean;
}

function makeSelfSignedCert(): { key: string; cert: string } {
  const dir = mkdtempSync(join(tmpdir(), "whisper-guard-e2e-"));
  const keyPath = join(dir, "key.pem");
  const certPath = join(dir, "cert.pem");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", keyPath, "-out", certPath,
    "-days", "2", "-subj", "/CN=whisper-guard-e2e",
  ], { stdio: "ignore" });
  const out = { key: readFileSync(keyPath, "utf8"), cert: readFileSync(certPath, "utf8") };
  rmSync(dir, { recursive: true, force: true });
  return out;
}

export class E2ENetwork {
  readonly log: CapturedRequest[] = [];
  graphMode: GraphMode = "mock";
  graphDelayMs = 0;
  private verdicts = new Map<string, Verdict>();
  private explainRows = new Map<string, Record<string, unknown>[]>();
  private identifyRows = new Map<string, Record<string, unknown>[]>();
  readonly submits: Record<string, unknown>[] = [];
  readonly device: DeviceFlowMockState = {
    pollsUntilApproved: 2,
    polls: 0,
    apiKey: "whisper_e2e_mock_key_0000000000000000",
    approveVisited: false,
  };

  private proxy!: http.Server;
  private tlsServer!: https.Server;
  private tlsPort = 0;
  proxyPort = 0;

  setVerdict(host: string, v: Verdict): void {
    this.verdicts.set(host.toLowerCase(), v);
  }
  setExplain(host: string, rows: Record<string, unknown>[]): void {
    this.explainRows.set(host.toLowerCase(), rows);
  }
  setIdentify(host: string, rows: Record<string, unknown>[]): void {
    this.identifyRows.set(host.toLowerCase(), rows);
  }
  clearLog(): void {
    this.log.length = 0;
  }
  requestsTo(host: string): CapturedRequest[] {
    return this.log.filter((r) => r.host === host);
  }

  // Chromium's own service endpoints: browser infrastructure, not the
  // extension. They are excluded from the "who was contacted" set but NOT
  // from the full-log secret scan, which always runs over everything.
  private static readonly BROWSER_INFRA =
    /(^|\.)(google\.com|googleapis\.com|gstatic\.com|gvt1\.com|googleusercontent\.com|chromium\.org)$/;

  contactedHosts(): string[] {
    return [
      ...new Set(
        this.log
          .filter((r) => r.scheme !== "connect")
          .map((r) => r.host)
          .filter((h) => !E2ENetwork.BROWSER_INFRA.test(h)),
      ),
    ];
  }

  async start(): Promise<void> {
    const { key, cert } = makeSelfSignedCert();

    // The TLS terminator: every CONNECT is piped here; SNI/Host routing
    // then serves the same mock handler as plain HTTP.
    this.tlsServer = https.createServer({ key, cert }, (req, res) => {
      void this.handle("https", req, res);
    });
    await new Promise<void>((r) => this.tlsServer.listen(0, "127.0.0.1", r));
    this.tlsPort = (this.tlsServer.address() as net.AddressInfo).port;

    this.proxy = http.createServer((req, res) => {
      // Absolute-URI plain-HTTP proxy request: http://host/path
      const m = /^http:\/\/([^/]+)(\/.*)?$/.exec(req.url ?? "");
      if (!m) {
        res.writeHead(400).end("bad proxy request");
        return;
      }
      void this.handle("http", req, res, m[1], m[2] ?? "/");
    });
    this.proxy.on("connect", (req, clientSocket, head) => {
      const host = (req.url ?? "").split(":")[0].toLowerCase();
      this.log.push({ scheme: "connect", method: "CONNECT", host, path: "", body: "", at: Date.now() });
      if (this.graphMode === "down" && host === "graph.whisper.security") {
        clientSocket.destroy();
        return;
      }
      const upstream = net.connect(this.tlsPort, "127.0.0.1", () => {
        clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        upstream.write(head);
        upstream.pipe(clientSocket);
        clientSocket.pipe(upstream);
      });
      upstream.on("error", () => clientSocket.destroy());
      clientSocket.on("error", () => upstream.destroy());
    });
    await new Promise<void>((r) => this.proxy.listen(0, "127.0.0.1", r));
    this.proxyPort = (this.proxy.address() as net.AddressInfo).port;
  }

  async stop(): Promise<void> {
    await new Promise((r) => this.proxy.close(r));
    await new Promise((r) => this.tlsServer.close(r));
  }

  private async handle(
    scheme: "http" | "https",
    req: http.IncomingMessage,
    res: http.ServerResponse,
    hostOverride?: string,
    pathOverride?: string,
  ): Promise<void> {
    const rawHost = hostOverride ?? req.headers.host ?? "";
    const host = rawHost.split(":")[0].toLowerCase();
    const path = pathOverride ?? req.url ?? "/";
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = Buffer.concat(chunks).toString("utf8");
    this.log.push({ scheme, method: req.method ?? "GET", host, path, body, at: Date.now() });

    if (host === "graph.whisper.security") return this.serveGraph(path, body, res);
    if (host === "console.whisper.security") return this.serveConsole(path, body, res);
    if (host === "get.whisper.online") {
      res.writeHead(404, { "content-type": "text/plain" }).end("no corpus published in e2e");
      return;
    }
    return this.serveFakeSite(host, path, res);
  }

  // ------------------------------------------------------------ mock graph

  private async serveGraph(path: string, body: string, res: http.ServerResponse): Promise<void> {
    if (this.graphMode === "down") {
      res.destroy();
      return;
    }
    if (this.graphMode === "http500") {
      res.writeHead(500, { "content-type": "application/json" }).end('{"title":"boom"}');
      return;
    }
    if (this.graphMode === "slow" || this.graphDelayMs > 0) {
      const delay = this.graphMode === "slow" ? 10_000 : this.graphDelayMs;
      await new Promise((r) => setTimeout(r, delay));
      if (this.graphMode === "slow") {
        res.destroy();
        return;
      }
    }
    if (path !== "/api/query") {
      res.writeHead(404).end();
      return;
    }
    let parsed: { query?: string; parameters?: Record<string, unknown> };
    try {
      parsed = JSON.parse(body) as typeof parsed;
    } catch {
      res.writeHead(400).end();
      return;
    }
    const q = parsed.query ?? "";
    const params = parsed.parameters ?? {};
    const rows: Record<string, unknown>[] = [];

    if (q.includes("whisper.assess")) {
      const hs = Array.isArray(params["hs"]) ? (params["hs"] as string[]) : [];
      for (const h of hs) {
        const v = this.verdicts.get(h.toLowerCase());
        rows.push(
          v
            ? { host: h.toLowerCase(), band: v.band, coverage: v.coverage, label: v.label }
            : { host: h.toLowerCase(), band: "UNKNOWN", coverage: "no-data", label: "unknown" },
        );
      }
    } else if (q.includes("whisper.explain")) {
      const h = String(params["h"] ?? "").toLowerCase();
      rows.push(...(this.explainRows.get(h) ?? []));
    } else if (q.includes("whisper.identify")) {
      const h = String(params["h"] ?? "").toLowerCase();
      rows.push(...(this.identifyRows.get(h) ?? []));
    } else if (q.includes("whisper.submit")) {
      this.submits.push(params["a"] as Record<string, unknown>);
      rows.push({ accepted: true });
    }

    res
      .writeHead(200, { "content-type": "application/json" })
      .end(JSON.stringify({ columns: [], rows, statistics: { rowCount: rows.length } }));
  }

  // --------------------------------------------------- mock console (8628)

  private serveConsole(path: string, _body: string, res: http.ServerResponse): void {
    if (path === "/api/device/authorize") {
      res.writeHead(200, { "content-type": "application/json" }).end(
        JSON.stringify({
          device_code: "e2e-device-code-1",
          user_code: "E2E-CODE",
          verification_uri: "https://console.whisper.security/activate",
          verification_uri_complete: "https://console.whisper.security/activate?user_code=E2E-CODE",
          interval: 1,
          expires_in: 600,
        }),
      );
      return;
    }
    if (path === "/api/device/token") {
      this.device.polls++;
      const approved = this.device.approveVisited && this.device.polls >= this.device.pollsUntilApproved;
      res.writeHead(200, { "content-type": "application/json" }).end(
        JSON.stringify(approved ? { status: "approved", api_key: this.device.apiKey } : { status: "pending" }),
      );
      return;
    }
    if (path.startsWith("/activate")) {
      this.device.approveVisited = true;
      res
        .writeHead(200, { "content-type": "text/html" })
        .end("<!doctype html><title>Whisper console</title><h1>Sign-in approved (e2e mock)</h1>");
      return;
    }
    res.writeHead(404).end();
  }

  // ------------------------------------------------------------- fake web

  private serveFakeSite(host: string, path: string, res: http.ServerResponse): void {
    res.writeHead(200, { "content-type": "text/html" }).end(
      `<!doctype html>
<html><head><title>${host}</title></head>
<body>
  <h1>e2e page for ${host}</h1>
  <p>path: ${path.split("?")[0]}</p>
  <form action="/login" method="post">
    <input type="text" name="user" autocomplete="username">
    <input type="password" name="pass" autocomplete="current-password">
    <button type="submit">Log in</button>
  </form>
</body></html>`,
    );
  }
}
