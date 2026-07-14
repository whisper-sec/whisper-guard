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

export interface EnrichRow {
  ip?: string;
  city?: string;
  country?: string;
  asn?: string;
  owner?: string;
  asnName?: string;
  prefix?: string;
  verdict?: string;
}

/** One control-plane endpoint (device or agent) the mock account holds. */
export interface MockEndpoint {
  agent: string;
  address: string;
  label: string;
  fqdn?: string;
  device?: boolean;
  created?: number;
  state?: string;
  counters?: Record<string, number>;
  logs?: Record<string, unknown>[];
}

export class E2ENetwork {
  readonly log: CapturedRequest[] = [];
  graphMode: GraphMode = "mock";
  graphDelayMs = 0;
  private verdicts = new Map<string, Verdict>();
  private explainRows = new Map<string, Record<string, unknown>[]>();
  private identifyRows = new Map<string, Record<string, unknown>[]>();
  private enrichRows = new Map<string, EnrichRow>();
  private variantRows = new Map<string, Record<string, unknown>[]>();
  private historyRows = new Map<string, Record<string, unknown>[]>();
  private cohostRows = new Map<string, Record<string, unknown>>();
  readonly endpoints: MockEndpoint[] = [];
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

  // A faithful local stand-in for the Whisper HTTPS-CONNECT egress endpoint:
  // it demands Proxy-Authorization (Basic w:et_…), records every CONNECT it
  // carries, and tunnels to the same mock TLS terminator so pages still load.
  // op:connect hands the extension THIS proxy's address, so turning the
  // browser-as-endpoint toggle on genuinely routes traffic through it.
  private egressProxy!: http.Server;
  egressPort = 0;
  readonly egressToken = "et_e2emocktoken000";
  readonly egressLog: { host: string; at: number }[] = [];
  readonly egressAttempts: { host: string; authed: boolean }[] = [];

  egressConnects(host: string): number {
    return this.egressLog.filter((r) => r.host === host).length;
  }
  clearEgressLog(): void {
    this.egressLog.length = 0;
    this.egressAttempts.length = 0;
  }

  setVerdict(host: string, v: Verdict): void {
    this.verdicts.set(host.toLowerCase(), v);
  }
  setExplain(host: string, rows: Record<string, unknown>[]): void {
    this.explainRows.set(host.toLowerCase(), rows);
  }
  setIdentify(host: string, rows: Record<string, unknown>[]): void {
    this.identifyRows.set(host.toLowerCase(), rows);
  }
  setEnrich(host: string, row: EnrichRow): void {
    this.enrichRows.set(host.toLowerCase(), row);
  }
  setVariants(host: string, rows: Record<string, unknown>[]): void {
    this.variantRows.set(host.toLowerCase(), rows);
  }
  setHistory(host: string, rows: Record<string, unknown>[]): void {
    this.historyRows.set(host.toLowerCase(), rows);
  }
  setCohost(host: string, row: Record<string, unknown>): void {
    this.cohostRows.set(host.toLowerCase(), row);
  }
  addEndpoint(e: MockEndpoint): void {
    this.endpoints.push(e);
  }
  clearEndpoints(): void {
    this.endpoints.length = 0;
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

    // The Whisper egress endpoint stand-in (auth-required CONNECT proxy).
    this.egressProxy = http.createServer((_req, res) => {
      res.writeHead(405).end("egress endpoint speaks CONNECT only");
    });
    this.egressProxy.on("connect", (req, clientSocket, head) => {
      const host = (req.url ?? "").split(":")[0].toLowerCase();
      const auth = req.headers["proxy-authorization"];
      const expected = "Basic " + Buffer.from(`w:${this.egressToken}`).toString("base64");
      this.egressAttempts.push({ host, authed: auth === expected });
      if (auth !== expected) {
        // Challenge (or reject a bad credential): the browser re-issues with
        // the credential onAuthRequired supplies.
        clientSocket.write(
          'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="whisper-egress"\r\nContent-Length: 0\r\n\r\n',
        );
        clientSocket.end();
        return;
      }
      this.egressLog.push({ host, at: Date.now() });
      const upstream = net.connect(this.tlsPort, "127.0.0.1", () => {
        clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        upstream.write(head);
        upstream.pipe(clientSocket);
        clientSocket.pipe(upstream);
      });
      upstream.on("error", () => clientSocket.destroy());
      clientSocket.on("error", () => upstream.destroy());
    });
    await new Promise<void>((r) => this.egressProxy.listen(0, "127.0.0.1", r));
    this.egressPort = (this.egressProxy.address() as net.AddressInfo).port;
  }

  async stop(): Promise<void> {
    await new Promise((r) => this.proxy.close(r));
    await new Promise((r) => this.tlsServer.close(r));
    await new Promise((r) => this.egressProxy.close(r));
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
    if (host === "rdap.whisper.online") return this.serveRdap(path, res);
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

    // The control plane rides the SAME endpoint: a bare CALL whisper.agents.
    if (q.includes("whisper.agents")) {
      return this.serveAgents(q, res);
    }

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
      // Both single ($h) and batched ($hs) forms.
      const hs = Array.isArray(params["hs"])
        ? (params["hs"] as string[])
        : [String(params["h"] ?? "")];
      for (const h of hs) rows.push(...(this.identifyRows.get(h.toLowerCase()) ?? []));
    } else if (q.includes("whisper.variants")) {
      const h = String(params["h"] ?? "").toLowerCase();
      rows.push(...(this.variantRows.get(h) ?? []));
    } else if (q.includes("whisper.history")) {
      const h = String(params["h"] ?? "").toLowerCase();
      rows.push(...(this.historyRows.get(h) ?? []));
    } else if (q.includes("whisper.submit")) {
      this.submits.push(params["a"] as Record<string, unknown>);
      rows.push({ accepted: true });
    } else if (q.includes("ANNOUNCED_BY") && q.includes("cohosted")) {
      // The destination drill (co-hosting fan-in).
      const h = String(params["h"] ?? "").toLowerCase();
      const row = this.cohostRows.get(h);
      if (row) rows.push(row);
    } else if (q.includes("RESOLVES_TO")) {
      // Enrichment: keyed (RETURN ... asn, owner ...), keyless geo, keyless net.
      const hs = Array.isArray(params["hosts"]) ? (params["hosts"] as string[]) : [];
      const wantNet = q.includes("prefix") && q.includes("threatNeighbors") && !q.includes("city");
      const wantGeoOnly = q.includes("city") && !q.includes("owner");
      for (const h of hs) {
        const e = this.enrichRows.get(h.toLowerCase());
        if (!e) continue;
        if (wantNet) {
          rows.push({ host: h.toLowerCase(), prefix: e.prefix ?? null, threatNeighbors: null });
        } else if (wantGeoOnly) {
          rows.push({ host: h.toLowerCase(), ip: e.ip ?? null, city: e.city ?? null, verdict: e.verdict ?? null });
        } else {
          rows.push({
            host: h.toLowerCase(),
            ip: e.ip ?? null,
            city: e.city ?? null,
            country: e.country ?? null,
            asn: e.asn ?? null,
            owner: e.owner ?? null,
            asnName: e.asnName ?? null,
            verdict: e.verdict ?? null,
          });
        }
      }
    }

    res
      .writeHead(200, { "content-type": "application/json" })
      .end(JSON.stringify({ columns: [], rows, statistics: { rowCount: rows.length } }));
  }

  // ---------------------------------------------- mock control plane (agents)

  private serveAgents(query: string, res: http.ServerResponse): void {
    const opMatch = /op:'([a-z]+)'/.exec(query);
    const op = opMatch?.[1] ?? "";
    let result: { columns: string[]; rows: unknown[] } = { columns: [], rows: [] };

    if (op === "list") {
      result = {
        columns: ["kind", "item"],
        rows: this.endpoints.map((e) => [
          "agents",
          {
            agent: e.agent,
            address: e.address,
            fqdn: e.fqdn ?? `${e.agent}.t-e2e.agents.whisper.online.`,
            label: e.label,
            device: e.device ? "true" : undefined,
            created: e.created ?? Date.now(),
            state: e.state ?? "active",
          },
        ]),
      };
    } else if (op === "agent") {
      const addrMatch = /agent:'([^']+)'/.exec(query);
      const e = this.endpoints.find((x) => x.agent === addrMatch?.[1]);
      const c = e?.counters ?? {};
      result = {
        columns: [
          "agent", "address", "fqdn", "label", "state", "last_seen",
          "dns_queries", "dns_blocked", "dns_nxdomain", "connections_total", "bytes_up", "bytes_down",
        ],
        rows: e
          ? [[
              e.agent, e.address, e.fqdn ?? "", e.label, e.state ?? "active", c["last_seen"] ?? Date.now(),
              c["dns_queries"] ?? 0, c["dns_blocked"] ?? 0, c["dns_nxdomain"] ?? 0,
              c["connections_total"] ?? 0, c["bytes_up"] ?? 0, c["bytes_down"] ?? 0,
            ]]
          : [],
      };
    } else if (op === "logs") {
      const agentMatch = /agent:'([^']+)'/.exec(query);
      const e = this.endpoints.find((x) => x.agent === agentMatch?.[1]);
      const cols = ["ts", "kind", "qname", "qtype", "rcode", "decision", "source", "answer", "latency_ms", "agent", "peer"];
      result = {
        columns: cols,
        rows: (e?.logs ?? []).map((r) => cols.map((c) => (r as Record<string, unknown>)[c] ?? null)),
      };
    } else if (op === "register") {
      const labelMatch = /label:'([^']*)'/.exec(query);
      const agent = `agent-e2e${Math.random().toString(16).slice(2, 12)}`;
      const address = `2a04:2a01:e2e:${Math.random().toString(16).slice(2, 6)}::1`;
      const e: MockEndpoint = { agent, address, label: labelMatch?.[1] ?? "device", device: true, state: "active", logs: [] };
      this.endpoints.push(e);
      result = { columns: ["agent", "address", "label"], rows: [[agent, address, e.label]] };
    } else if (op === "connect") {
      const agentMatch = /agent:'([^']+)'/.exec(query);
      const e = this.endpoints.find((x) => x.agent === agentMatch?.[1]);
      // Hand back THIS process's local egress endpoint so the browser is
      // genuinely routed through it (an http-scheme CONNECT proxy locally;
      // the production endpoint is the https egress on :443).
      result = {
        columns: ["http_proxy", "connection_string", "address"],
        rows: [[
          `http://w:${this.egressToken}@127.0.0.1:${this.egressPort}`,
          `socks5h://w:${this.egressToken}@127.0.0.1:${this.egressPort}`,
          e?.address ?? "",
        ]],
      };
    }

    const envelope = {
      columns: ["op", "ok", "status", "result", "error", "retry_after"],
      rows: [{ op, ok: true, status: 200, result, error: null, retry_after: null }],
    };
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(envelope));
  }

  // ------------------------------------------------ mock rdap (keyless)

  private serveRdap(path: string, res: http.ServerResponse): void {
    const url = new URL(path, "https://rdap.whisper.online");
    if (url.pathname === "/verify-identity") {
      const ip = (url.searchParams.get("ip") ?? "").toLowerCase();
      const known = this.endpoints.find((e) => e.address.toLowerCase() === ip);
      const body = known
        ? {
            is_whisper_agent: true,
            fqdn: known.fqdn ?? `${known.agent}.t-e2e.agents.whisper.online`,
            dane_ok: true,
            jws_ok: true,
            evidence: { address: ip, posture: "tier1.5" },
          }
        : { is_whisper_agent: false, evidence: { address: ip, ptr: null }, detail: "no Whisper agent identity anchors this address" };
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(body));
      return;
    }
    if (url.pathname.startsWith("/ip/")) {
      res.writeHead(200, { "content-type": "application/json" }).end(
        JSON.stringify({ objectClassName: "ip network", handle: "e2e", type: "Whisper agent identity" }),
      );
      return;
    }
    res.writeHead(404).end();
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
