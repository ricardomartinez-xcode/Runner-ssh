import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { appendFile, chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { z } from "zod";
import type { AdminService } from "./admin.js";
import type { Environment } from "./config.js";
import { AppError } from "./errors.js";

type BreakGlassSession = {
  binding: string;
  exp: number;
  sid: string;
  v: 1;
};

type AttemptState = {
  count: number;
  expiresAt: number;
  lockedUntil: number;
};

type SocketTicket = {
  digest: string;
  expiresAt: number;
};

const authInput = z.object({ key: z.string().min(20).max(512) }).strict();
const socketAuthInput = z.object({ type: z.literal("authorize"), ticket: z.string().min(32).max(256) }).strict();
const sessionCookie = "relead_break_glass";

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function hmac(secret: string, value: string): string {
  return createHmac("sha256", secret).update(value).digest("base64url");
}

function hmacHex(secret: string, value: string): string {
  return createHmac("sha256", secret).update(value).digest("hex");
}

function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function cookies(request: FastifyRequest): Record<string, string> {
  const result: Record<string, string> = {};
  for (const part of (request.headers.cookie ?? "").split(";")) {
    const index = part.indexOf("=");
    if (index < 1) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (key) result[key] = value;
  }
  return result;
}

function clientIp(request: FastifyRequest): string {
  return request.ip;
}

function assertEnabled(env: Environment): void {
  if (!env.BREAK_GLASS_ENABLED) throw new AppError(404, "not_found", "Not found.");
}

function createSession(env: Environment, binding: string): { token: string; session: BreakGlassSession } {
  const session: BreakGlassSession = {
    v: 1,
    sid: randomBytes(16).toString("base64url"),
    binding,
    exp: Math.floor(Date.now() / 1000) + env.BREAK_GLASS_SESSION_TTL_SECONDS,
  };
  const payload = Buffer.from(JSON.stringify(session), "utf8").toString("base64url");
  return { token: `${payload}.${hmac(env.BREAK_GLASS_SESSION_SECRET!, payload)}`, session };
}

function readSession(env: Environment, request: FastifyRequest, binding: string): BreakGlassSession | null {
  const token = cookies(request)[sessionCookie];
  if (!token) return null;
  const [payload, signature, extra] = token.split(".");
  if (!payload || !signature || extra || !safeEqual(signature, hmac(env.BREAK_GLASS_SESSION_SECRET!, payload))) return null;
  try {
    const parsed: unknown = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    const value = parsed as Record<string, unknown>;
    if (value.v !== 1 || typeof value.sid !== "string" || typeof value.binding !== "string" || typeof value.exp !== "number") return null;
    if (value.exp <= Math.floor(Date.now() / 1000) || value.binding !== binding) return null;
    return value as BreakGlassSession;
  } catch {
    return null;
  }
}

function cookieHeader(env: Environment, token: string): string {
  const secure = process.env.NODE_ENV === "production" || env.BREAK_GLASS_REQUIRE_CLOUDFLARE_ACCESS ? "; Secure" : "";
  return `${sessionCookie}=${token}; Path=/bash; HttpOnly; SameSite=Strict; Max-Age=${env.BREAK_GLASS_SESSION_TTL_SECONDS}${secure}`;
}

function clearCookieHeader(): string {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `${sessionCookie}=; Path=/bash; HttpOnly; SameSite=Strict; Max-Age=0${secure}`;
}

function messageBuffer(value: unknown): Buffer {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof ArrayBuffer) return Buffer.from(value);
  if (Array.isArray(value) && value.every(Buffer.isBuffer)) return Buffer.concat(value);
  return Buffer.from(String(value), "utf8");
}

function containsPinnedHost(knownHosts: string, host: string): boolean {
  return knownHosts.split(/\r?\n/).some((line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) return false;
    const [hosts] = trimmed.split(/\s+/, 1);
    return hosts?.split(",").includes(host) ?? false;
  });
}

export function registerEmergencyConsoleRoutes(server: FastifyInstance, admin: AdminService, env: Environment): void {
  const attempts = new Map<string, AttemptState>();
  const accessIdentities = new WeakMap<FastifyRequest, string>();
  const socketTickets = new Map<string, SocketTicket>();
  let activeSessions = 0;
  let pendingSessions = 0;
  let accessJwks: ReturnType<typeof createRemoteJWKSet> | undefined;

  const requireCloudflareAccess = async (request: FastifyRequest): Promise<void> => {
    if (!env.BREAK_GLASS_REQUIRE_CLOUDFLARE_ACCESS) {
      accessIdentities.set(request, `ip:${clientIp(request)}`);
      return;
    }
    const assertion = request.headers["cf-access-jwt-assertion"];
    if (typeof assertion !== "string" || !assertion) throw new AppError(403, "access_required", "Cloudflare Access authentication is required.");
    const issuer = env.CLOUDFLARE_ACCESS_TEAM_DOMAIN!.replace(/\/+$/, "");
    accessJwks ??= createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`));
    try {
      const { payload } = await jwtVerify(assertion, accessJwks, { issuer, audience: env.CLOUDFLARE_ACCESS_AUD! });
      if (typeof payload.sub !== "string" || !payload.sub) throw new Error("Cloudflare Access token is missing sub.");
      accessIdentities.set(request, `cloudflare:${payload.sub}`);
    } catch {
      throw new AppError(403, "access_required", "Cloudflare Access authentication is required.");
    }
  };

  const identity = (request: FastifyRequest): string => accessIdentities.get(request) ?? `ip:${clientIp(request)}`;
  const binding = (request: FastifyRequest): string => hmac(env.BREAK_GLASS_SESSION_SECRET!, identity(request));

  const audit = async (request: FastifyRequest, event: string, metadata: Record<string, unknown> = {}): Promise<void> => {
    const unsignedRecord = {
      at: new Date().toISOString(),
      event,
      ip_hash: hmac(env.BREAK_GLASS_SESSION_SECRET!, clientIp(request)),
      identity_hash: hmac(env.BREAK_GLASS_SESSION_SECRET!, identity(request)),
      metadata,
    };
    const record = {
      ...unsignedRecord,
      record_hmac_sha256: hmacHex(env.BREAK_GLASS_SESSION_SECRET!, JSON.stringify(unsignedRecord)),
    };
    await mkdir(env.DATA_DIR, { recursive: true, mode: 0o700 });
    const auditPath = join(env.DATA_DIR, "break-glass-audit.jsonl");
    await appendFile(auditPath, `${JSON.stringify(record)}\n`, { encoding: "utf8", mode: 0o600 });
    await chmod(auditPath, 0o600);
    if (admin.enabled) {
      try {
        await admin.rest("audit_logs", {
          method: "POST",
          body: {
            actor_id: null,
            action: event,
            entity_type: "system",
            entity_id: null,
            metadata: { ...metadata, ip_hash: record.ip_hash, surface: "/bash" },
          },
          prefer: "return=minimal",
        });
      } catch (error) {
        server.log.warn({ err: error }, "Supabase break-glass audit mirror unavailable");
      }
    }
  };

  const guard = async (request: FastifyRequest): Promise<void> => {
    assertEnabled(env);
    await requireCloudflareAccess(request);
  };

  server.get("/bash", async (request, reply) => {
    await guard(request);
    return reply.type("text/html; charset=utf-8").send(breakGlassHtml());
  });

  server.get("/bash/assets/xterm.js", async (request, reply) => {
    await guard(request);
    const asset = await readFile(join(process.cwd(), "node_modules", "@xterm", "xterm", "lib", "xterm.js"));
    return reply.type("application/javascript; charset=utf-8").send(asset);
  });

  server.get("/bash/assets/xterm.css", async (request, reply) => {
    await guard(request);
    const asset = await readFile(join(process.cwd(), "node_modules", "@xterm", "xterm", "css", "xterm.css"));
    return reply.type("text/css; charset=utf-8").send(asset);
  });

  server.get("/bash/assets/recovery.js", async (request, reply) => {
    await guard(request);
    return reply.type("application/javascript; charset=utf-8").send(breakGlassJavascript());
  });

  server.get("/bash/session", async (request) => {
    await guard(request);
    const session = readSession(env, request, binding(request));
    return { authenticated: Boolean(session), expires_at: session ? new Date(session.exp * 1000).toISOString() : null };
  });

  server.post("/bash/auth", async (request, reply) => {
    await guard(request);
    const attemptKey = hmac(env.BREAK_GLASS_SESSION_SECRET!, `attempt:${identity(request)}`);
    const now = Date.now();
    for (const [key, value] of attempts) {
      if (value.expiresAt <= now) attempts.delete(key);
    }
    for (const [sid, value] of socketTickets) {
      if (value.expiresAt <= now) socketTickets.delete(sid);
    }
    const attempt = attempts.get(attemptKey);
    if (attempt && attempt.lockedUntil > now) throw new AppError(423, "recovery_locked", "Recovery access is temporarily locked.");

    const input = authInput.parse(request.body);
    const valid = safeEqual(sha256(input.key), env.BREAK_GLASS_KEY_SHA256!.toLowerCase());
    if (!valid) {
      const count = (attempt?.count ?? 0) + 1;
      const lockedUntil = count >= env.BREAK_GLASS_MAX_FAILED_ATTEMPTS ? now + env.BREAK_GLASS_LOCKOUT_SECONDS * 1000 : 0;
      attempts.set(attemptKey, { count: lockedUntil ? 0 : count, lockedUntil, expiresAt: now + env.BREAK_GLASS_LOCKOUT_SECONDS * 1000 });
      await audit(request, "break_glass.authentication_failed", { locked: Boolean(lockedUntil) });
      throw new AppError(401, "recovery_denied", "Recovery key was rejected.");
    }

    attempts.delete(attemptKey);
    const { token, session } = createSession(env, binding(request));
    const socketTicket = randomBytes(32).toString("base64url");
    await audit(request, "break_glass.authenticated", { session_id: session.sid, expires_at: new Date(session.exp * 1000).toISOString() });
    socketTickets.set(session.sid, { digest: sha256(socketTicket), expiresAt: session.exp * 1000 });
    return reply.header("Set-Cookie", cookieHeader(env, token)).send({
      socket_ticket: socketTicket,
      expires_at: new Date(session.exp * 1000).toISOString(),
    });
  });

  server.post("/bash/logout", async (request, reply) => {
    await guard(request);
    const session = readSession(env, request, binding(request));
    if (session) {
      socketTickets.delete(session.sid);
      await audit(request, "break_glass.logged_out", { session_id: session.sid });
    }
    return reply.header("Set-Cookie", clearCookieHeader()).code(204).send();
  });

  server.get("/bash/socket", {
    websocket: true,
    preValidation: async (request) => {
      await guard(request);
      if (!readSession(env, request, binding(request))) throw new AppError(401, "recovery_session_required", "Recovery session is required.");
    },
  }, (socket, request) => {
    const session = readSession(env, request, binding(request))!;
    if (pendingSessions >= 3) return socket.close(1013, "Recovery authentication busy");
    pendingSessions += 1;
    let pending = true;
    let authorizationFinished = false;
    const leavePending = () => {
      if (!pending) return;
      pending = false;
      pendingSessions = Math.max(0, pendingSessions - 1);
    };
    let authorizationTimer: NodeJS.Timeout;
    const rejectAuthorization = (reason: string) => {
      if (authorizationFinished) return;
      authorizationFinished = true;
      clearTimeout(authorizationTimer);
      leavePending();
      socket.off("message", authorize);
      void audit(request, "break_glass.socket_authorization_failed", { session_id: session.sid, reason }).finally(() => {
        socket.close(1008, reason === "ticket_timeout" ? "Recovery ticket required" : "Invalid recovery ticket");
      });
    };

    const authorize = (raw: unknown) => {
      if (authorizationFinished) return;
      let input: z.infer<typeof socketAuthInput>;
      try {
        input = socketAuthInput.parse(JSON.parse(messageBuffer(raw).toString("utf8")));
      } catch {
        rejectAuthorization("invalid_ticket_message");
        return;
      }

      const ticket = socketTickets.get(session.sid);
      if (!ticket || ticket.expiresAt <= Date.now() || !safeEqual(sha256(input.ticket), ticket.digest)) {
        rejectAuthorization("invalid_ticket");
        return;
      }
      if (activeSessions >= 1) {
        authorizationFinished = true;
        clearTimeout(authorizationTimer);
        leavePending();
        socket.off("message", authorize);
        socket.send("\r\n[relead] Ya existe una consola de recuperación activa.\r\n");
        socket.close(1013, "Recovery console busy");
        return;
      }

      socketTickets.delete(session.sid);
      authorizationFinished = true;
      clearTimeout(authorizationTimer);
      leavePending();
      socket.off("message", authorize);
      activeSessions += 1;

      void (async () => {
      const directory = await mkdtemp(join(tmpdir(), "relead-break-glass-"));
      const keyPath = join(directory, "render_identity");
      const knownHostsPath = join(directory, "known_hosts");
      const inputDigest = createHmac("sha256", env.BREAK_GLASS_SESSION_SECRET!).update(`input:${session.sid}\0`);
      const outputDigest = createHmac("sha256", env.BREAK_GLASS_SESSION_SECRET!).update(`output:${session.sid}\0`);
      let inputBytes = 0;
      let outputBytes = 0;
      let closed = false;
      let child: ChildProcessWithoutNullStreams | undefined;
      let pingTimer: NodeJS.Timeout | undefined;
      let expiryTimer: NodeJS.Timeout | undefined;

      const send = (value: string | Buffer) => {
        try { socket.send(value); } catch { /* socket is already closed */ }
      };
      const finish = async (reason: string, exitCode: number | null = null) => {
        if (closed) return;
        closed = true;
        if (pingTimer) clearInterval(pingTimer);
        if (expiryTimer) clearTimeout(expiryTimer);
        if (child && child.exitCode === null && !child.killed) child.kill("SIGTERM");
        await rm(directory, { recursive: true, force: true });
        activeSessions = Math.max(0, activeSessions - 1);
        try {
          await audit(request, "break_glass.session_closed", {
            session_id: session.sid,
            reason,
            exit_code: exitCode,
            input_bytes: inputBytes,
            output_bytes: outputBytes,
            input_hmac_sha256: inputDigest.digest("hex"),
            output_hmac_sha256: outputDigest.digest("hex"),
          });
        } catch (error) {
          server.log.error({ err: error, session_id: session.sid }, "Break-glass close audit failed");
        }
      };

      try {
        if (!containsPinnedHost(env.BREAK_GLASS_RENDER_KNOWN_HOSTS!, env.BREAK_GLASS_RENDER_SSH_HOST!)) {
          throw new AppError(503, "render_host_key_missing", "Pinned Render known_hosts does not match the configured region.");
        }
        await writeFile(keyPath, `${env.BREAK_GLASS_RENDER_PRIVATE_KEY!.trim()}\n`, { mode: 0o600 });
        await writeFile(knownHostsPath, `${env.BREAK_GLASS_RENDER_KNOWN_HOSTS!.trim()}\n`, { mode: 0o600 });
        await audit(request, "break_glass.session_opened", {
          session_id: session.sid,
          render_service_id: env.BREAK_GLASS_RENDER_SERVICE_ID,
          render_ssh_host: env.BREAK_GLASS_RENDER_SSH_HOST,
        });

        child = spawn("ssh", [
          "-tt",
          "-i", keyPath,
          "-o", "BatchMode=yes",
          "-o", "StrictHostKeyChecking=yes",
          "-o", `UserKnownHostsFile=${knownHostsPath}`,
          "-o", "IdentitiesOnly=yes",
          "-o", "PasswordAuthentication=no",
          "-o", "ConnectTimeout=15",
          "-o", "ServerAliveInterval=15",
          "-o", "ServerAliveCountMax=2",
          `${env.BREAK_GLASS_RENDER_SERVICE_ID}@${env.BREAK_GLASS_RENDER_SSH_HOST}`,
        ], {
          shell: false,
          env: { PATH: "/usr/local/bin:/usr/bin:/bin", HOME: directory, LANG: "C.UTF-8", TERM: "xterm-256color" },
          stdio: ["pipe", "pipe", "pipe"],
        });

        const forward = (chunk: Buffer) => {
          if (closed) return;
          if (outputBytes + chunk.length > env.BREAK_GLASS_MAX_SESSION_BYTES) {
            outputBytes += chunk.length;
            outputDigest.update(chunk);
            send("\r\n[relead] Límite de salida de la sesión alcanzado.\r\n");
            void finish("output_limit").finally(() => socket.close(1009, "Recovery output limit"));
            return;
          }
          outputBytes += chunk.length;
          outputDigest.update(chunk);
          send(chunk);
        };
        child.stdout.on("data", forward);
        child.stderr.on("data", forward);
        child.stdin.on("error", () => { void finish("ssh_stdin_failed").finally(() => socket.close(1011, "SSH input unavailable")); });
        child.on("error", () => {
          send("\r\n[relead] No fue posible iniciar el cliente SSH de recuperación.\r\n");
          void finish("ssh_start_failed").finally(() => socket.close(1011, "SSH unavailable"));
        });
        child.on("close", (code) => {
          send(`\r\n[relead] La sesión SSH terminó con código ${code ?? "desconocido"}.\r\n`);
          void finish("ssh_closed", code).finally(() => socket.close(1000, "SSH session closed"));
        });

        socket.on("message", (raw: unknown) => {
          const chunk = messageBuffer(raw);
          if (closed) return;
          if (inputBytes + chunk.length > env.BREAK_GLASS_MAX_SESSION_BYTES) {
            send("\r\n[relead] Límite de entrada de la sesión alcanzado.\r\n");
            void finish("input_limit").finally(() => socket.close(1009, "Recovery input limit"));
            return;
          }
          inputBytes += chunk.length;
          inputDigest.update(chunk);
          child?.stdin.write(chunk);
        });
        socket.on("close", () => { void finish("browser_closed"); });
        socket.on("error", () => { void finish("websocket_error"); });
        pingTimer = setInterval(() => {
          try { socket.ping(); } catch { /* close handler performs cleanup */ }
        }, 15_000);
        expiryTimer = setTimeout(() => {
          send("\r\n[relead] La sesión de recuperación expiró.\r\n");
          socket.close(1000, "Recovery session expired");
        }, Math.max(1, session.exp * 1000 - Date.now()));
      } catch (error) {
        server.log.error({ err: error }, "Break-glass SSH session failed");
        send("\r\n[relead] No fue posible abrir la consola de recuperación.\r\n");
        await finish("session_setup_failed");
        socket.close(1011, "Recovery setup failed");
      }
      })().catch((error) => {
        activeSessions = Math.max(0, activeSessions - 1);
        server.log.error({ err: error }, "Break-glass session initialization failed");
        try { socket.close(1011, "Recovery setup failed"); } catch { /* socket is already closed */ }
      });
    };

    authorizationTimer = setTimeout(() => rejectAuthorization("ticket_timeout"), 10_000);
    socket.on("message", authorize);
    socket.once("close", () => {
      authorizationFinished = true;
      clearTimeout(authorizationTimer);
      leavePending();
    });
  });
}

function breakGlassHtml(): string {
  return `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReLead Recovery Console</title><link rel="stylesheet" href="/bash/assets/xterm.css"><style>
:root{color-scheme:dark;font-family:Inter,system-ui,sans-serif;background:#090b10;color:#e5e7eb}*{box-sizing:border-box}body{margin:0;background:#090b10;min-height:100vh}.page{width:min(1180px,100%);margin:auto;padding:22px}.top{display:flex;align-items:center;justify-content:space-between;gap:14px;border-bottom:1px solid #2a2f3a;padding-bottom:16px}.brand{font-size:20px;font-weight:800}.brand span{color:#ef4444}.status{font:12px ui-monospace,monospace;color:#9ca3af}.panel{margin-top:18px;border:1px solid #2a2f3a;background:#11151d;padding:18px;border-radius:6px}.warning{border-left:3px solid #ef4444;padding:10px 12px;background:#2a1115;color:#fecaca;margin-bottom:16px}.login{max-width:480px;margin:10vh auto}.field{display:grid;gap:7px}.field input{padding:12px;background:#090b10;border:1px solid #3b4250;color:#f9fafb;border-radius:5px}button{border:1px solid #3b4250;background:#1b222d;color:#f9fafb;padding:9px 12px;border-radius:5px;cursor:pointer}button.primary{background:#b91c1c;border-color:#dc2626;font-weight:700}button:disabled{opacity:.5;cursor:not-allowed}.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}.terminal{height:min(68vh,720px);min-height:420px;background:#05070a;border:1px solid #242a34;padding:8px}.muted{color:#9ca3af;font-size:13px}.error{color:#fca5a5;min-height:20px}.hidden{display:none}@media(max-width:700px){.page{padding:12px}.top{align-items:flex-start;flex-direction:column}.terminal{height:66vh;min-height:340px}.toolbar{display:grid;grid-template-columns:repeat(2,1fr)}button{width:100%}}
</style></head><body><main class="page"><header class="top"><div><div class="brand">ReLead <span>Recovery</span></div><div class="muted">Consola break-glass del worker en Render</div></div><div id="status" class="status">BLOQUEADA</div></header>
<section id="login" class="panel login"><div class="warning"><b>Acceso de control interno.</b> Esta sesión opera fuera del flujo administrativo y puede modificar el contenedor del worker.</div><form id="auth-form"><div class="field"><label for="recovery-key">Clave de recuperación</label><input id="recovery-key" type="password" autocomplete="off" required minlength="20" autofocus></div><button class="primary" style="width:100%;margin-top:14px">Desbloquear consola</button><p id="auth-error" class="error"></p></form></section>
<section id="console" class="panel hidden"><div class="toolbar"><button data-send="id">Identidad</button><button data-send="pwd">Directorio</button><button data-send="ps aux --sort=-%mem | head -20">Procesos</button><button data-send="df -h">Disco</button><button data-send="free -h">Memoria</button><button data-send="node --version && cloudflared --version">Versiones</button><button id="reauthenticate">Reautenticar</button><button id="logout">Bloquear</button></div><div id="terminal" class="terminal" aria-label="Terminal interactiva del worker"></div></section></main>
<script src="/bash/assets/xterm.js"></script><script src="/bash/assets/recovery.js"></script></body></html>`;
}

function breakGlassJavascript(): string {
  return `const login=document.getElementById('login'),consolePanel=document.getElementById('console'),statusBox=document.getElementById('status'),errorBox=document.getElementById('auth-error');let socket=null,term=null,socketTicket=null;
function setStatus(value,color){statusBox.textContent=value;statusBox.style.color=color||'#9ca3af'}
function showLogin(){login.classList.remove('hidden');consolePanel.classList.add('hidden');socketTicket=null;setStatus('BLOQUEADA','#fca5a5')}
function showConsole(){login.classList.add('hidden');consolePanel.classList.remove('hidden');if(!term){term=new Terminal({cursorBlink:true,convertEol:true,fontFamily:'ui-monospace,SFMono-Regular,Menlo,monospace',fontSize:14,theme:{background:'#05070a',foreground:'#e5e7eb',cursor:'#ef4444'}});term.open(document.getElementById('terminal'));term.onData(function(data){if(socket&&socket.readyState===WebSocket.OPEN&&!socketTicket)socket.send(data)})}connect()}
function connect(){if(!socketTicket)return showLogin();if(socket)socket.close();setStatus('AUTENTICANDO','#fbbf24');term.writeln('\\r\\n[relead] conectando al worker de Render...');socket=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/bash/socket');socket.binaryType='arraybuffer';socket.onopen=function(){socket.send(JSON.stringify({type:'authorize',ticket:socketTicket}));socketTicket=null};socket.onmessage=function(event){setStatus('CONTROL INTERNO ACTIVO','#86efac');if(event.data instanceof ArrayBuffer)term.write(new Uint8Array(event.data));else term.write(String(event.data))};socket.onclose=function(event){setStatus('SESIÓN CERRADA','#fca5a5');term.writeln('\\r\\n[relead] conexión cerrada ('+event.code+').')};socket.onerror=function(){setStatus('ERROR DE CONEXIÓN','#fca5a5')}}
document.getElementById('auth-form').onsubmit=async function(event){event.preventDefault();errorBox.textContent='';const key=document.getElementById('recovery-key');try{const response=await fetch('/bash/auth',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:key.value})});key.value='';const body=await response.json().catch(function(){return{}});if(!response.ok)throw new Error(body.message||'Acceso rechazado.');if(!body.socket_ticket)throw new Error('No se recibió el ticket de recuperación.');socketTicket=body.socket_ticket;showConsole()}catch(error){errorBox.textContent=error.message}};
document.querySelectorAll('[data-send]').forEach(function(button){button.onclick=function(){if(socket&&socket.readyState===WebSocket.OPEN&&!socketTicket)socket.send(button.dataset.send+'\\r')}});document.getElementById('reauthenticate').onclick=async function(){if(socket)socket.close();await fetch('/bash/logout',{method:'POST'});showLogin()};document.getElementById('logout').onclick=async function(){if(socket)socket.close();await fetch('/bash/logout',{method:'POST'});showLogin()};showLogin();`;
}
