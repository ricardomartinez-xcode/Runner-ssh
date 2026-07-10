import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { AppError, forbidden } from "./errors.js";

type AdminRole = "admin" | "operator" | "viewer";
type JsonRecord = Record<string, unknown>;

type AdminPrincipal = {
  id: string;
  email: string;
  role: AdminRole;
  token: string;
};

const targetInput = z.object({
  name: z.string().min(1).max(120),
  type: z.enum(["ssh", "codespace", "tailscale", "cloudflare_tunnel", "local"]),
  host: z.string().min(1).max(255),
  port: z.coerce.number().int().min(1).max(65535).default(22),
  username: z.string().min(1).max(120),
  auth_type: z.enum(["private_key", "password", "agent", "token"]).default("private_key"),
  secret_ref: z.string().max(500).nullable().optional(),
  tags: z.array(z.string().min(1).max(50)).max(20).default([]),
  working_directory: z.string().max(500).nullable().optional(),
  enabled: z.boolean().default(true),
});

const commandInput = z.object({
  name: z.string().min(1).max(120),
  description: z.string().max(500).nullable().optional(),
  command_template: z.string().min(1).max(2000),
  risk_level: z.enum(["low", "medium", "high"]).default("low"),
  requires_approval: z.boolean().default(false),
  allowed_roles: z.array(z.enum(["admin", "operator", "viewer"])).min(1).default(["admin", "operator"]),
  enabled: z.boolean().default(true),
});

function isRecord(value: unknown): value is JsonRecord {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function bearer(request: FastifyRequest): string {
  const header = request.headers.authorization;
  if (!header?.startsWith("Bearer ")) throw new AppError(401, "unauthorized", "Supabase session required.");
  const token = header.slice(7).trim();
  if (!token) throw new AppError(401, "unauthorized", "Supabase session required.");
  return token;
}

function idParam(request: FastifyRequest): string {
  const value = (request.params as { id?: string }).id;
  if (!value) throw new AppError(400, "bad_request", "Missing id.");
  return value;
}

function requireRole(principal: AdminPrincipal, roles: AdminRole[]): void {
  if (!roles.includes(principal.role)) throw forbidden("Insufficient ReLead Ops permissions.");
}

export class AdminService {
  readonly enabled: boolean;
  private readonly url: string;
  private readonly publishableKey: string;
  private readonly secretKey: string;

  constructor(source: NodeJS.ProcessEnv = process.env) {
    this.url = (source.SUPABASE_URL ?? "").replace(/\/+$/, "");
    this.publishableKey = source.SUPABASE_PUBLISHABLE_KEY ?? source.SUPABASE_ANON_KEY ?? "";
    this.secretKey = source.SUPABASE_SECRET_KEY ?? source.SUPABASE_SERVICE_ROLE_KEY ?? "";
    this.enabled = Boolean(this.url && this.publishableKey && this.secretKey);
  }

  publicConfig() {
    return { enabled: this.enabled, supabaseUrl: this.url, publishableKey: this.publishableKey };
  }

  async principal(request: FastifyRequest): Promise<AdminPrincipal> {
    if (!this.enabled) throw new AppError(503, "admin_unavailable", "Supabase admin integration is not configured.");
    const token = bearer(request);
    const userResponse = await fetch(`${this.url}/auth/v1/user`, {
      headers: { apikey: this.publishableKey, Authorization: `Bearer ${token}` },
    });
    if (!userResponse.ok) throw new AppError(401, "unauthorized", "Invalid or expired Supabase session.");
    const user: unknown = await userResponse.json();
    if (!isRecord(user) || typeof user.id !== "string") throw new AppError(401, "unauthorized", "Invalid Supabase user.");

    const profiles = await this.rest("profiles", {
      query: `id=eq.${encodeURIComponent(user.id)}&select=id,email,role&limit=1`,
    });
    const profile = Array.isArray(profiles) && isRecord(profiles[0]) ? profiles[0] : undefined;
    if (!profile) throw new AppError(403, "profile_missing", "ReLead Ops profile not found.");
    const role = profile.role;
    if (role !== "admin" && role !== "operator" && role !== "viewer") throw forbidden("Invalid ReLead Ops role.");

    return {
      id: user.id,
      email: typeof profile.email === "string" ? profile.email : typeof user.email === "string" ? user.email : "",
      role,
      token,
    };
  }

  async rest(table: string, options: { method?: string; query?: string; body?: unknown; prefer?: string } = {}): Promise<unknown> {
    const response = await fetch(`${this.url}/rest/v1/${table}${options.query ? `?${options.query}` : ""}`, {
      method: options.method ?? "GET",
      headers: {
        apikey: this.secretKey,
        Authorization: `Bearer ${this.secretKey}`,
        "Content-Type": "application/json",
        Prefer: options.prefer ?? "return=representation",
      },
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
    if (!response.ok) {
      const message = await response.text();
      throw new AppError(response.status, "supabase_error", message || "Supabase request failed.");
    }
    if (response.status === 204) return null;
    const text = await response.text();
    return text ? JSON.parse(text) : null;
  }

  async rpc(functionName: string, body: Record<string, unknown> = {}): Promise<unknown> {
    const response = await fetch(`${this.url}/rest/v1/rpc/${functionName}`, {
      method: "POST",
      headers: {
        apikey: this.secretKey,
        Authorization: `Bearer ${this.secretKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      const message = await response.text();
      throw new AppError(response.status, "supabase_error", message || "Supabase RPC request failed.");
    }
    const text = await response.text();
    return text ? JSON.parse(text) : null;
  }
}

export function registerAdminRoutes(server: FastifyInstance, admin: AdminService): void {
  server.get("/admin", async (_request, reply) => reply.type("text/html; charset=utf-8").send(adminHtml()));
  server.get("/admin/config", async () => admin.publicConfig());

  server.get("/admin/api/me", async (request) => {
    const principal = await admin.principal(request);
    return { user: { id: principal.id, email: principal.email, role: principal.role } };
  });

  server.get("/admin/api/dashboard", async (request) => {
    await admin.principal(request);
    const [targets, executions, health] = await Promise.all([
      admin.rest("targets", { query: "select=id,name,type,enabled,created_at&order=created_at.desc" }),
      admin.rest("executions", { query: "select=id,status,created_at,target_id,command_id&order=created_at.desc&limit=10" }),
      admin.rest("health_checks", { query: "select=target_id,status,latency_ms,checked_at&order=checked_at.desc&limit=100" }),
    ]);
    const targetRows = Array.isArray(targets) ? targets : [];
    const healthRows = Array.isArray(health) ? health : [];
    const latestByTarget = new Map<string, JsonRecord>();
    for (const row of healthRows) {
      if (isRecord(row) && typeof row.target_id === "string" && !latestByTarget.has(row.target_id)) latestByTarget.set(row.target_id, row);
    }
    return {
      summary: {
        targets: targetRows.length,
        enabled: targetRows.filter((row) => isRecord(row) && row.enabled === true).length,
        online: [...latestByTarget.values()].filter((row) => row.status === "online").length,
        offline: [...latestByTarget.values()].filter((row) => row.status === "offline").length,
      },
      targets,
      executions,
      health: [...latestByTarget.values()],
    };
  });

  server.get("/admin/api/targets", async (request) => {
    await admin.principal(request);
    return { targets: await admin.rest("targets", { query: "select=*&order=created_at.desc" }) };
  });
  server.post("/admin/api/targets", async (request, reply) => {
    const principal = await admin.principal(request);
    requireRole(principal, ["admin"]);
    const body = targetInput.parse(request.body);
    const target = await admin.rest("targets", { method: "POST", body: { ...body, created_by: principal.id } });
    return reply.code(201).send({ target });
  });
  server.patch("/admin/api/targets/:id", async (request) => {
    const principal = await admin.principal(request);
    requireRole(principal, ["admin"]);
    const body = targetInput.partial().parse(request.body);
    return { target: await admin.rest("targets", { method: "PATCH", query: `id=eq.${encodeURIComponent(idParam(request))}`, body }) };
  });
  server.delete("/admin/api/targets/:id", async (request, reply) => {
    const principal = await admin.principal(request);
    requireRole(principal, ["admin"]);
    await admin.rest("targets", { method: "DELETE", query: `id=eq.${encodeURIComponent(idParam(request))}`, prefer: "return=minimal" });
    return reply.code(204).send();
  });

  server.get("/admin/api/commands", async (request) => {
    await admin.principal(request);
    return { commands: await admin.rest("commands", { query: "select=*&order=created_at.desc" }) };
  });
  server.post("/admin/api/commands", async (request, reply) => {
    const principal = await admin.principal(request);
    requireRole(principal, ["admin"]);
    const body = commandInput.parse(request.body);
    const command = await admin.rest("commands", { method: "POST", body: { ...body, created_by: principal.id } });
    return reply.code(201).send({ command });
  });
  server.patch("/admin/api/commands/:id", async (request) => {
    const principal = await admin.principal(request);
    requireRole(principal, ["admin"]);
    const body = commandInput.partial().parse(request.body);
    return { command: await admin.rest("commands", { method: "PATCH", query: `id=eq.${encodeURIComponent(idParam(request))}`, body }) };
  });
  server.delete("/admin/api/commands/:id", async (request, reply) => {
    const principal = await admin.principal(request);
    requireRole(principal, ["admin"]);
    await admin.rest("commands", { method: "DELETE", query: `id=eq.${encodeURIComponent(idParam(request))}`, prefer: "return=minimal" });
    return reply.code(204).send();
  });

  server.get("/admin/api/executions", async (request) => {
    await admin.principal(request);
    return { executions: await admin.rest("executions", { query: "select=*&order=created_at.desc&limit=100" }) };
  });
  server.get("/admin/api/health", async (request) => {
    await admin.principal(request);
    return { health: await admin.rest("health_checks", { query: "select=*&order=checked_at.desc&limit=200" }) };
  });

  server.get("/admin/api/users", async (request) => {
    const principal = await admin.principal(request);
    requireRole(principal, ["admin"]);
    return {
      users: await admin.rest("profiles", { query: "select=id,email,full_name,role,created_at,updated_at&order=email.asc" }),
      target_permissions: await admin.rest("target_permissions", { query: "select=*&limit=500" }),
      command_permissions: await admin.rest("command_permissions", { query: "select=*&limit=500" }),
    };
  });
}

function adminHtml(): string {
  return `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReLead Ops</title><style>
:root{color-scheme:dark;font-family:Inter,system-ui,sans-serif;background:#020617;color:#e5e7eb}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top right,#0c4a6e55,transparent 35%),#020617}.shell{max-width:1180px;margin:auto;padding:32px}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:28px}.brand{font-size:24px;font-weight:800}.brand span{color:#22d3ee}.muted{color:#94a3b8}.card{background:#0f172ad9;border:1px solid #1e293b;border-radius:16px;padding:20px;box-shadow:0 18px 50px #0005}.login{max-width:420px;margin:12vh auto}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.metric b{display:block;font-size:30px;margin-top:8px}.cols{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:18px}input,button{width:100%;padding:12px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;margin-top:10px}button{background:#0891b2;border:0;font-weight:700;cursor:pointer}.row{display:flex;justify-content:space-between;gap:12px;padding:12px 0;border-bottom:1px solid #1e293b}.pill{padding:3px 9px;border-radius:999px;background:#1e293b;font-size:12px}.ok{color:#22c55e}.bad{color:#ef4444}@media(max-width:800px){.grid,.cols{grid-template-columns:1fr}.shell{padding:18px}}
</style></head><body><main class="shell"><div id="app"></div></main><script>
const state={token:localStorage.getItem('relead_ops_token')||'',cfg:null};
const app=document.getElementById('app');
async function api(path,options={}){const r=await fetch(path,{...options,headers:{'Content-Type':'application/json',Authorization:'Bearer '+state.token,...options.headers}});if(r.status===204)return null;const j=await r.json();if(!r.ok)throw new Error(j.message||j.error||'Error');return j}
function login(){app.innerHTML='<section class="card login"><div class="brand">ReLead <span>Ops</span></div><p class="muted">Centro seguro de operaciones de infraestructura.</p><form id="f"><input id="email" type="email" placeholder="Correo" required><input id="pass" type="password" placeholder="Contraseña" required><button>Iniciar sesión</button><p id="err" class="bad"></p></form></section>';document.getElementById('f').onsubmit=async e=>{e.preventDefault();try{const r=await fetch(state.cfg.supabaseUrl+'/auth/v1/token?grant_type=password',{method:'POST',headers:{apikey:state.cfg.publishableKey,'Content-Type':'application/json'},body:JSON.stringify({email:email.value,password:pass.value})});const j=await r.json();if(!r.ok)throw new Error(j.error_description||j.msg||'No fue posible iniciar sesión');state.token=j.access_token;localStorage.setItem('relead_ops_token',state.token);dashboard()}catch(x){err.textContent=x.message}}}
async function dashboard(){try{const [me,d]=await Promise.all([api('/admin/api/me'),api('/admin/api/dashboard')]);const s=d.summary;app.innerHTML='<div class="top"><div><div class="brand">ReLead <span>Ops</span></div><div class="muted">'+me.user.email+' · '+me.user.role+'</div></div><button id="out" style="width:auto">Cerrar sesión</button></div><section class="grid">'+[['Targets',s.targets],['Activos',s.enabled],['Online',s.online],['Offline',s.offline]].map(x=>'<div class="card metric"><span class="muted">'+x[0]+'</span><b>'+x[1]+'</b></div>').join('')+'</section><section class="cols"><div class="card"><h2>Targets</h2>'+((d.targets||[]).map(t=>'<div class="row"><div><b>'+esc(t.name)+'</b><div class="muted">'+esc(t.type)+'</div></div><span class="pill">'+(t.enabled?'activo':'inactivo')+'</span></div>').join('')||'<p class="muted">Sin targets todavía.</p>')+'</div><div class="card"><h2>Últimas ejecuciones</h2>'+((d.executions||[]).map(x=>'<div class="row"><span>'+esc(x.status)+'</span><span class="muted">'+new Date(x.created_at).toLocaleString()+'</span></div>').join('')||'<p class="muted">Sin ejecuciones todavía.</p>')+'</div></section>';document.getElementById('out').onclick=()=>{localStorage.removeItem('relead_ops_token');state.token='';login()}}catch(e){localStorage.removeItem('relead_ops_token');state.token='';login()}}
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
fetch('/admin/config').then(r=>r.json()).then(c=>{state.cfg=c;if(!c.enabled){app.innerHTML='<section class="card login"><h1>ReLead Ops</h1><p class="bad">Supabase no está configurado en Render.</p></section>';return}state.token?dashboard():login()});
</script></body></html>`;
}
