import { spawn } from "node:child_process";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import type { AdminService } from "./admin.js";
import { AppError, forbidden } from "./errors.js";
import { deleteManagedCredential, managedCredentialsEnabled, storeManagedCredential } from "./target-secrets.js";

type JsonRecord = Record<string, unknown>;

const targetInput = z.object({
  name: z.string().min(1).max(120),
  type: z.enum(["ssh", "codespace", "tailscale", "cloudflare_tunnel", "local"]),
  host: z.string().min(1).max(255),
  port: z.coerce.number().int().min(1).max(65535).default(22),
  username: z.string().min(1).max(120),
  auth_type: z.enum(["private_key", "password", "agent", "token"]).default("private_key"),
  credential_source: z.enum(["managed", "environment", "agent", "reference"]).default("managed"),
  credential: z.string().max(50_000).optional(),
  environment_variable: z.string().max(120).optional(),
  secret_reference: z.string().max(500).optional(),
  tags: z.array(z.string().min(1).max(50)).max(20).default([]),
  working_directory: z.string().max(500).nullable().optional(),
  known_hosts: z.string().max(10_000).nullable().optional(),
  enabled: z.boolean().default(true),
});

const scanInput = z.object({
  host: z.string().min(1).max(255).regex(/^[A-Za-z0-9._:[\]-]+$/, "Invalid host."),
  port: z.coerce.number().int().min(1).max(65535).default(22),
});

function isRecord(value: unknown): value is JsonRecord {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function first(value: unknown, label: string): JsonRecord {
  if (!Array.isArray(value) || !isRecord(value[0])) throw new AppError(404, "not_found", `${label} not found.`);
  return value[0];
}

function idParam(request: FastifyRequest): string {
  const value = (request.params as { id?: string }).id;
  if (!value) throw new AppError(400, "bad_request", "Missing target id.");
  return value;
}

function requireAdmin(role: string): void {
  if (role !== "admin") throw forbidden("Only administrators can manage targets and credentials.");
}

function environmentReference(name: string | undefined): string {
  const normalized = name?.trim() ?? "";
  if (!/^[A-Z_][A-Z0-9_]*$/.test(normalized)) {
    throw new AppError(400, "invalid_environment_variable", "Use a valid Render variable name, for example SSH_PASSWORD_SERVER_MAIN.");
  }
  return `RENDER_ENV:${normalized}`;
}

function advancedReference(value: string | undefined): string {
  const normalized = value?.trim() ?? "";
  if (!/^(ENV:|RENDER_ENV:|1PASSWORD:)/.test(normalized)) {
    throw new AppError(400, "invalid_secret_ref", "The advanced reference must start with ENV:, RENDER_ENV:, or 1PASSWORD:.");
  }
  return normalized;
}

function validateCredential(authType: string, credential: string): void {
  if (!credential.trim()) throw new AppError(400, "credential_required", "Enter the password or private key.");
  if (authType === "private_key" && !credential.includes("PRIVATE KEY")) {
    throw new AppError(400, "invalid_private_key", "The pasted value does not look like an SSH private key.");
  }
}

async function audit(admin: AdminService, actorId: string, action: string, targetId: string, metadata: JsonRecord = {}): Promise<void> {
  await admin.rest("audit_logs", {
    method: "POST",
    body: { actor_id: actorId, action, entity_type: "target", entity_id: targetId, metadata },
    prefer: "return=minimal",
  });
}

function targetRecord(input: z.infer<typeof targetInput>, secretRef: string | null): JsonRecord {
  return {
    name: input.name,
    type: input.type,
    host: input.host,
    port: input.port,
    username: input.username,
    auth_type: input.credential_source === "agent" ? "agent" : input.auth_type,
    secret_ref: input.credential_source === "agent" ? null : secretRef,
    tags: input.tags,
    working_directory: input.working_directory ?? null,
    known_hosts: input.known_hosts ?? null,
    enabled: input.enabled,
  };
}

async function scanHostKey(host: string, port: number): Promise<string> {
  if (host.startsWith("-")) throw new AppError(400, "invalid_host", "Invalid host.");
  return await new Promise((resolve, reject) => {
    const child = spawn("ssh-keyscan", ["-T", "7", "-p", String(port), host], { shell: false, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => { stdout = (stdout + chunk.toString("utf8")).slice(-20_000); });
    child.stderr.on("data", (chunk: Buffer) => { stderr = (stderr + chunk.toString("utf8")).slice(-4_000); });
    child.on("error", () => reject(new AppError(500, "ssh_keyscan_unavailable", "ssh-keyscan is unavailable in the runner image.")));
    child.on("close", (code) => {
      const keys = stdout.split("\n").filter((line) => line.trim() && !line.startsWith("#")).join("\n").trim();
      if (code !== 0 || !keys) reject(new AppError(502, "host_key_scan_failed", stderr.trim() || "No SSH host key was returned."));
      else resolve(keys);
    });
  });
}

export function registerImprovedTargetRoutes(server: FastifyInstance, admin: AdminService): void {
  server.get("/admin/manage-v2", async (_request, reply) => reply.type("text/html; charset=utf-8").send(targetManagerHtml()));

  server.get("/admin/api/v2/config", async (request) => {
    await admin.principal(request);
    return { managed_credentials_enabled: managedCredentialsEnabled() };
  });

  server.get("/admin/api/v2/targets", async (request) => {
    await admin.principal(request);
    return { targets: await admin.rest("targets", { query: "select=*&order=created_at.desc" }) };
  });

  server.post("/admin/api/v2/scan-host-key", async (request) => {
    const principal = await admin.principal(request);
    requireAdmin(principal.role);
    const input = scanInput.parse(request.body);
    return {
      known_hosts: await scanHostKey(input.host, input.port),
      warning: "Compare the fingerprint with a trusted source before saving the target.",
    };
  });

  server.post("/admin/api/v2/targets", async (request, reply) => {
    const principal = await admin.principal(request);
    requireAdmin(principal.role);
    const input = targetInput.parse(request.body);

    let initialRef: string | null = null;
    if (input.credential_source === "environment") initialRef = environmentReference(input.environment_variable);
    if (input.credential_source === "reference") initialRef = advancedReference(input.secret_reference);
    if (input.credential_source === "managed") validateCredential(input.auth_type, input.credential ?? "");

    const created = await admin.rest("targets", {
      method: "POST",
      body: { ...targetRecord(input, initialRef), created_by: principal.id },
    });
    const row = first(created, "Target");
    const targetId = String(row.id);

    try {
      if (input.credential_source === "managed") {
        const managedRef = await storeManagedCredential(admin, targetId, input.credential ?? "", principal.id);
        await admin.rest("targets", {
          method: "PATCH",
          query: `id=eq.${encodeURIComponent(targetId)}`,
          body: { secret_ref: managedRef },
          prefer: "return=minimal",
        });
        row.secret_ref = managedRef;
      }
      await audit(admin, principal.id, "target.created", targetId, {
        name: input.name,
        type: input.type,
        credential_source: input.credential_source,
      });
      return reply.code(201).send({ target: row });
    } catch (error) {
      await admin.rest("targets", { method: "DELETE", query: `id=eq.${encodeURIComponent(targetId)}`, prefer: "return=minimal" });
      throw error;
    }
  });

  server.patch("/admin/api/v2/targets/:id", async (request) => {
    const principal = await admin.principal(request);
    requireAdmin(principal.role);
    const targetId = idParam(request);
    const input = targetInput.parse(request.body);
    const current = first(await admin.rest("targets", {
      query: `id=eq.${encodeURIComponent(targetId)}&select=*&limit=1`,
    }), "Target");
    const previousRef = typeof current.secret_ref === "string" ? current.secret_ref : null;

    let nextRef: string | null = previousRef;
    if (input.credential_source === "managed") {
      if (input.credential?.trim()) {
        validateCredential(input.auth_type, input.credential);
        nextRef = await storeManagedCredential(admin, targetId, input.credential, principal.id);
      } else if (!previousRef?.startsWith("MANAGED:")) {
        throw new AppError(400, "credential_required", "Enter a credential when switching this target to managed storage.");
      }
    } else if (input.credential_source === "environment") {
      nextRef = environmentReference(input.environment_variable);
    } else if (input.credential_source === "reference") {
      nextRef = advancedReference(input.secret_reference);
    } else {
      nextRef = null;
    }

    await admin.rest("targets", {
      method: "PATCH",
      query: `id=eq.${encodeURIComponent(targetId)}`,
      body: targetRecord(input, nextRef),
      prefer: "return=minimal",
    });

    if (previousRef?.startsWith("MANAGED:") && !nextRef?.startsWith("MANAGED:")) {
      await deleteManagedCredential(admin, targetId);
    }
    await audit(admin, principal.id, "target.updated", targetId, {
      credential_source: input.credential_source,
      credential_replaced: Boolean(input.credential?.trim()),
    });
    return { ok: true };
  });

  server.delete("/admin/api/v2/targets/:id", async (request, reply) => {
    const principal = await admin.principal(request);
    requireAdmin(principal.role);
    const targetId = idParam(request);
    await admin.rest("targets", { method: "DELETE", query: `id=eq.${encodeURIComponent(targetId)}`, prefer: "return=minimal" });
    await audit(admin, principal.id, "target.deleted", targetId);
    return reply.code(204).send();
  });
}

function targetManagerHtml(): string {
  return `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReLead Ops · Targets</title><style>
:root{color-scheme:dark;font-family:Inter,system-ui,sans-serif;background:#020617;color:#e5e7eb}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at top right,#0c4a6e55,transparent 34%),#020617}button,input,select,textarea{font:inherit}.shell{max-width:1280px;margin:auto;padding:28px}.top,.toolbar,.item-head,.actions{display:flex;gap:12px;align-items:center}.top,.toolbar,.item-head{justify-content:space-between}.brand{font-size:26px;font-weight:850}.brand span{color:#22d3ee}.muted{color:#94a3b8}.small{font-size:13px}.nav{display:flex;gap:8px;flex-wrap:wrap;margin:20px 0}.btn{padding:10px 14px;border-radius:10px;border:1px solid #334155;background:#0f172a;color:#e5e7eb;cursor:pointer;text-decoration:none}.btn.primary{background:#0891b2;border-color:#0891b2;font-weight:750}.btn.danger{background:#7f1d1d;border-color:#991b1b}.btn:disabled{opacity:.45;cursor:not-allowed}.card{background:#0f172ae8;border:1px solid #1e293b;border-radius:16px;padding:19px;box-shadow:0 18px 50px #0004}.login{max-width:430px;margin:12vh auto}.login input,.login button{width:100%;padding:12px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;margin-top:10px}.login button{background:#0891b2;border:0;font-weight:750}.list{display:grid;gap:12px}.item{padding:16px;border:1px solid #263449;border-radius:13px;background:#091225}.actions{flex-wrap:wrap;margin-top:14px}.pill{display:inline-block;padding:4px 9px;border-radius:999px;background:#1e293b;font-size:12px}.pill.ok{color:#86efac;background:#14532d66}.notice{padding:12px;border-radius:10px;background:#0c4a6e55;border:1px solid #0e7490;margin:12px 0}.warning{background:#78350f55;border-color:#b45309}.error{color:#fca5a5}.grid{display:grid;grid-template-columns:1fr 1fr;gap:13px}.field{display:grid;gap:6px}.field.full{grid-column:1/-1}.field label{font-size:13px;color:#cbd5e1}.field input,.field select,.field textarea{width:100%;padding:11px;border-radius:9px;border:1px solid #334155;background:#020617;color:#e5e7eb}.field textarea{min-height:110px;resize:vertical}.check{display:flex;gap:8px;align-items:center}.check input{width:auto}.catalog-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.category{margin:24px 0 10px;color:#67e8f9}.code{font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;background:#020617;padding:9px;border-radius:8px;margin-top:9px;word-break:break-word}dialog{width:min(820px,calc(100% - 24px));border:1px solid #334155;border-radius:16px;background:#0f172a;color:#e5e7eb;padding:0;box-shadow:0 24px 90px #000c}dialog::backdrop{background:#000a}.modal-head,.modal-body,.modal-foot{padding:18px}.modal-head{display:flex;justify-content:space-between;border-bottom:1px solid #263449}.modal-foot{display:flex;justify-content:flex-end;gap:8px;border-top:1px solid #263449}@media(max-width:800px){.grid,.catalog-grid{grid-template-columns:1fr}.field.full{grid-column:auto}.shell{padding:16px}.top,.toolbar,.item-head{align-items:flex-start;flex-direction:column}}
</style></head><body><main class="shell"><div id="app"></div></main><dialog id="modal"></dialog><script>
const state={token:localStorage.getItem('relead_ops_token')||'',cfg:null,me:null,settings:null,targets:[],commands:[],catalog:[],view:'targets'};const app=document.getElementById('app');const modal=document.getElementById('modal');
function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
async function api(path,options){options=options||{};const headers=Object.assign({'Content-Type':'application/json',Authorization:'Bearer '+state.token},options.headers||{});const r=await fetch(path,Object.assign({},options,{headers:headers}));if(r.status===204)return null;const text=await r.text();let data={};try{data=text?JSON.parse(text):{}}catch(e){data={message:text}}if(!r.ok)throw new Error(data.message||data.error||'Error');return data}
function login(){app.innerHTML='<section class="card login"><div class="brand">ReLead <span>Ops</span></div><p class="muted">Administración segura de targets.</p><form id="login"><input id="email" type="email" placeholder="Correo" required><input id="password" type="password" placeholder="Contraseña" required><button>Iniciar sesión</button><p id="login-error" class="error"></p></form></section>';document.getElementById('login').onsubmit=async function(e){e.preventDefault();try{const r=await fetch(state.cfg.supabaseUrl+'/auth/v1/token?grant_type=password',{method:'POST',headers:{apikey:state.cfg.publishableKey,'Content-Type':'application/json'},body:JSON.stringify({email:document.getElementById('email').value,password:document.getElementById('password').value})});const j=await r.json();if(!r.ok)throw new Error(j.error_description||j.msg||'No fue posible iniciar sesión');state.token=j.access_token;localStorage.setItem('relead_ops_token',state.token);await boot()}catch(x){document.getElementById('login-error').textContent=x.message}}}
function shell(content){app.innerHTML='<div class="top"><div><div class="brand">ReLead <span>Ops</span></div><div class="muted">'+esc(state.me.email)+' · '+esc(state.me.role)+'</div></div><button id="logout" class="btn primary">Cerrar sesión</button></div><nav class="nav"><button class="btn '+(state.view==='targets'?'primary':'')+'" data-view="targets">Targets y credenciales</button><button class="btn '+(state.view==='catalog'?'primary':'')+'" data-view="catalog">Catálogo recomendado</button><a class="btn" href="/admin/manage">Operaciones, asignaciones y logs</a></nav>'+content;document.querySelectorAll('[data-view]').forEach(function(b){b.onclick=function(){state.view=b.dataset.view;render()}});document.getElementById('logout').onclick=function(){localStorage.removeItem('relead_ops_token');state.token='';login()}}
async function boot(){try{state.me=(await api('/admin/api/me')).user;state.settings=await api('/admin/api/v2/config');await render()}catch(e){localStorage.removeItem('relead_ops_token');state.token='';login()}}
async function render(){shell('<div class="card">Cargando…</div>');try{if(state.view==='catalog')await renderCatalog();else await renderTargets()}catch(e){shell('<div class="card error">'+esc(e.message)+'</div>')}}
function sourceOf(t){if(t.auth_type==='agent')return'agent';if((t.secret_ref||'').startsWith('MANAGED:'))return'managed';if((t.secret_ref||'').startsWith('RENDER_ENV:')||(t.secret_ref||'').startsWith('ENV:'))return'environment';return'reference'}
async function renderTargets(){const data=await api('/admin/api/v2/targets');state.targets=data.targets||[];const cards=state.targets.map(function(t){return '<article class="item"><div class="item-head"><div><h3 style="margin:0">'+esc(t.name)+'</h3><div class="muted small">'+esc(t.username)+'@'+esc(t.host)+':'+esc(t.port)+' · '+esc(t.type)+'</div><div style="margin-top:8px"><span class="pill">'+esc(t.auth_type)+'</span> <span class="pill">'+esc(sourceOf(t))+'</span></div></div><span class="pill ok">'+(t.enabled?'activo':'inactivo')+'</span></div><div class="actions"><button class="btn" data-edit="'+esc(t.id)+'">Editar</button><a class="btn primary" href="/admin/manage">Asignar comandos / ejecutar</a><button class="btn danger" data-delete="'+esc(t.id)+'">Eliminar</button></div></article>'}).join('');const warning=state.settings.managed_credentials_enabled?'':'<div class="notice warning"><b>Credenciales cifradas desactivadas.</b> Agrega <code>SSH_KEY_ENCRYPTION_SECRET</code> en Render con al menos 32 caracteres aleatorios. Mientras tanto puedes usar una variable de Render.</div>';shell('<section class="card"><div class="toolbar"><div><h2 style="margin:0 0 4px">Targets</h2><div class="muted">Agrega contraseñas, llaves privadas o referencias de Render sin usar 1Password.</div></div><button id="add" class="btn primary">Agregar target</button></div>'+warning+'<div class="list">'+(cards||'<div class="notice">No hay targets. Pulsa <b>Agregar target</b>.</div>')+'</div></section>');document.getElementById('add').onclick=function(){openTarget()};document.querySelectorAll('[data-edit]').forEach(function(b){b.onclick=function(){openTarget(state.targets.find(function(t){return t.id===b.dataset.edit}))}});document.querySelectorAll('[data-delete]').forEach(function(b){b.onclick=async function(){const t=state.targets.find(function(x){return x.id===b.dataset.delete});if(!confirm('¿Eliminar '+t.name+'?'))return;await api('/admin/api/v2/targets/'+t.id,{method:'DELETE'});await renderTargets()}})}
function targetForm(t){t=t||{};const src=sourceOf(t);const env=(t.secret_ref||'').replace(/^RENDER_ENV:|^ENV:/,'');return '<form id="target-form" class="grid"><div class="field"><label>Nombre</label><input name="name" required value="'+esc(t.name||'')+'" placeholder="Servidor principal"></div><div class="field"><label>Tipo</label><select name="type"><option>ssh</option><option>tailscale</option><option>cloudflare_tunnel</option><option>codespace</option><option>local</option></select></div><div class="field"><label>Host o IP</label><input name="host" required value="'+esc(t.host||'')+'" placeholder="server.example.com"></div><div class="field"><label>Puerto</label><input name="port" type="number" min="1" max="65535" value="'+esc(t.port||22)+'"></div><div class="field"><label>Usuario SSH</label><input name="username" required value="'+esc(t.username||'')+'" placeholder="ubuntu"></div><div class="field"><label>Método SSH</label><select name="auth_type"><option value="private_key">Llave privada</option><option value="password">Contraseña</option><option value="agent">SSH Agent</option><option value="token">Token</option></select></div><div class="field full"><label>Dónde guardar la credencial</label><select name="credential_source"><option value="managed">Guardar cifrada en ReLead Ops</option><option value="environment">Usar variable de Render</option><option value="agent">Usar SSH Agent</option><option value="reference">Referencia avanzada</option></select></div><div id="credential-fields" class="field full"></div><div class="field full"><label>Directorio de trabajo</label><input name="working_directory" value="'+esc(t.working_directory||'')+'" placeholder="/opt/app"></div><div class="field full"><label>Clave pública del host (known_hosts)</label><textarea name="known_hosts" placeholder="server.example.com ssh-ed25519 AAAAC3...">'+esc(t.known_hosts||'')+'</textarea><div class="actions"><button type="button" class="btn" id="scan-key">Detectar clave del host</button></div><div class="muted small">Verifica la huella con una fuente confiable antes de guardar.</div></div><div class="field full"><label>Etiquetas separadas por coma</label><input name="tags" value="'+esc((t.tags||[]).join(', '))+'" placeholder="prod, docker"></div><label class="check field full"><input name="enabled" type="checkbox" '+(t.enabled===false?'':'checked')+'> Target activo</label><p id="form-error" class="error field full"></p></form><input type="hidden" id="initial-source" value="'+esc(src)+'"><input type="hidden" id="initial-env" value="'+esc(env)+'">'}
function renderCredentialFields(editing){const f=document.getElementById('target-form');const source=f.elements.credential_source.value;const auth=f.elements.auth_type.value;const box=document.getElementById('credential-fields');if(auth==='agent'){f.elements.credential_source.value='agent'}if(source==='managed'){const disabled=!state.settings.managed_credentials_enabled?' disabled':'';box.innerHTML='<label>'+(auth==='password'?'Contraseña SSH':'Llave privada SSH')+'</label>'+(auth==='password'?'<input name="credential" type="password" autocomplete="new-password" placeholder="'+(editing?'Deja vacío para conservarla':'Escribe la contraseña')+'"'+disabled+'>':'<textarea name="credential" placeholder="'+(editing?'Deja vacío para conservar la llave':'Pega aquí la llave privada completa')+'"'+disabled+'></textarea>')+(!state.settings.managed_credentials_enabled?'<div class="error small">Configura SSH_KEY_ENCRYPTION_SECRET en Render para activar esta opción.</div>':'<div class="muted small">La credencial se cifra antes de almacenarse y nunca vuelve al navegador.</div>')}else if(source==='environment'){box.innerHTML='<label>Nombre de la variable en Render</label><input name="environment_variable" value="'+esc(document.getElementById('initial-env').value)+'" placeholder="SSH_PASSWORD_SERVER_MAIN"><div class="muted small">Escribe solo el nombre. No uses RENDER_ENV: en este campo.</div>'}else if(source==='reference'){box.innerHTML='<label>Referencia avanzada</label><input name="secret_reference" placeholder="ENV:SSH_KEY o 1PASSWORD:op://..."><div class="muted small">Solo para compatibilidad avanzada.</div>'}else{box.innerHTML='<div class="notice">El proceso del runner debe tener un SSH Agent disponible.</div>'}}
function openTarget(t){const editing=Boolean(t&&t.id);modal.innerHTML='<div class="modal-head"><strong>'+(editing?'Editar target':'Agregar target')+'</strong><button class="btn" id="close">Cerrar</button></div><div class="modal-body">'+targetForm(t)+'</div><div class="modal-foot"><button class="btn" id="cancel">Cancelar</button><button class="btn primary" id="save">Guardar</button></div>';modal.showModal();const f=document.getElementById('target-form');f.elements.type.value=t&&t.type||'ssh';f.elements.auth_type.value=t&&t.auth_type||'private_key';f.elements.credential_source.value=sourceOf(t||{});renderCredentialFields(editing);f.elements.credential_source.onchange=function(){renderCredentialFields(editing)};f.elements.auth_type.onchange=function(){if(f.elements.auth_type.value==='agent')f.elements.credential_source.value='agent';renderCredentialFields(editing)};document.getElementById('close').onclick=document.getElementById('cancel').onclick=function(){modal.close()};document.getElementById('scan-key').onclick=async function(){try{const host=f.elements.host.value.trim();const port=Number(f.elements.port.value||22);if(!host)throw new Error('Escribe primero el host.');const result=await api('/admin/api/v2/scan-host-key',{method:'POST',body:JSON.stringify({host:host,port:port})});f.elements.known_hosts.value=result.known_hosts;alert('Clave detectada. Compara la huella antes de guardar.')}catch(e){document.getElementById('form-error').textContent=e.message}};document.getElementById('save').onclick=async function(){if(!f.reportValidity())return;const fd=new FormData(f);const body={name:fd.get('name'),type:fd.get('type'),host:fd.get('host'),port:Number(fd.get('port')),username:fd.get('username'),auth_type:fd.get('auth_type'),credential_source:fd.get('credential_source'),credential:String(fd.get('credential')||''),environment_variable:String(fd.get('environment_variable')||''),secret_reference:String(fd.get('secret_reference')||''),working_directory:String(fd.get('working_directory')||'').trim()||null,known_hosts:String(fd.get('known_hosts')||'').trim()||null,tags:String(fd.get('tags')||'').split(',').map(function(v){return v.trim()}).filter(Boolean),enabled:fd.get('enabled')==='on'};try{await api('/admin/api/v2/targets'+(editing?'/'+t.id:''),{method:editing?'PATCH':'POST',body:JSON.stringify(body)});modal.close();await renderTargets()}catch(e){document.getElementById('form-error').textContent=e.message}}}
async function renderCatalog(){const results=await Promise.all([api('/admin/api/catalog'),api('/admin/api/commands')]);state.catalog=results[0].catalog||[];state.commands=results[1].commands||[];const installed=new Set(state.commands.map(function(c){return c.catalog_key}).filter(Boolean));const groups={};state.catalog.forEach(function(c){(groups[c.category]||(groups[c.category]=[])).push(c)});let html='<div class="toolbar"><div><h2 style="margin:0">Catálogo recomendado</h2><div class="muted">Comandos revisados por categoría y nivel de riesgo.</div></div><button class="btn primary" id="install-all">Agregar catálogo completo</button></div>';Object.keys(groups).sort().forEach(function(category){html+='<h3 class="category">'+esc(category)+'</h3><div class="catalog-grid">'+groups[category].map(function(c){const done=installed.has(c.catalog_key);return '<article class="item"><div class="item-head"><div><b>'+esc(c.name)+'</b><div class="muted small">'+esc(c.description)+'</div></div><span class="pill">'+esc(c.risk_level)+'</span></div><div class="code">'+esc(c.command_template)+'</div><div class="actions"><button class="btn '+(done?'':'primary')+'" data-install="'+esc(c.catalog_key)+'" '+(done?'disabled':'')+'>'+(done?'Agregado':'Agregar')+'</button></div></article>'}).join('')+'</div>'});shell('<section class="card">'+html+'</section>');document.getElementById('install-all').onclick=async function(){await api('/admin/api/catalog/install',{method:'POST',body:'{}'});await renderCatalog()};document.querySelectorAll('[data-install]').forEach(function(b){b.onclick=async function(){await api('/admin/api/catalog/install',{method:'POST',body:JSON.stringify({keys:[b.dataset.install]})});await renderCatalog()}})}
fetch('/admin/config').then(function(r){return r.json()}).then(function(c){state.cfg=c;if(!c.enabled){app.innerHTML='<section class="card login error">Supabase no está configurado.</section>';return}state.token?boot():login()}).catch(function(e){app.innerHTML='<section class="card login error">'+esc(e.message)+'</section>'});
</script></body></html>`;
}
