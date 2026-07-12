import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { AdminService } from "./admin.js";
import { forbidden } from "./errors.js";

export type CatalogCommand = {
  catalog_key: string;
  category: string;
  name: string;
  description: string;
  command_template: string;
  risk_level: "low" | "medium" | "high";
  requires_approval: boolean;
  allowed_roles: Array<"admin" | "operator" | "viewer">;
  enabled: boolean;
  destructive?: boolean;
};

export const commandCatalog: CatalogCommand[] = [
  { catalog_key: "system.identity", category: "Sistema", name: "Identidad del usuario", description: "Muestra UID, grupos y usuario remoto.", command_template: "id && whoami", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "system.hostname", category: "Sistema", name: "Nombre y sistema operativo", description: "Muestra hostname y datos básicos del sistema.", command_template: "hostnamectl 2>/dev/null || hostname", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "system.uptime", category: "Sistema", name: "Uptime y carga", description: "Tiempo encendido y carga promedio.", command_template: "uptime", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "system.kernel", category: "Sistema", name: "Kernel y arquitectura", description: "Versión de kernel y arquitectura.", command_template: "uname -a", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "system.time", category: "Sistema", name: "Fecha del servidor", description: "Fecha y zona horaria reportadas por el target.", command_template: "date -Is", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "system.disk", category: "Sistema", name: "Uso de disco", description: "Espacio y tipo de sistema de archivos.", command_template: "df -hT", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "system.memory", category: "Sistema", name: "Uso de memoria", description: "Memoria RAM y swap disponibles.", command_template: "free -h", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "system.block_devices", category: "Sistema", name: "Discos y montajes", description: "Lista dispositivos, tamaños y puntos de montaje.", command_template: "lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINTS", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "system.top_cpu", category: "Sistema", name: "Procesos con más CPU", description: "Top de procesos ordenados por CPU.", command_template: "ps aux --sort=-%cpu | head -n 21", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "system.top_memory", category: "Sistema", name: "Procesos con más memoria", description: "Top de procesos ordenados por memoria.", command_template: "ps aux --sort=-%mem | head -n 21", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "network.addresses", category: "Red", name: "Interfaces de red", description: "Direcciones IP resumidas por interfaz.", command_template: "ip -brief address", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "network.routes", category: "Red", name: "Tabla de rutas", description: "Muestra rutas activas del target.", command_template: "ip route", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "network.listeners", category: "Red", name: "Puertos en escucha", description: "Lista sockets TCP y UDP en escucha.", command_template: "ss -tulpn", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "services.failed", category: "Servicios", name: "Servicios fallidos", description: "Lista unidades systemd fallidas.", command_template: "systemctl --failed --no-pager", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "services.errors", category: "Servicios", name: "Errores recientes del sistema", description: "Últimos errores registrados por journald.", command_template: "journalctl -p err -n 100 --no-pager", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "sessions.active", category: "Seguridad", name: "Sesiones activas", description: "Usuarios conectados actualmente.", command_template: "who", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "sessions.recent", category: "Seguridad", name: "Inicios de sesión recientes", description: "Últimas sesiones registradas.", command_template: "last -n 20", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "updates.available", category: "Seguridad", name: "Actualizaciones disponibles", description: "Paquetes actualizables en sistemas Debian/Ubuntu.", command_template: "apt list --upgradable 2>/dev/null | head -n 100", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "firewall.status", category: "Seguridad", name: "Estado del firewall", description: "Muestra el estado detallado de UFW sin modificar reglas.", command_template: "sudo -n ufw status verbose", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "ssh.service", category: "Servicios", name: "Estado del servicio SSH", description: "Muestra el estado actual de OpenSSH.", command_template: "systemctl status ssh --no-pager", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "docker.ps", category: "Docker", name: "Contenedores activos", description: "Lista contenedores y estado.", command_template: "docker ps --format 'table {{.Names}}\\t{{.Image}}\\t{{.Status}}\\t{{.Ports}}'", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "docker.compose.ps", category: "Docker", name: "Estado de Docker Compose", description: "Muestra servicios del proyecto Compose actual.", command_template: "docker compose ps", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "docker.images", category: "Docker", name: "Imágenes Docker", description: "Lista imágenes disponibles.", command_template: "docker image ls", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "docker.volumes", category: "Docker", name: "Volúmenes Docker", description: "Lista volúmenes locales.", command_template: "docker volume ls", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "docker.networks", category: "Docker", name: "Redes Docker", description: "Lista redes Docker.", command_template: "docker network ls", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "docker.disk", category: "Docker", name: "Uso de disco Docker", description: "Resumen de espacio usado por imágenes, contenedores y caché.", command_template: "docker system df", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "docker.stats", category: "Docker", name: "Consumo de contenedores", description: "CPU y memoria en una captura única.", command_template: "docker stats --no-stream", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "docker.compose.logs", category: "Docker", name: "Logs de Docker Compose", description: "Últimas 200 líneas de todos los servicios.", command_template: "docker compose logs --tail 200", risk_level: "medium", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "docker.compose.pull", category: "Docker", name: "Actualizar imágenes Compose", description: "Descarga las imágenes declaradas en Compose.", command_template: "docker compose pull", risk_level: "high", requires_approval: true, allowed_roles: ["admin"], enabled: true },
  { catalog_key: "docker.compose.up", category: "Docker", name: "Aplicar Docker Compose", description: "Crea o actualiza servicios en segundo plano.", command_template: "docker compose up -d", risk_level: "high", requires_approval: true, allowed_roles: ["admin"], enabled: true },
  { catalog_key: "docker.compose.restart", category: "Docker", name: "Reiniciar Docker Compose", description: "Reinicia todos los servicios del proyecto.", command_template: "docker compose restart", risk_level: "high", requires_approval: true, allowed_roles: ["admin"], enabled: true },
  { catalog_key: "docker.compose.down", category: "Docker", name: "Detener Docker Compose", description: "Detiene y elimina contenedores del proyecto Compose actual.", command_template: "docker compose down", risk_level: "high", requires_approval: true, allowed_roles: ["admin"], enabled: true, destructive: true },
  { catalog_key: "docker.prune", category: "Docker", name: "Limpiar objetos Docker", description: "Elimina objetos Docker no utilizados.", command_template: "docker system prune -f", risk_level: "high", requires_approval: true, allowed_roles: ["admin"], enabled: true, destructive: true },
  { catalog_key: "docker.volume.prune", category: "Docker", name: "Limpiar volúmenes Docker", description: "Elimina volúmenes Docker no utilizados. Puede borrar datos si un volumen dejó de estar referenciado.", command_template: "docker volume prune -f", risk_level: "high", requires_approval: true, allowed_roles: ["admin"], enabled: true, destructive: true },
  { catalog_key: "git.status", category: "Git", name: "Estado Git", description: "Rama y archivos modificados.", command_template: "git status --short --branch", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "git.log", category: "Git", name: "Últimos commits", description: "Últimos 15 commits resumidos.", command_template: "git log -n 15 --oneline --decorate", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "git.remote", category: "Git", name: "Remotos Git", description: "Lista URLs remotas configuradas.", command_template: "git remote -v", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "git.diffstat", category: "Git", name: "Resumen de cambios Git", description: "Estadística de cambios no confirmados.", command_template: "git diff --stat", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "git.pull", category: "Git", name: "Actualizar repositorio Git", description: "Hace pull fast-forward sin crear merge automático.", command_template: "git pull --ff-only", risk_level: "high", requires_approval: true, allowed_roles: ["admin"], enabled: true },
  { catalog_key: "git.clean.dry_run", category: "Git", name: "Vista previa de limpieza Git", description: "Muestra archivos no versionados que se eliminarían.", command_template: "git clean -fdn", risk_level: "medium", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "git.reset.hard", category: "Git", name: "Reset hard Git", description: "Descarta todos los cambios locales versionados.", command_template: "git reset --hard", risk_level: "high", requires_approval: true, allowed_roles: ["admin"], enabled: true, destructive: true },
  { catalog_key: "git.clean.force", category: "Git", name: "Limpieza forzada Git", description: "Elimina archivos no versionados.", command_template: "git clean -fd", risk_level: "high", requires_approval: true, allowed_roles: ["admin"], enabled: true, destructive: true },
  { catalog_key: "node.versions", category: "Node.js", name: "Versiones Node y npm", description: "Muestra las versiones instaladas.", command_template: "node --version && npm --version", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "node.test", category: "Node.js", name: "Ejecutar pruebas npm", description: "Ejecuta el script de pruebas del proyecto, que puede contener código arbitrario del repositorio.", command_template: "npm test", risk_level: "high", requires_approval: true, allowed_roles: ["admin"], enabled: true },
  { catalog_key: "node.build", category: "Node.js", name: "Construir proyecto npm", description: "Ejecuta el script de construcción del proyecto, que puede contener código arbitrario del repositorio.", command_template: "npm run build", risk_level: "high", requires_approval: true, allowed_roles: ["admin"], enabled: true },
  { catalog_key: "node.ci", category: "Node.js", name: "Instalar dependencias npm", description: "Instalación reproducible desde package-lock.", command_template: "npm ci", risk_level: "high", requires_approval: true, allowed_roles: ["admin"], enabled: true },
  { catalog_key: "cloudflared.service", category: "Servicios", name: "Servicio Cloudflared", description: "Estado del servicio cloudflared.", command_template: "systemctl status cloudflared --no-pager", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "cloudflared.logs", category: "Servicios", name: "Logs de Cloudflared", description: "Muestra las últimas 200 líneas del túnel Cloudflare.", command_template: "journalctl -u cloudflared -n 200 --no-pager", risk_level: "low", requires_approval: false, allowed_roles: ["admin", "operator"], enabled: true },
  { catalog_key: "updates.upgrade", category: "Seguridad", name: "Aplicar actualizaciones", description: "Actualiza índices e instala upgrades disponibles en Debian/Ubuntu.", command_template: "sudo -n apt-get update && sudo -n env DEBIAN_FRONTEND=noninteractive apt-get upgrade -y", risk_level: "high", requires_approval: true, allowed_roles: ["admin"], enabled: true },
  { catalog_key: "updates.autoremove", category: "Seguridad", name: "Eliminar paquetes obsoletos", description: "Elimina paquetes instalados automáticamente que ya no son necesarios.", command_template: "sudo -n apt-get autoremove -y", risk_level: "high", requires_approval: true, allowed_roles: ["admin"], enabled: true, destructive: true },
  { catalog_key: "system.reboot", category: "Sistema", name: "Reiniciar sistema", description: "Solicita reinicio del target. Requiere privilegios sudo no interactivos configurados en el target.", command_template: "sudo -n /sbin/reboot", risk_level: "high", requires_approval: true, allowed_roles: ["admin"], enabled: true, destructive: true },
  { catalog_key: "system.shutdown", category: "Sistema", name: "Apagar sistema", description: "Apaga el target y lo deja fuera de línea hasta una intervención externa.", command_template: "sudo -n /sbin/shutdown -h now", risk_level: "high", requires_approval: true, allowed_roles: ["admin"], enabled: true, destructive: true },
  { catalog_key: "services.restart.nginx", category: "Servicios", name: "Reiniciar nginx", description: "Reinicia nginx mediante systemd.", command_template: "sudo -n systemctl restart nginx", risk_level: "high", requires_approval: true, allowed_roles: ["admin"], enabled: true, destructive: true },
  { catalog_key: "services.restart.docker", category: "Servicios", name: "Reiniciar Docker", description: "Reinicia el servicio Docker mediante systemd.", command_template: "sudo -n systemctl restart docker", risk_level: "high", requires_approval: true, allowed_roles: ["admin"], enabled: true, destructive: true },
  { catalog_key: "services.restart.ssh", category: "Servicios", name: "Reiniciar SSH", description: "Reinicia OpenSSH y puede interrumpir la conectividad actual.", command_template: "sudo -n systemctl restart ssh", risk_level: "high", requires_approval: true, allowed_roles: ["admin"], enabled: true, destructive: true },
  { catalog_key: "services.restart.cloudflared", category: "Servicios", name: "Reiniciar Cloudflared", description: "Reinicia el túnel Cloudflare y puede interrumpir el acceso al target.", command_template: "sudo -n systemctl restart cloudflared", risk_level: "high", requires_approval: true, allowed_roles: ["admin"], enabled: true, destructive: true },
];

const installInput = z.object({ keys: z.array(z.string().min(1)).max(100).optional() });

export function registerCommandCatalogRoutes(server: FastifyInstance, admin: AdminService): void {
  server.get("/admin/api/catalog", async (request) => {
    await admin.principal(request);
    return { catalog: commandCatalog };
  });

  server.post("/admin/api/catalog/install", async (request, reply) => {
    const principal = await admin.principal(request);
    if (principal.role !== "admin") throw forbidden("Only administrators can install catalog commands.");
    const input = installInput.parse(request.body ?? {});
    const selected = input.keys?.length ? commandCatalog.filter((entry) => input.keys!.includes(entry.catalog_key)) : commandCatalog;
    if (!selected.length) return reply.code(200).send({ installed: 0 });
    await admin.rest("commands", {
      method: "POST",
      query: "on_conflict=catalog_key",
      body: selected.map((entry) => ({ ...entry, impact: entry.description, created_by: principal.id })),
      prefer: "resolution=merge-duplicates,return=minimal",
    });
    await admin.rest("audit_logs", {
      method: "POST",
      body: {
        actor_id: principal.id,
        action: "command_catalog.installed",
        entity_type: "command",
        metadata: { keys: selected.map((entry) => entry.catalog_key), count: selected.length },
      },
      prefer: "return=minimal",
    });
    return reply.code(201).send({ installed: selected.length });
  });
}
