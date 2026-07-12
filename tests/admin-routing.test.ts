import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import type { AdminService } from "../src/admin.js";
import { registerImprovedTargetRoutes } from "../src/admin-targets-v2.js";
import { registerAdminUiRoutes } from "../src/admin-ui.js";
import { registerAdminRoutes } from "../src/admin.js";

describe("canonical admin routing", () => {
  it("keeps one admin panel and leaves break-glass recovery outside it", async () => {
    const server = Fastify();
    const admin = { publicConfig: () => ({ enabled: false }) } as unknown as AdminService;
    registerAdminRoutes(server, admin);
    registerAdminUiRoutes(server, admin);
    registerImprovedTargetRoutes(server, admin);

    const adminRoot = await server.inject({ method: "GET", url: "/admin" });
    const legacy = await server.inject({ method: "GET", url: "/admin/manage-v2" });
    const canonical = await server.inject({ method: "GET", url: "/admin/manage" });

    expect(adminRoot.headers.location).toBe("/admin/manage");
    expect(legacy.headers.location).toBe("/admin/manage");
    expect(canonical.statusCode).toBe(200);
    expect(canonical.body).toContain("Usuarios y permisos");
    expect(canonical.body).toContain("initTargetWizard");
    expect(canonical.body).toContain("[hidden]{display:none!important}");
    expect(canonical.body).toContain("dialog[open]{display:flex");
    expect(canonical.body).not.toContain('data-view="emergency"');
    expect(canonical.body).not.toContain("Consola de emergencia");
    const inlineScript = /<script>([\s\S]*)<\/script>/.exec(canonical.body)?.[1];
    expect(inlineScript).toBeTruthy();
    expect(() => new Function(inlineScript!)).not.toThrow();
    await server.close();
  });
});
