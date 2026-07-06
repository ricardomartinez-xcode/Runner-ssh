import { describe, expect, it } from "vitest";
import { Registry } from "../src/registry.js";
import type { RunnerConfig } from "../src/types.js";

const config: RunnerConfig = {
  version: 1,
  collections: {
    repository: {
      description: "Repo",
      required_roles: ["runner.operator"],
      tasks: { "repo.status": { description: "Status", argv: ["git", "status", "--short"] } },
    },
  },
  targets: {
    staging: {
      type: "ssh",
      description: "Staging",
      required_roles: ["runner.operator"],
      allowed_collections: ["repository"],
      host: "staging.example.com",
      port: 22,
      username: "runner",
      known_hosts: "staging.example.com ssh-ed25519 AAAA",
      auth: { provider: "env", reference: "TEST_KEY", mode: "key" },
    },
  },
};

describe("Registry", () => {
  it("only plans a configured task", () => {
    const registry = new Registry(config);
    expect(registry.plan({ subject: "u", roles: ["runner.operator"], scopes: [] }, "staging", "repository", "repo.status").task.argv)
      .toEqual(["git", "status", "--short"]);
  });

  it("rejects arbitrary tasks", () => {
    const registry = new Registry(config);
    expect(() => registry.plan({ subject: "u", roles: ["runner.operator"], scopes: [] }, "staging", "repository", "ssh.exec"))
      .toThrow(/was not found/);
  });
});
