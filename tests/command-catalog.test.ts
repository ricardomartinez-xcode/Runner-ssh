import { describe, expect, it } from "vitest";
import { commandCatalog } from "../src/command-catalog.js";

describe("recommended command catalog", () => {
  it("uses unique stable catalog keys", () => {
    const keys = commandCatalog.map((command) => command.catalog_key);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("forces approval and administrator access for every high-risk command", () => {
    for (const command of commandCatalog.filter((entry) => entry.risk_level === "high")) {
      expect(command.requires_approval, command.catalog_key).toBe(true);
      expect(command.allowed_roles, command.catalog_key).toEqual(["admin"]);
    }
  });

  it("marks every destructive command as high risk", () => {
    for (const command of commandCatalog.filter((entry) => entry.destructive)) {
      expect(command.risk_level, command.catalog_key).toBe("high");
      expect(command.requires_approval, command.catalog_key).toBe(true);
    }
  });

  it("never weakens SSH host verification", () => {
    expect(commandCatalog.some((command) => /StrictHostKeyChecking\s*=\s*no/i.test(command.command_template))).toBe(false);
  });

  it("requires approval for repository-changing and package-script commands", () => {
    for (const key of ["git.pull", "node.test", "node.build", "node.ci"]) {
      expect(commandCatalog.find((command) => command.catalog_key === key)).toMatchObject({
        risk_level: "high",
        requires_approval: true,
        allowed_roles: ["admin"],
      });
    }
  });
});
