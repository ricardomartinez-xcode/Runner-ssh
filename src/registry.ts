import type { CollectionDefinition, Plan, Principal, RunnerConfig, TargetDefinition } from "./types.js";
import { forbidden, notFound } from "./errors.js";

function allowed(principal: Principal, required: string[] | undefined): boolean {
  return !required?.length || required.some((role) => principal.roles.includes(role));
}

export class Registry {
  constructor(private readonly config: RunnerConfig) {}

  listCollections(principal: Principal) {
    return Object.entries(this.config.collections)
      .filter(([, collection]) => allowed(principal, collection.required_roles))
      .map(([id, collection]) => ({
        id,
        description: collection.description,
        tasks: Object.entries(collection.tasks).map(([taskId, task]) => ({
          id: taskId,
          description: task.description,
          timeout_seconds: task.timeout_seconds,
        })),
      }));
  }

  listTargets(principal: Principal) {
    return Object.entries(this.config.targets)
      .filter(([, target]) => allowed(principal, target.required_roles))
      .map(([id, target]) => ({
        id,
        type: target.type,
        description: target.description,
        allowed_collections: target.allowed_collections,
      }));
  }

  getCollection(principal: Principal, id: string) {
    const collection = this.collection(principal, id);
    return {
      id,
      description: collection.description,
      tasks: Object.entries(collection.tasks).map(([taskId, task]) => ({
        id: taskId,
        description: task.description,
        timeout_seconds: task.timeout_seconds,
      })),
    };
  }

  getTarget(principal: Principal, id: string) {
    const target = this.target(principal, id);
    return { id, type: target.type, description: target.description, allowed_collections: target.allowed_collections };
  }

  plan(principal: Principal, targetId: string, collectionId: string, taskId: string): Plan {
    const target = this.target(principal, targetId);
    const collection = this.collection(principal, collectionId);
    if (!target.allowed_collections.includes(collectionId)) {
      throw forbidden(`Collection "${collectionId}" is not allowed for target "${targetId}".`);
    }
    const task = collection.tasks[taskId];
    if (!task) throw notFound(`Task "${taskId}" was not found in collection "${collectionId}".`);
    const commandPreview = `target=${targetId}; type=${target.type}; task=${taskId}; argv=${task.argv.map((part) => JSON.stringify(part)).join(" ")}`;
    return { targetId, collectionId, taskId, target, collection, task, commandPreview };
  }

  private collection(principal: Principal, id: string): CollectionDefinition {
    const value = this.config.collections[id];
    if (!value) throw notFound(`Collection "${id}" was not found.`);
    if (!allowed(principal, value.required_roles)) throw forbidden(`Not allowed to use collection "${id}".`);
    return value;
  }

  private target(principal: Principal, id: string): TargetDefinition {
    const value = this.config.targets[id];
    if (!value) throw notFound(`Target "${id}" was not found.`);
    if (!allowed(principal, value.required_roles)) throw forbidden(`Not allowed to use target "${id}".`);
    return value;
  }
}
