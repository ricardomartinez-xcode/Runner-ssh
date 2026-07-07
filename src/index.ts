import { Auth } from "./auth.js";
import { app } from "./app.js";
import { loadEnvironment, loadRunnerConfig } from "./config.js";
import { Executors } from "./executors.js";
import { Jobs } from "./jobs.js";
import { Registry } from "./registry.js";
import { Secrets } from "./secrets.js";
import { FileStore } from "./store.js";

const env = loadEnvironment();
const config = await loadRunnerConfig(env.RUNNER_CONFIG_PATH);
const registry = new Registry(config);
const store = new FileStore(env.DATA_DIR);
await store.init();

const jobs = new Jobs(env, registry, store, new Executors(new Secrets()));
const server = app({ env, auth: new Auth(env), registry, jobs });
await server.listen({ host: env.HOST, port: env.PORT });
