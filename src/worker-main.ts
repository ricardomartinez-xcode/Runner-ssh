import { AdminService } from "./admin.js";
import { loadEnvironment } from "./config.js";
import { startWorker } from "./worker.js";

const env = loadEnvironment();
const admin = new AdminService();

await startWorker(admin, env);
