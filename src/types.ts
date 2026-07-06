export type TargetType = "ssh" | "codespace";
export type JobStatus = "planned" | "queued" | "running" | "succeeded" | "failed" | "cancelled" | "expired";

export type SecretReference = {
  provider: "1password" | "env";
  reference: string;
  mode?: "key" | "password" | "token";
};

export type TaskDefinition = {
  description: string;
  argv: string[];
  timeout_seconds?: number;
};

export type CollectionDefinition = {
  description: string;
  required_roles?: string[];
  tasks: Record<string, TaskDefinition>;
};

export type SshTarget = {
  type: "ssh";
  description: string;
  required_roles?: string[];
  allowed_collections: string[];
  working_directory?: string;
  host: string;
  port?: number;
  username: string;
  known_hosts: string;
  auth: SecretReference & { mode: "key" | "password" };
};

export type CodespaceTarget = {
  type: "codespace";
  description: string;
  required_roles?: string[];
  allowed_collections: string[];
  working_directory?: string;
  codespace_name: string;
  github_token: SecretReference;
};

export type TargetDefinition = SshTarget | CodespaceTarget;

export type RunnerConfig = {
  version: 1;
  collections: Record<string, CollectionDefinition>;
  targets: Record<string, TargetDefinition>;
};

export type Principal = {
  subject: string;
  roles: string[];
  scopes: string[];
};

export type Job = {
  id: string;
  requester_subject: string;
  requester_roles: string[];
  requester_scopes: string[];
  target_id: string;
  collection_id: string;
  task_id: string;
  status: JobStatus;
  created_at: string;
  expires_at: string;
  started_at?: string;
  completed_at?: string;
  cancelled_at?: string;
  command_preview: string;
  output: string;
  output_truncated: boolean;
  exit_code?: number | null;
  error?: string;
};

export type Plan = {
  targetId: string;
  collectionId: string;
  taskId: string;
  target: TargetDefinition;
  collection: CollectionDefinition;
  task: TaskDefinition;
  commandPreview: string;
};
