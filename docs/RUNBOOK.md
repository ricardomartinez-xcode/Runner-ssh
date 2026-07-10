# ReLead Ops Runbook

## Deploy

```bash
npm ci
npm run check
npm test
docker build -t relead-ops:local .
```

Then deploy both Render services from `render.yaml`.

## Apply Migrations

Apply migrations in order:

```text
0001_runner_admin.sql
0002_ssh_execution.sql
0003_managed_credentials_and_catalog.sql
0004_worker_approvals_permissions.sql
```

## Onboard A Target

1. Open `/admin/manage-v2`.
2. Choose `SSH normal` or `SSH via Cloudflare Tunnel or bastion`.
3. Enter host, port, username, environment and tags.
4. Choose managed credential, Render variable, SSH Agent or advanced reference.
5. Detect and verify `known_hosts`.
6. Run connection test.
7. Save target.
8. Install/assign catalog commands.
9. Keep production targets disabled until the first health check passes.

## Execute A Command

1. Select a target.
2. Select an assigned command.
3. Confirm with `EJECUTAR`.
4. If approval is required, an admin approves or rejects.
5. Worker claims the job and streams logs.

## Recover Interrupted Jobs

The worker updates `heartbeat_at`. `mark_interrupted_executions()` requeues stale jobs until `max_retries`; after that, they fail with `interrupted=true`.

Manual SQL inspection:

```sql
select id, status, worker_id, heartbeat_at, retry_count, max_retries, last_error
from public.executions
order by created_at desc
limit 20;
```

## Rotate A Target Credential

1. Edit the target.
2. Paste a new private key/password or change the Render variable.
3. Test connection.
4. Save.
5. Remove old public key from the target.
6. Confirm `target.updated` in audit logs.

## Troubleshooting

- `known_hosts_required`: detect host key and compare fingerprint.
- `secret_resolution_failed`: missing Render variable or managed credential.
- `unsupported_target`: target type is not executable by the Render worker.
- `Permission denied`: wrong username, key, authorized_keys or SSH port.
- `Worker heartbeat expired`: worker crashed or was redeployed; job will retry.
