-- Non-secret worker liveness metadata for operations and recovery diagnostics.

create table if not exists public.worker_instances (
  worker_id text primary key,
  service text not null default 'relead-ops-worker',
  status text not null default 'online' check (status in ('online', 'draining', 'offline')),
  started_at timestamptz not null default now(),
  last_heartbeat timestamptz not null default now(),
  active_jobs integer not null default 0 check (active_jobs >= 0),
  max_concurrent_jobs integer not null default 1 check (max_concurrent_jobs >= 1),
  heartbeat_interval_ms integer not null default 10000 check (heartbeat_interval_ms >= 1000),
  metadata jsonb not null default '{}'::jsonb
);

alter table public.worker_instances enable row level security;

drop policy if exists worker_instances_admin_read on public.worker_instances;
create policy worker_instances_admin_read on public.worker_instances
  for select using (public.is_admin());

create index if not exists worker_instances_last_heartbeat_idx
  on public.worker_instances(last_heartbeat desc);

comment on table public.worker_instances is
  'Non-secret liveness and capacity metadata reported by ReLead Ops workers.';
