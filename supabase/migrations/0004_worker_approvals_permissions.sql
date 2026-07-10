-- ReLead Ops production worker, approvals, streaming logs, health, and granular permissions.

alter table public.targets
  add column if not exists environment text not null default 'dev' check (environment in ('prod', 'staging', 'dev')),
  add column if not exists disabled_reason text,
  add column if not exists last_tested_at timestamptz,
  add column if not exists last_test_status text check (last_test_status in ('passed', 'failed', 'unknown')),
  add column if not exists last_test_message text;

alter table public.commands
  add column if not exists impact text,
  add column if not exists destructive boolean not null default false;

alter table public.executions
  drop constraint if exists executions_status_check;

alter table public.executions
  add constraint executions_status_check
  check (status in ('planned', 'queued', 'running', 'succeeded', 'failed', 'cancelled', 'expired', 'approval_required', 'rejected'));

alter table public.executions
  add column if not exists confirmed_at timestamptz,
  add column if not exists approved_by uuid references auth.users(id) on delete set null,
  add column if not exists approved_at timestamptz,
  add column if not exists rejected_by uuid references auth.users(id) on delete set null,
  add column if not exists rejected_at timestamptz,
  add column if not exists rejection_reason text,
  add column if not exists worker_id text,
  add column if not exists locked_at timestamptz,
  add column if not exists heartbeat_at timestamptz,
  add column if not exists timeout_at timestamptz,
  add column if not exists retry_count integer not null default 0 check (retry_count >= 0),
  add column if not exists max_retries integer not null default 2 check (max_retries >= 0),
  add column if not exists last_error text,
  add column if not exists interrupted boolean not null default false,
  add column if not exists stdout_truncated boolean not null default false,
  add column if not exists stderr_truncated boolean not null default false;

alter table public.health_checks
  add column if not exists raw_summary text,
  add column if not exists docker_status text,
  add column if not exists systemd_status text,
  add column if not exists tailscale_status text,
  add column if not exists cloudflared_status text;

create table if not exists public.environments (
  id text primary key check (id in ('prod', 'staging', 'dev')),
  name text not null,
  requires_approval boolean not null default false,
  created_at timestamptz not null default now()
);

insert into public.environments (id, name, requires_approval)
values
  ('prod', 'Production', true),
  ('staging', 'Staging', false),
  ('dev', 'Development', false)
on conflict (id) do update
set name = excluded.name,
    requires_approval = excluded.requires_approval;

create table if not exists public.organization_members (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('admin', 'operator', 'viewer')),
  environments text[] not null default '{dev}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.target_permissions (
  user_id uuid not null references auth.users(id) on delete cascade,
  target_id uuid not null references public.targets(id) on delete cascade,
  environment text not null default 'dev' check (environment in ('prod', 'staging', 'dev')),
  can_execute boolean not null default false,
  can_manage boolean not null default false,
  created_at timestamptz not null default now(),
  primary key (user_id, target_id, environment)
);

create table if not exists public.command_permissions (
  user_id uuid not null references auth.users(id) on delete cascade,
  command_id uuid not null references public.commands(id) on delete cascade,
  can_execute boolean not null default false,
  created_at timestamptz not null default now(),
  primary key (user_id, command_id)
);

create table if not exists public.execution_log_events (
  id bigserial primary key,
  execution_id uuid not null references public.executions(id) on delete cascade,
  stream text not null check (stream in ('stdout', 'stderr', 'system')),
  chunk text not null,
  redacted boolean not null default true,
  truncated boolean not null default false,
  created_at timestamptz not null default now()
);

alter table public.environments enable row level security;
alter table public.organization_members enable row level security;
alter table public.target_permissions enable row level security;
alter table public.command_permissions enable row level security;
alter table public.execution_log_events enable row level security;

create policy environments_read_authenticated on public.environments
  for select using (auth.uid() is not null);

create policy organization_members_read_own_or_admin on public.organization_members
  for select using (user_id = auth.uid() or public.is_admin());

create policy organization_members_admin_write on public.organization_members
  for all using (public.is_admin()) with check (public.is_admin());

create policy target_permissions_read_own_or_admin on public.target_permissions
  for select using (user_id = auth.uid() or public.is_admin());

create policy target_permissions_admin_write on public.target_permissions
  for all using (public.is_admin()) with check (public.is_admin());

create policy command_permissions_read_own_or_admin on public.command_permissions
  for select using (user_id = auth.uid() or public.is_admin());

create policy command_permissions_admin_write on public.command_permissions
  for all using (public.is_admin()) with check (public.is_admin());

create policy execution_log_events_read_authenticated on public.execution_log_events
  for select using (auth.uid() is not null);

create policy execution_log_events_admin_write on public.execution_log_events
  for all using (public.is_admin()) with check (public.is_admin());

create index if not exists executions_worker_claim_idx
  on public.executions(status, confirmed_at, locked_at, heartbeat_at, created_at)
  where status = 'queued';

create index if not exists executions_approval_idx
  on public.executions(status, created_at desc)
  where status = 'approval_required';

create index if not exists execution_log_events_execution_id_idx
  on public.execution_log_events(execution_id, id);

create index if not exists target_permissions_user_idx
  on public.target_permissions(user_id, target_id, environment);

create index if not exists command_permissions_user_idx
  on public.command_permissions(user_id, command_id);

create or replace function public.claim_execution(p_worker_id text, p_lock_seconds integer default 90)
returns setof public.executions
language plpgsql
security definer
set search_path = public
as $$
declare
  claimed public.executions%rowtype;
begin
  update public.executions e
  set status = 'running',
      worker_id = p_worker_id,
      locked_at = now(),
      heartbeat_at = now(),
      started_at = coalesce(e.started_at, now()),
      timeout_at = now() + interval '5 minutes',
      last_error = null
  where e.id = (
    select candidate.id
    from public.executions candidate
    where candidate.status = 'queued'
      and candidate.confirmed_at is not null
      and candidate.retry_count <= candidate.max_retries
      and (
        candidate.locked_at is null
        or candidate.heartbeat_at is null
        or candidate.heartbeat_at < now() - make_interval(secs => p_lock_seconds)
      )
    order by candidate.created_at asc
    for update skip locked
    limit 1
  )
  returning * into claimed;

  if claimed.id is not null then
    return next claimed;
  end if;
end;
$$;

create or replace function public.mark_interrupted_executions(p_stale_seconds integer default 300)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  affected integer;
begin
  update public.executions
  set status = case when retry_count < max_retries then 'queued' else 'failed' end,
      retry_count = case when retry_count < max_retries then retry_count + 1 else retry_count end,
      interrupted = true,
      last_error = 'Worker heartbeat expired.',
      worker_id = null,
      locked_at = null,
      heartbeat_at = null,
      finished_at = case when retry_count < max_retries then finished_at else now() end
  where status = 'running'
    and heartbeat_at is not null
    and heartbeat_at < now() - make_interval(secs => p_stale_seconds);

  get diagnostics affected = row_count;
  return affected;
end;
$$;

comment on function public.claim_execution(text, integer) is
  'Atomically claims one confirmed queued execution for a worker using row locks and SKIP LOCKED.';

comment on table public.execution_log_events is
  'Append-only redacted stdout/stderr/system log chunks for SSE or Supabase Realtime streaming.';
