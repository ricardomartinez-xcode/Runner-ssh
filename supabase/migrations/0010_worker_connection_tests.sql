-- Execute target connection tests exclusively in the worker process.

create table if not exists public.target_connection_tests (
  id uuid primary key default gen_random_uuid(),
  target_id uuid not null references public.targets(id) on delete cascade,
  requested_by uuid references auth.users(id) on delete set null,
  status text not null default 'queued' check (status in ('queued', 'running', 'succeeded', 'failed')),
  enable_on_success boolean not null default false,
  worker_id text,
  locked_at timestamptz,
  heartbeat_at timestamptz,
  retry_count integer not null default 0 check (retry_count >= 0),
  max_retries integer not null default 1 check (max_retries >= 0),
  interrupted boolean not null default false,
  stdout text,
  stderr text,
  stdout_truncated boolean not null default false,
  stderr_truncated boolean not null default false,
  exit_code integer,
  duration_ms integer,
  error text,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz not null default now()
);

alter table public.target_connection_tests enable row level security;

create policy target_connection_tests_admin_read on public.target_connection_tests
  for select using (public.is_admin());

create unique index target_connection_tests_one_active_per_target
  on public.target_connection_tests(target_id)
  where status in ('queued', 'running');

create index target_connection_tests_claim_idx
  on public.target_connection_tests(status, created_at)
  where status = 'queued';

create or replace function public.claim_target_connection_test(p_worker_id text)
returns setof public.target_connection_tests
language plpgsql
security definer
set search_path = public
as $$
declare
  claimed public.target_connection_tests%rowtype;
begin
  update public.target_connection_tests test
  set status = 'running',
      worker_id = p_worker_id,
      locked_at = now(),
      heartbeat_at = now(),
      started_at = coalesce(test.started_at, now()),
      error = null
  where test.id = (
    select candidate.id
    from public.target_connection_tests candidate
    join public.targets target_row on target_row.id = candidate.target_id
    where candidate.status = 'queued'
      and candidate.retry_count <= candidate.max_retries
      and not exists (
        select 1 from public.executions running
        where running.target_id = candidate.target_id
          and running.status = 'running'
      )
    order by candidate.created_at asc
    for update of candidate, target_row skip locked
    limit 1
  )
  returning * into claimed;

  if claimed.id is not null then
    return next claimed;
  end if;
end;
$$;

create or replace function public.mark_interrupted_connection_tests(p_stale_seconds integer default 300)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  affected integer;
begin
  with stale as (
    update public.target_connection_tests
    set status = case when retry_count < max_retries then 'queued' else 'failed' end,
        retry_count = case when retry_count < max_retries then retry_count + 1 else retry_count end,
        interrupted = true,
        error = 'Worker heartbeat expired.',
        worker_id = null,
        locked_at = null,
        heartbeat_at = null,
        finished_at = case when retry_count < max_retries then finished_at else now() end
    where status = 'running'
      and heartbeat_at is not null
      and heartbeat_at < now() - make_interval(secs => p_stale_seconds)
    returning target_id, status
  )
  update public.targets target
  set last_tested_at = now(),
      last_test_status = 'failed',
      last_test_message = 'Worker heartbeat expired during connection test.',
      enabled = case when stale.status = 'failed' then false else target.enabled end,
      disabled_reason = case when stale.status = 'failed' then 'Connection test worker was interrupted.' else target.disabled_reason end
  from stale
  where target.id = stale.target_id
    and stale.status = 'failed';

  get diagnostics affected = row_count;
  return affected;
end;
$$;

-- Connection tests and executions share the same per-target lease.
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
    join public.targets target_row on target_row.id = candidate.target_id
    where candidate.status = 'queued'
      and candidate.confirmed_at is not null
      and candidate.retry_count <= candidate.max_retries
      and not exists (
        select 1 from public.executions running
        where running.target_id = candidate.target_id
          and running.status = 'running'
      )
      and not exists (
        select 1 from public.target_connection_tests running_test
        where running_test.target_id = candidate.target_id
          and running_test.status = 'running'
      )
      and (
        candidate.locked_at is null
        or candidate.heartbeat_at is null
        or candidate.heartbeat_at < now() - make_interval(secs => p_lock_seconds)
      )
    order by candidate.created_at asc
    for update of candidate, target_row skip locked
    limit 1
  )
  returning * into claimed;

  if claimed.id is not null then
    return next claimed;
  end if;
end;
$$;

revoke execute on function public.claim_target_connection_test(text) from public;
revoke execute on function public.mark_interrupted_connection_tests(integer) from public;
revoke execute on function public.claim_execution(text, integer) from public;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    grant execute on function public.claim_target_connection_test(text) to service_role;
    grant execute on function public.mark_interrupted_connection_tests(integer) to service_role;
    grant execute on function public.claim_execution(text, integer) to service_role;
  end if;
end;
$$;

comment on table public.target_connection_tests is
  'Auditable worker-only SSH connection tests used before enabling targets.';
