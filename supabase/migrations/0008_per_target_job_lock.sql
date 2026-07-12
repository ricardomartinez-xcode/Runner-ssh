-- Serialize SSH executions per target while preserving global worker concurrency.

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
        select 1
        from public.executions running
        where running.target_id = candidate.target_id
          and running.status = 'running'
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

comment on function public.claim_execution(text, integer) is
  'Atomically claims one confirmed execution and serializes active jobs per target.';
