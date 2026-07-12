-- Run after all migrations in a Supabase-compatible database.

do $$
declare
  forbidden_policy text;
begin
  select policyname
  into forbidden_policy
  from pg_policies
  where schemaname = 'public'
    and policyname in (
      'profiles_admin_write',
      'targets_admin_write',
      'commands_admin_write',
      'target_commands_admin_write',
      'executions_operator_insert',
      'executions_admin_update',
      'health_admin_write',
      'audit_insert_operator',
      'organization_members_admin_write',
      'target_permissions_admin_write',
      'command_permissions_admin_write',
      'execution_log_events_admin_write'
    )
  limit 1;

  if forbidden_policy is not null then
    raise exception 'Browser mutation policy still exists: %', forbidden_policy;
  end if;

  if has_function_privilege('authenticated', 'public.claim_execution(text,integer)', 'execute') then
    raise exception 'authenticated must not execute claim_execution';
  end if;

  if has_function_privilege('anon', 'public.claim_execution(text,integer)', 'execute') then
    raise exception 'anon must not execute claim_execution';
  end if;

  if not has_function_privilege('service_role', 'public.claim_execution(text,integer)', 'execute') then
    raise exception 'service_role must execute claim_execution';
  end if;

  if has_function_privilege('authenticated', 'public.mark_interrupted_executions(integer)', 'execute') then
    raise exception 'authenticated must not execute mark_interrupted_executions';
  end if;

  if has_function_privilege('authenticated', 'public.claim_target_connection_test(text)', 'execute') then
    raise exception 'authenticated must not execute claim_target_connection_test';
  end if;

  if not has_function_privilege('service_role', 'public.claim_target_connection_test(text)', 'execute') then
    raise exception 'service_role must execute claim_target_connection_test';
  end if;
end;
$$;

grant usage on schema public to authenticated;
grant insert on public.executions to authenticated;

set role authenticated;

do $$
begin
  begin
    insert into public.executions (target_id, command_id, status)
    values (gen_random_uuid(), gen_random_uuid(), 'queued');
    raise exception 'authenticated insert unexpectedly passed RLS';
  exception
    when insufficient_privilege then null;
  end;
end;
$$;

reset role;

select 'backend-only RLS checks passed' as result;
