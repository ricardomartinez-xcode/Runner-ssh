-- Route every audited mutation through the Fastify backend. Browser sessions
-- remain read-only and never receive the Supabase service-role credential.

update public.executions
set status = 'planned'
where confirmed_at is null
  and status in ('queued', 'approval_required');

drop policy if exists profiles_admin_write on public.profiles;
drop policy if exists targets_admin_write on public.targets;
drop policy if exists commands_admin_write on public.commands;
drop policy if exists target_commands_admin_write on public.target_commands;
drop policy if exists executions_operator_insert on public.executions;
drop policy if exists executions_admin_update on public.executions;
drop policy if exists health_admin_write on public.health_checks;
drop policy if exists audit_insert_operator on public.audit_logs;
drop policy if exists organization_members_admin_write on public.organization_members;
drop policy if exists target_permissions_admin_write on public.target_permissions;
drop policy if exists command_permissions_admin_write on public.command_permissions;
drop policy if exists execution_log_events_admin_write on public.execution_log_events;

revoke execute on function public.claim_execution(text, integer) from public;
revoke execute on function public.mark_interrupted_executions(integer) from public;
revoke execute on function public.handle_new_user() from public;
revoke execute on function public.sync_profile_organization_member() from public;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    grant execute on function public.claim_execution(text, integer) to service_role;
    grant execute on function public.mark_interrupted_executions(integer) to service_role;
  end if;
end;
$$;

comment on table public.executions is
  'Execution rows are read through RLS and mutated only by audited Fastify/worker service-role paths.';
