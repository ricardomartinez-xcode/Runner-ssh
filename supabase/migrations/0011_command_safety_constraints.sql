-- Normalize legacy dangerous commands and enforce approval invariants in SQL.

update public.commands
set risk_level = 'high',
    requires_approval = true,
    allowed_roles = array['admin']::text[],
    destructive = true
where catalog_key is null
   or destructive = true
   or risk_level = 'high'
   or command_template ~* '(^|[[:space:]])(rm|mv|dd|mkfs|shutdown|reboot|poweroff|halt|kill|pkill|systemctl[[:space:]]+(restart|stop|disable)|docker.*(prune|down|restart|rm|up|pull)|git[[:space:]]+(pull|reset|clean|checkout)|apt(-get)?[[:space:]]+(upgrade|dist-upgrade|autoremove|install|remove)|npm[[:space:]]+(run|test|exec|ci|install)|npx)([[:space:]]|$)';

create or replace function public.enforce_command_safety()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  if new.catalog_key is null then
    new.risk_level := 'high';
  end if;

  if new.command_template ~* '(^|[[:space:]])(rm|mv|dd|mkfs|shutdown|reboot|poweroff|halt|kill|pkill|systemctl[[:space:]]+(restart|stop|disable)|docker.*(prune|down|restart|rm|up|pull)|git[[:space:]]+(pull|reset|clean|checkout)|apt(-get)?[[:space:]]+(upgrade|dist-upgrade|autoremove|install|remove)|npm[[:space:]]+(run|test|exec|ci|install)|npx)([[:space:]]|$)' then
    new.risk_level := 'high';
    new.destructive := true;
  end if;

  if new.risk_level = 'high' or new.destructive = true then
    new.risk_level := 'high';
    new.requires_approval := true;
    new.allowed_roles := array['admin']::text[];
  end if;
  return new;
end;
$$;

drop trigger if exists enforce_command_safety on public.commands;
create trigger enforce_command_safety
before insert or update of catalog_key, command_template, risk_level, requires_approval, allowed_roles, destructive
on public.commands
for each row execute function public.enforce_command_safety();

revoke execute on function public.enforce_command_safety() from public;

alter table public.commands
  drop constraint if exists commands_high_risk_approval_check;

alter table public.commands
  add constraint commands_high_risk_approval_check
  check (
    (risk_level <> 'high' and destructive = false)
    or (
      risk_level = 'high'
      and requires_approval = true
      and allowed_roles = array['admin']::text[]
    )
  );

comment on constraint commands_high_risk_approval_check on public.commands is
  'High-risk, destructive, and non-catalog commands require explicit approval and admin-only execution.';
