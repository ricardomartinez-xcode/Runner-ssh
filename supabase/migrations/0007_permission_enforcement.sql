-- Keep organization membership roles aligned with profiles while preserving
-- explicit environment grants managed by administrators.

create or replace function public.sync_profile_organization_member()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.organization_members (user_id, role, environments, updated_at)
  values (
    new.id,
    new.role,
    case when new.role = 'admin' then array['prod', 'staging', 'dev']::text[] else array['dev']::text[] end,
    now()
  )
  on conflict (user_id) do update
  set role = excluded.role,
      updated_at = now();
  return new;
end;
$$;

drop trigger if exists sync_profile_organization_member on public.profiles;
create trigger sync_profile_organization_member
after insert or update of role on public.profiles
for each row execute function public.sync_profile_organization_member();

insert into public.organization_members (user_id, role, environments, updated_at)
select
  id,
  role,
  case when role = 'admin' then array['prod', 'staging', 'dev']::text[] else array['dev']::text[] end,
  now()
from public.profiles
on conflict (user_id) do update
set role = excluded.role,
    updated_at = now();

comment on function public.sync_profile_organization_member() is
  'Synchronizes profile roles without broadening existing explicit environment grants.';
