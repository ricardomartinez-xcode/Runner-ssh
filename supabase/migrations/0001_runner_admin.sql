-- Runner Admin Supabase schema
-- Apply in Supabase SQL editor or through the Supabase CLI.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  full_name text,
  role text not null default 'viewer' check (role in ('admin', 'operator', 'viewer')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.targets (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  type text not null check (type in ('ssh', 'codespace', 'tailscale', 'cloudflare_tunnel', 'local')),
  host text not null,
  port integer not null default 22 check (port between 1 and 65535),
  username text not null,
  auth_type text not null default 'private_key' check (auth_type in ('private_key', 'password', 'agent', 'token')),
  secret_ref text,
  tags text[] not null default '{}',
  working_directory text,
  enabled boolean not null default true,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.commands (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  command_template text not null,
  risk_level text not null default 'low' check (risk_level in ('low', 'medium', 'high')),
  requires_approval boolean not null default false,
  allowed_roles text[] not null default '{admin,operator}',
  enabled boolean not null default true,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.target_commands (
  target_id uuid not null references public.targets(id) on delete cascade,
  command_id uuid not null references public.commands(id) on delete cascade,
  primary key (target_id, command_id)
);

create table if not exists public.executions (
  id uuid primary key default gen_random_uuid(),
  target_id uuid not null references public.targets(id) on delete restrict,
  command_id uuid not null references public.commands(id) on delete restrict,
  requested_by uuid references auth.users(id) on delete set null,
  status text not null default 'queued' check (status in ('queued', 'running', 'succeeded', 'failed', 'cancelled', 'approval_required')),
  command_rendered text,
  stdout text,
  stderr text,
  exit_code integer,
  error text,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.health_checks (
  id uuid primary key default gen_random_uuid(),
  target_id uuid not null references public.targets(id) on delete cascade,
  status text not null check (status in ('online', 'offline', 'degraded', 'unknown')),
  latency_ms integer,
  cpu_percent numeric,
  ram_percent numeric,
  disk_percent numeric,
  message text,
  checked_at timestamptz not null default now()
);

create table if not exists public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  actor_id uuid references auth.users(id) on delete set null,
  action text not null,
  entity_type text not null,
  entity_id uuid,
  metadata jsonb not null default '{}',
  created_at timestamptz not null default now()
);

create or replace function public.current_role()
returns text
language sql
stable
as $$
  select coalesce((select role from public.profiles where id = auth.uid()), 'viewer')
$$;

create or replace function public.is_admin()
returns boolean
language sql
stable
as $$
  select public.current_role() = 'admin'
$$;

create or replace function public.is_operator()
returns boolean
language sql
stable
as $$
  select public.current_role() in ('admin', 'operator')
$$;

alter table public.profiles enable row level security;
alter table public.targets enable row level security;
alter table public.commands enable row level security;
alter table public.target_commands enable row level security;
alter table public.executions enable row level security;
alter table public.health_checks enable row level security;
alter table public.audit_logs enable row level security;

create policy profiles_read_own_or_admin on public.profiles for select using (id = auth.uid() or public.is_admin());
create policy profiles_admin_write on public.profiles for all using (public.is_admin()) with check (public.is_admin());

create policy targets_read_authenticated on public.targets for select using (auth.uid() is not null);
create policy targets_admin_write on public.targets for all using (public.is_admin()) with check (public.is_admin());

create policy commands_read_authenticated on public.commands for select using (auth.uid() is not null);
create policy commands_admin_write on public.commands for all using (public.is_admin()) with check (public.is_admin());

create policy target_commands_read_authenticated on public.target_commands for select using (auth.uid() is not null);
create policy target_commands_admin_write on public.target_commands for all using (public.is_admin()) with check (public.is_admin());

create policy executions_read_authenticated on public.executions for select using (auth.uid() is not null);
create policy executions_operator_insert on public.executions for insert with check (public.is_operator());
create policy executions_admin_update on public.executions for update using (public.is_admin()) with check (public.is_admin());

create policy health_read_authenticated on public.health_checks for select using (auth.uid() is not null);
create policy health_admin_write on public.health_checks for all using (public.is_admin()) with check (public.is_admin());

create policy audit_read_admin on public.audit_logs for select using (public.is_admin());
create policy audit_insert_operator on public.audit_logs for insert with check (public.is_operator());

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, full_name, role)
  values (
    new.id,
    coalesce(new.email, ''),
    coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name'),
    'viewer'
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

insert into public.commands (name, description, command_template, risk_level, requires_approval, allowed_roles)
values
  ('whoami', 'Muestra el usuario remoto activo.', 'whoami', 'low', false, '{admin,operator,viewer}'),
  ('uptime', 'Muestra disponibilidad y carga del target.', 'uptime', 'low', false, '{admin,operator,viewer}'),
  ('disk usage', 'Muestra uso de disco.', 'df -h', 'low', false, '{admin,operator,viewer}'),
  ('docker ps', 'Lista contenedores Docker.', 'docker ps', 'medium', false, '{admin,operator}'),
  ('git pull', 'Actualiza el repositorio en el directorio de trabajo.', 'git pull --ff-only', 'medium', false, '{admin,operator}'),
  ('docker compose up', 'Levanta servicios con Docker Compose.', 'docker compose up -d', 'high', true, '{admin}')
on conflict do nothing;
