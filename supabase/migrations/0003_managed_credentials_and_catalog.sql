-- ReLead Ops managed credentials and expanded command catalog.

create table if not exists public.target_secrets (
  id uuid primary key default gen_random_uuid(),
  target_id uuid not null unique references public.targets(id) on delete cascade,
  ciphertext text not null,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.target_secrets enable row level security;

-- No client policies are intentionally created. Only the backend service key can
-- read or write encrypted credential envelopes.

alter table public.commands
  add column if not exists catalog_key text;

create unique index if not exists commands_catalog_key_unique
  on public.commands(catalog_key)
  where catalog_key is not null;

comment on table public.target_secrets is
  'AES-256-GCM encrypted target credentials. The encryption key exists only in the ReLead Ops backend.';

comment on column public.commands.catalog_key is
  'Stable key for commands installed from the ReLead Ops recommended catalog.';
