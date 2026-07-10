-- ReLead Ops SSH execution support

alter table public.targets
  add column if not exists known_hosts text;

alter table public.executions
  add column if not exists approved_by uuid references auth.users(id) on delete set null,
  add column if not exists approved_at timestamptz,
  add column if not exists duration_ms integer;

create index if not exists executions_status_created_at_idx
  on public.executions(status, created_at desc);

create index if not exists health_checks_target_checked_at_idx
  on public.health_checks(target_id, checked_at desc);

create index if not exists audit_logs_created_at_idx
  on public.audit_logs(created_at desc);

comment on column public.targets.secret_ref is
  'Server-side credential reference. Supported formats: ENV:VARIABLE_NAME, RENDER_ENV:VARIABLE_NAME, or 1PASSWORD:op://vault/item/field.';

comment on column public.targets.known_hosts is
  'OpenSSH known_hosts entry used for strict host key verification.';
