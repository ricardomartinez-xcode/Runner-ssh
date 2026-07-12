-- Limit executable targets to SSH and Cloudflare Tunnel, and allow
-- private-key-plus-password SSH credentials.

update public.targets
set
  type = 'ssh',
  enabled = false,
  disabled_reason = coalesce(disabled_reason, 'Target type retired; recreate as SSH or Cloudflare Tunnel before enabling.'),
  updated_at = now()
where type not in ('ssh', 'cloudflare_tunnel');

update public.targets
set
  auth_type = 'private_key',
  enabled = false,
  disabled_reason = coalesce(disabled_reason, 'Token SSH authentication is retired; rotate to key, password, or key plus password before enabling.'),
  updated_at = now()
where auth_type = 'token';

alter table public.targets
  drop constraint if exists targets_type_check;

alter table public.targets
  add constraint targets_type_check
  check (type in ('ssh', 'cloudflare_tunnel'));

alter table public.targets
  drop constraint if exists targets_auth_type_check;

alter table public.targets
  add constraint targets_auth_type_check
  check (auth_type in ('private_key', 'password', 'private_key_password', 'agent'));
