# Security model

This project intentionally has no `ssh.exec`, arbitrary shell command, arbitrary hostname, arbitrary username, arbitrary password, private-key or dynamic `op://` input.

Only exact `argv` arrays in `config/runner.yaml` are executable. The API flow is:

```text
list -> plan -> literal EJECUTAR -> execute -> read redacted log
```

## Required practices

1. Use a dedicated Keycloak client and minimal roles.
2. Use one 1Password Service Account per environment with read access only to required vaults.
3. Pin every SSH host key in `known_hosts`; never set `StrictHostKeyChecking=no`.
4. Prefer dedicated target SSH accounts and SSH keys or certificates. Password mode is legacy-only, fetched from a preconfigured secret reference.
5. Do not expose a laptop's SSH server publicly. Use VPN/Tailscale/WireGuard or a controlled outbound tunnel.
6. Keep target system operations behind a target-local allowlist wrapper.
7. Treat persistent job logs as operational data; they are redacted and bounded but not an immutable SIEM.
8. Run one Render instance when using the included file-backed job store.

## Target-local wrapper

Install a restricted `/usr/local/bin/runner-task` on a server:

```bash
#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  system-info) uname -a ;;
  service-status) systemctl --no-pager --full status caddy ;;
  docker-ps) docker ps --format 'table {{.Names}}	{{.Image}}	{{.Status}}' ;;
  *) echo "Task not allowed." >&2; exit 64 ;;
esac
```

Do not pass arbitrary arguments into a shell, `sudo`, Docker or systemctl.
