# Tailscale

## Decision

ReLead Ops production target connectivity is limited to direct SSH and SSH through Cloudflare Tunnel. It does not expose "Tailscale" as a direct target type in the UI for Render.

Reason: a Render Docker service cannot be assumed to have a persistent tailnet interface like `tailscale0`. Tailscale userspace networking is designed for containers without a tun device, but it behaves as a userspace proxy path and needs explicit process wiring. A normal `ssh 100.x.y.z` from the app container is reliable only when the worker process itself has real tailnet connectivity.

Supported pattern today, only for explicitly verified networks:

- Create the target as `SSH normal`.
- Use a Tailscale IP or MagicDNS name only when `relead-ops-worker` is confirmed to reach the tailnet.
- Keep `known_hosts` pinned for the actual host and port.

Recommended production alternative:

- Cloudflare Tunnel to the private SSH service, using a pinned SSH host key and a target type of `cloudflare_tunnel`.

## Render Notes

Direct Tailscale in Render would require one of:

- userspace networking and a SOCKS/HTTP proxy path;
- a sidecar/proxy process supervised with the app;
- OAuth client or ephemeral auth key rotation;
- secure state handling for node identity;
- MagicDNS resolution support in the container.

This repository does not ship that direct node mode because leaving a visible target option that cannot execute reliably is worse than requiring a documented bastion/tunnel.

## Variables If You Build A Tailnet Worker Later

Do not commit these:

```env
TS_AUTHKEY=
TS_OAUTH_CLIENT_ID=
TS_OAUTH_CLIENT_SECRET=
TS_HOSTNAME=relead-ops-worker
TS_STATE_DIR=/var/data/tailscale
TS_USERSPACE=true
```

## Diagnostics

From inside the worker:

```bash
tailscale status
tailscale ip -4
getent hosts target-name
ssh -p 2222 user@100.x.y.z true
```

## References

- Tailscale userspace networking: https://tailscale.com/docs/concepts/userspace-networking
- Tailscale Docker containers: https://tailscale.com/docs/features/containers/docker
- Tailscale Docker parameters: https://tailscale.com/docs/features/containers/docker/docker-params
- Render Docker services: https://render.com/docs/docker
