# ReleadServer Setup

## Detected System

- Name: `ReleadServer`
- Hostname: `releadserver`
- OS: Ubuntu 26.04 LTS
- Kernel: `7.0.0-27-generic`
- User: `ricardo`
- LAN IP: `192.168.3.32`
- Tailscale IP: `100.96.199.114`
- SSH service: installed, enabled and active
- SSH port: `2222`
- Root login: disabled
- Pubkey auth: enabled
- Password auth: enabled in current `sshd_config`
- Firewall: `ufw` service is active; SSH `2222/tcp` is allowed only from LAN `192.168.3.0/24` and Tailscale `100.64.0.0/10`
- Tailscale: active and online
- Cloudflare Tunnel: `cloudflared` installed, tunnel authentication/configuration pending

## What Was Changed

A dedicated ed25519 keypair was created locally:

```text
Private key: /home/ricardo/.ssh/relead_ops_ed25519
Public key:  /home/ricardo/.ssh/relead_ops_ed25519.pub
```

Only the public key was appended to:

```text
/home/ricardo/.ssh/authorized_keys
```

No firewall rule was changed. SSH root login was not enabled. `StrictHostKeyChecking` was not disabled.

`cloudflared` was installed locally:

```text
cloudflared version 2026.7.1
```

No Cloudflare Tunnel was created yet because this session does not have a Cloudflare Tunnel token or an authenticated `cert.pem`. `cloudflared.service` is not installed and no `cloudflared` process is running. Do not create an unauthenticated quick tunnel for production SSH.

A separate Render break-glass key and offline recovery material were created outside the repository:

```text
Private SSH key: /home/ricardo/.ssh/relead_ops_render_break_glass_ed25519
Public SSH key:  /home/ricardo/.ssh/relead_ops_render_break_glass_ed25519.pub
Recovery key:    /home/ricardo/.config/relead-ops/break-glass-recovery-key
Recovery digest: /home/ricardo/.config/relead-ops/break-glass-recovery-key.sha256
Session secret:  /home/ricardo/.config/relead-ops/break-glass-session-secret
```

Private/recovery files are mode `0600`. The public-key fingerprint is:

```text
SHA256:SBgT0FE/vUm7JbUGyIxnyRr/eRGufQDiUGF3635W9sg
```

This key has not yet been added to the Render account and `/bash` remains disabled. Render CLI `v2.21.0` is installed at `/home/ricardo/.local/bin/render`; account authorization and discovery of the real worker service ID are still required before the proxy can connect.

When a Cloudflare Tunnel token for tunnel `relead` is available, install the service on this host with:

```bash
sudo cloudflared service install '<CLOUDFLARE_TUNNEL_TOKEN>'
```

If the hostname is protected by Cloudflare Access, configure these Render secrets for `relead-ops-web` and `relead-ops-worker`:

```env
TUNNEL_SERVICE_TOKEN_ID=
TUNNEL_SERVICE_TOKEN_SECRET=
```

Then route the tunnel hostname to:

```text
ssh://localhost:2222
```

## Verified SSH Results

Last verified: 2026-07-12.

Loopback test:

```bash
ssh -i /home/ricardo/.ssh/relead_ops_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -p 2222 ricardo@127.0.0.1 'whoami && hostname && uptime && df -h /'
```

Returned:

```text
ricardo
releadserver
11:20:09 up 12 days, 6:03, load average: 1.21, 0.60, 0.23
/dev/mapper/ubuntu--vg-ubuntu--lv 26G 14G 11G 57% /
```

Tailscale IP test:

```bash
ssh -i /home/ricardo/.ssh/relead_ops_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -p 2222 ricardo@100.96.199.114 'whoami && hostname && uptime && df -h /'
```

Returned the same successful result.

Host key fingerprint from `ssh-keyscan -T 7 -p 2222 100.96.199.114`:

```text
256 SHA256:YupRBSxFaOWMWiE/6VFyWNDlWFCddh+oRV3be+C8rDo [100.96.199.114]:2222 (ED25519)
```

Firewall status:

```text
Status: active
Default: deny (incoming), allow (outgoing), deny (routed)
2222/tcp ALLOW IN 100.64.0.0/10
2222/tcp ALLOW IN 192.168.3.0/24
22/tcp ALLOW IN 100.64.0.0/10
22/tcp on tailscale0 ALLOW IN Anywhere
```

## known_hosts

Use the ed25519 host key for the target:

```text
[100.96.199.114]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO7xy42Z7/5Jjot1uQbdYNaSBP+lCsVTq5TUK2BZ0KIi
```

## ReLead Ops Target Draft

Target name:

```text
ReleadServer
```

Recommended fields:

```json
{
  "name": "ReleadServer",
  "type": "cloudflare_tunnel",
  "host": "REPLACE_WITH_CLOUDFLARE_SSH_HOSTNAME",
  "port": 22,
  "username": "ricardo",
  "environment": "dev",
  "auth_type": "private_key_password",
  "credential_source": "managed",
  "known_hosts": "REPLACE_WITH_CLOUDFLARE_SSH_HOSTNAME ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO7xy42Z7/5Jjot1uQbdYNaSBP+lCsVTq5TUK2BZ0KIi",
  "tags": ["releadserver", "cloudflare-tunnel", "ssh", "dev"],
  "enabled": false
}
```

Keep it disabled until the Cloudflare Tunnel hostname is created, `known_hosts` is captured for that hostname, and the Render worker is confirmed to reach it with strict host checking.

## Current Registration Status

SSH on this computer is configured and verified. The target is not yet registered in ReLead Ops production. Credentials pasted into a chat are treated as exposed, were not copied into the repository or local environment, and must be rotated before production use. This session also lacks a verified Supabase migration connection and the active Render/Cloudflare configuration needed to complete the end-to-end path.

The required server-side values remain:

```text
SUPABASE_SECRET_KEY
SSH_KEY_ENCRYPTION_SECRET
```

The Supabase secret API key alone does not provide a PostgreSQL migration connection. Apply SQL through a linked Supabase CLI session, the SQL editor, or a database connection after rotating the exposed key. Without a verified `SSH_KEY_ENCRYPTION_SECRET`, the private key must not be persisted as a managed credential. As an alternative, store the dedicated SSH credential as a rotated Render secret named `RELEADSERVER_SSH_CREDENTIAL` and set the target credential source to Render environment variable.

Render connectivity is also not proven. The host is reachable over LAN and Tailscale, but production ReLead Ops should use Cloudflare Tunnel plus SSH for this target. `cloudflared` is installed, but no tunnel service is configured yet because no Cloudflare Tunnel token or authenticated Cloudflare certificate is available in this session.

Do not mark `ReleadServer` enabled in production until the worker can run this exact test successfully from its runtime network:

```bash
ssh -i "$RELEADSERVER_SSH_KEY_FILE" \
  -o ProxyCommand='cloudflared access ssh --hostname %h' \
  -o IdentitiesOnly=yes \
  -o BatchMode=no \
  -o StrictHostKeyChecking=yes \
  -p 22 \
  ricardo@REPLACE_WITH_CLOUDFLARE_SSH_HOSTNAME \
  'whoami && hostname && uptime && df -h /'
```

## How To Store The Secret

Preferred Render variable:

```text
RELEADSERVER_SSH_CREDENTIAL
```

For `private_key_password`, set the variable value to JSON:

```json
{
  "private_key": "PRIVATE_KEY_CONTENT",
  "password": "SSH_PASSWORD"
}
```

Use the private key content from:

```text
/home/ricardo/.ssh/relead_ops_ed25519
```

Do not commit or paste the private key or password into docs, logs or PR text.

## Assign Low-Risk Commands

After creating the target, assign:

```text
System identity
Hostname
Uptime
Disk usage
```

Then execute:

```text
whoami
hostname
uptime
df -h
```

## Revocation

1. Disable target `ReleadServer`.
2. Remove the `relead-ops-target:ReleadServer` public key line from `/home/ricardo/.ssh/authorized_keys`.
3. Delete `RELEADSERVER_SSH_KEY` from Render.
4. Delete the target after audit review.
