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
- Cloudflare Tunnel: not installed or configured on this host

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
  "type": "ssh",
  "host": "100.96.199.114",
  "port": 2222,
  "username": "ricardo",
  "environment": "dev",
  "auth_type": "private_key",
  "credential_source": "environment",
  "environment_variable": "RELEADSERVER_SSH_KEY",
  "known_hosts": "[100.96.199.114]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO7xy42Z7/5Jjot1uQbdYNaSBP+lCsVTq5TUK2BZ0KIi",
  "tags": ["releadserver", "tailscale", "dev"],
  "enabled": false
}
```

Keep it disabled until the Render worker is confirmed to reach `100.96.199.114:2222`.

## Current Registration Status

SSH on this computer is configured and verified. The target is not yet registered in ReLead Ops production from this Codex session because the session does not have the required administrative credentials:

```text
SUPABASE_SECRET_KEY
SSH_KEY_ENCRYPTION_SECRET
```

Without a Supabase service role key, the target cannot be written to Supabase. Without `SSH_KEY_ENCRYPTION_SECRET`, the private key cannot be stored as a managed encrypted ReLead Ops credential from this environment. As an alternative, store the private key as a Render secret named `RELEADSERVER_SSH_KEY` and set the target credential source to Render environment variable.

Render connectivity is also not proven. The host is reachable over LAN and Tailscale, but the Render worker must have real connectivity to the tailnet, a bastion, a subnet router, a Cloudflare Tunnel TCP path, or another approved relay before the target can be enabled. There is no `cloudflared` service or tunnel configured on this host right now.

Do not mark `ReleadServer` enabled in production until the worker can run this exact test successfully from its runtime network:

```bash
ssh -i "$RELEADSERVER_SSH_KEY_FILE" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -p 2222 ricardo@100.96.199.114 'whoami && hostname && uptime && df -h /'
```

## How To Store The Secret

Preferred Render variable:

```text
RELEADSERVER_SSH_KEY
```

Set its value to the private key content from:

```text
/home/ricardo/.ssh/relead_ops_ed25519
```

Do not commit or paste that private key into docs, logs or PR text.

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
