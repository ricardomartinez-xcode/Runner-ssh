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
- Firewall: `ufw` service is active; full rules were not changed

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

Loopback test:

```bash
ssh -i /home/ricardo/.ssh/relead_ops_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -p 2222 ricardo@127.0.0.1 'whoami && hostname && uptime && df -h /'
```

Returned:

```text
ricardo
releadserver
up 10 days...
/dev/mapper/ubuntu--vg-ubuntu--lv 26G 11G 15G 43% /
```

Tailscale IP test:

```bash
ssh -i /home/ricardo/.ssh/relead_ops_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new -p 2222 ricardo@100.96.199.114 'whoami && hostname && uptime && df -h /'
```

Returned the same successful result.

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

## Why It Is Not Registered Yet

This Codex session does not have:

```text
SUPABASE_URL
SUPABASE_PUBLISHABLE_KEY
SUPABASE_SECRET_KEY
SSH_KEY_ENCRYPTION_SECRET
```

Because those are missing, the target could not be written to Supabase and the private key could not be stored as a managed encrypted ReLead Ops credential from this environment.

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
system.identity
system.hostname
system.uptime
system.disk
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
