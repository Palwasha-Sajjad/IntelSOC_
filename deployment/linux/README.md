# IntelSOC Linux Deployment Kit

Required bundle contents:

- `install-intelsoc-agent.sh`
- `intelsoc-caddy-root.crt`

Run the read-only preflight first:

```bash
sudo bash install-intelsoc-agent.sh --dry-run
```

For an already enrolled IntelSOC endpoint, inspect and back up the existing
configuration, then use the guarded migration option:

```bash
sudo bash install-intelsoc-agent.sh --migrate-existing
```

The installer collects the approved Linux telemetry only: SSH journald, sudo
journald, account/group audit events, and narrowly keyed identity-file changes.
Broad process EXECVE auditing remains disabled until separately approved.
