# Proxmox CLI

A flexible command-line interface for managing Proxmox VE servers.

## Features

- Manage VMs: list, info, start, stop, suspend, resume
- Filter by node or tags
- JSON output for scripting
- Use VM ID or name
- Show guest IPs and optional OS/hostname when QGA is enabled

## Installation

```bash
# Install using uv tool
uv tool install .

# If already installed, rebuild from local source each time:
uv tool install . --reinstall

# Or install in development mode
uv pip install -e .
```

## Usage

```bash
# List all VMs
proxmox-cli list

# Get VM info
proxmox-cli info 100

# With guest OS/hostname (requires QEMU Guest Agent)
proxmox-cli info 100 --with-osinfo

# Start a VM
proxmox-cli start 100 --yes

# Stop a VM gracefully
proxmox-cli stop 100 --yes

# JSON output for scripting
proxmox-cli --output json list
```

## Configuration

Create a configuration file at `~/.config/proxmox-cli/config.ini` (an example is in `examples/config.example.ini`):

```ini
[proxmox]
host = your.proxmox.server
port = 8006
user = root@pam
token_name = your-token-name
token_value = your-token-secret
verify_ssl = true

# Optional: Custom CA certificate for self-signed certs
# ca_cert_path = /path/to/ca-cert.pem
```

### Multiple Profiles

You can create multiple profiles for different Proxmox servers:

```ini
[proxmox]
# Default profile
host = homelab.local
token_name = home-token
token_value = home-secret

[production]
host = prod.example.com
token_name = prod-token
token_value = prod-secret
verify_ssl = true
```

Use profiles with: `proxmox-cli --profile production list`

### Environment variables (optional)

- Real environment variables (`PROXMOX_*`) override values from `config.ini`.

### Executable alias

The package also installs a short alias `pve` for convenience:

```bash
pve list
```

### Exit Codes

- 0: Success
- 2: Invalid input
- 3: Not found
- 4: Permission denied
- 5: Timeout
- 6: Server error

## License

MIT
