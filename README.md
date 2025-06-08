# IPIP Tunnel with eBPF

This is an educational example of implementing an IPIP (IP-in-IP) tunnel using eBPF and TC (Traffic Control).

## Overview

This project demonstrates how to implement an IPIP tunnel using Linux TC (Traffic Control) and eBPF for educational purposes.

## Files

- `ipip.c` - eBPF program for packet encapsulation/decapsulation
- `ipip.yml` - Tunnel configuration file
- `Makefile` - Build and setup automation

## Configuration

Configure the tunnel in `ipip.yml`:

```yaml
tunnel:
  transport_nic: ens7           # Physical network interface
  dest_cidr: 192.168.1.0/24     # Subnet to tunnel
  local_addr: 10.0.0.1          # Local tunnel endpoint
  remote_addr: 10.0.0.2         # Remote tunnel endpoint
```

## Usage

### Build and Setup
```bash
make                          # Build and load everything
make config                   # Show current configuration
```

### Cleanup
```bash
make clean                    # Clean up configuration
```

### Tracing
```bash
make trace                    # Show eBPF program logs
```

## How it Works

1. **Encapsulation**: Packets destined for the specified subnet are encapsulated with IPIP
2. **Decapsulation**: Incoming IPIP packets are decapsulated

## Note

**This is an educational example.** Not intended for production use.