# ebpFilter

An eBPF-based DNS blocking tool for Linux that filters outgoing DNS queries at the kernel level. It provides a web UI for managing blocked domains dynamically.

## Features

- Kernel-level DNS filtering using eBPF (TCX egress hook)
- Web-based UI for managing blocked domains
- Real-time blocking without system restart
- Supports both IPv4 and IPv6

## Prerequisites

- Linux kernel 6.6+ (with TCX support)
- Go 1.25+
- clang/LLVM (for compiling eBPF code)
- Root privileges (for attaching eBPF programs)

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/AahilRafiq/ebpFilter.git
   cd ebpFilter
   ```

2. Install Go dependencies:
   ```bash
   go mod download
   ```

3. Generate eBPF code and build:
   ```bash
   go generate
   go build
   ```

## Running

Run with sudo, specifying your network interface:

```bash
sudo ./ebpfocus <interface_name>
```

For example:
```bash
sudo ./ebpfocus eth0
```

Or use the provided script (update the interface name in `run.sh` first):
```bash
./run.sh
```

The web UI will be available at `http://localhost:3000`.

## Usage

1. Open `http://localhost:3000` in your browser
2. Add domains to block using the input field
3. Remove domains by clicking on them in the list
4. Changes take effect immediately

The blocked domains are persisted in `dnslist.txt`.

## How It Works

The tool attaches an eBPF program to the network interface's egress path. It inspects outgoing UDP packets on port 53 (DNS) and drops queries for blocked domains before they leave the system.

## License

Dual MIT/GPL
