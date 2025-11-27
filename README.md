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
0. Commands to install the required dependencies:

   Ubuntu/Debian
   ```bash
   sudo apt-get update
   sudo apt-get install libbpf-dev clang llvm libelf-dev zlib1g-dev gcc linux-headers
   
   sudo apt update
   sudo apt install net-tools
   ```
   
   Fedora/CentOS/RHEL 8+
   ```bash
   sudo dnf update
   sudo dnf install -y libbpf-devel clang llvm elfutils-libelf-devel zlib-devel gcc net-tools bc kernel-devel
   ```

2. Clone the repository:
   ```bash
   git clone https://github.com/AahilRafiq/ebpFilter.git
   cd ebpFilter
   ```

3. Install Go dependencies:
   ```bash
   go mod download
   ```

4. Generate eBPF code and build:
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

## Screenshots
<img width="600" height="600" alt="image" src="https://github.com/user-attachments/assets/bbbfb113-9c25-4b3f-9fd4-8446bc7dcb08" />
<img width="1312" height="628" alt="image" src="https://github.com/user-attachments/assets/cc596cba-ee41-4d1d-a3a8-53a4ee7a8e1e" />

