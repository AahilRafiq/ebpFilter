sudo -v

# Flush local DNS cache
resolvectl flush-caches

go generate
go build

# Update ifname here
sudo ./ebpfocus wlo1