sudo -v

# Currently only supports IPv4
echo "Disabling ipv6 (currently not supported)"
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1

resolvectl flush-caches

go generate
go build

# Update ifname here
sudo ./ebpfocus wlo1