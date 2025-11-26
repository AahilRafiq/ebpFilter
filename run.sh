sudo -v
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1

resolvectl flush-caches

go generate
go build

sudo ./ebpfocus