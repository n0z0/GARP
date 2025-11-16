# GARP

Gratuitous ARP

```sh
# Untuk mengumumkan bahwa IP 192.168.1.123 ada di MAC aa:bb:cc:dd:ee:ff
sudo go run arp_announce.go -iface eth0 -ip 192.168.1.123 -mac aa:bb:cc:dd:ee:ff
```
