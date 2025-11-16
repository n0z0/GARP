package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// 1. Definisikan dan parse flag dari command-line
	ifaceName := flag.String("iface", "eth0", "Nama network interface (e.g., eth0, wlan0)")
	ipStr := flag.String("ip", "", "IP address yang akan diumumkan (wajib)")
	macStr := flag.String("mac", "", "MAC address yang akan diumumkan (wajib)")
	flag.Parse()

	if *ipStr == "" || *macStr == "" {
		log.Fatal("Error: Flag -ip dan -mac wajib diisi.")
	}

	// 2. Parsing IP dan MAC address
	ip := net.ParseIP(*ipStr)
	if ip == nil {
		log.Fatalf("Error: IP address '%s' tidak valid.", *ipStr)
	}
	// Pastikan IPv4
	ip = ip.To4()
	if ip == nil {
		log.Fatal("Error: Hanya mendukung alamat IPv4.")
	}

	mac, err := net.ParseMAC(*macStr)
	if err != nil {
		log.Fatalf("Error: MAC address '%s' tidak valid: %v", *macStr, err)
	}

	// 3. Cari network interface yang digunakan
	iface, err := findInterface(*ifaceName)
	if err != nil {
		log.Fatalf("Error: Tidak bisa menemukan interface %s: %v", *ifaceName, err)
	}

	// 4. Buat dan kirim paket ARP
	err = sendGratuitousARP(iface, ip, mac)
	if err != nil {
		log.Fatalf("Error: Gagal mengirim paket ARP: %v", err)
	}

	fmt.Printf("✅ Berhasil mengirim broadcast ARP untuk %s -> %s dari interface %s\n", ip, mac, iface.Name)
}

// findInterface mencari network interface berdasarkan nama
func findInterface(name string) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, i := range ifaces {
		if i.Name == name {
			return &i, nil
		}
	}
	return nil, errors.New("interface tidak ditemukan")
}

// sendGratuitousARP membangun dan mengirimkan paket Gratuitous ARP
func sendGratuitousARP(iface *net.Interface, sourceIP net.IP, sourceMAC net.HardwareAddr) error {
	// Buka handle untuk menulis paket mentah ke interface
	handle, err := pcap.OpenLive(iface.Name, 65536, false, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	// Siapkan layer Ethernet
	// Destination MAC adalah broadcast address (ff:ff:ff:ff:ff:ff)
	ethLayer := &layers.Ethernet{
		SrcMAC:       sourceMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	// Siapkan layer ARP
	// Ini adalah ARP Reply (Operation: 2) yang dikirim tanpa permintaan (gratuitous)
	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply, // Ini adalah kunci untuk Gratuitous ARP
		SourceHwAddress:   sourceMAC,
		SourceProtAddress: sourceIP,
		DstHwAddress:      net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Broadcast
		DstProtAddress:    sourceIP,                                             // Target IP adalah IP itu sendiri
	}

	// Serialize layers menjadi buffer byte
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buf, opts, ethLayer, arpLayer)
	if err != nil {
		return err
	}

	// Kirim paket
	return handle.WritePacketData(buf.Bytes())
}
