package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// 1. Definisikan dan parse flag dari command-line
	ifaceName := flag.String("iface", "eth0", "Nama network interface (e.g., eth0, wlan0)")
	ipStr := flag.String("ip", "", "IP address yang akan diumumkan (wajib)")
	macStr := flag.String("mac", "", "MAC address yang akan diumumkan (wajib)")
	// Tambahkan flag interval dengan tipe time.Duration
	interval := flag.Duration("interval", 0, "Interval pengiriman dalam detik. Contoh: 30s, 1m. Jika 0, kirim sekali lalu keluar.")
	flag.Parse()

	if *ipStr == "" || *macStr == "" {
		log.Fatal("Error: Flag -ip dan -mac wajib diisi.")
	}

	// 2. Parsing IP dan MAC address
	ip := net.ParseIP(*ipStr).To4()
	if ip == nil {
		log.Fatal("Error: Hanya mendukung alamat IPv4 yang valid.")
	}
	mac, err := net.ParseMAC(*macStr)
	if err != nil {
		log.Fatalf("Error: MAC address '%s' tidak valid: %v", *macStr, err)
	}

	// 3. Cari network interface
	iface, err := findInterface(*ifaceName)
	if err != nil {
		log.Fatalf("Error: Tidak bisa menemukan interface %s: %v", *ifaceName, err)
	}

	// 4. Siapkan handle pcap untuk pengiriman berulang
	handle, err := pcap.OpenLive(iface.Name, 65536, false, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error: Gagal membuka handle pcap: %v", err)
	}
	defer handle.Close()

	fmt.Printf("Target: %s -> %s pada interface %s\n", ip, mac, iface.Name)

	// 5. Logika utama: kirim sekali atau berulang
	if *interval > 0 {
		// Mode Looping (Daemon)
		fmt.Printf("Mode diaktifkan: Mengirim ARP broadcast setiap %v. Tekan Ctrl+C untuk berhenti.\n", *interval)
		runDaemon(handle, ip, mac, *interval)
	} else {
		// Mode Single-shot
		fmt.Println("Mode diaktifkan: Mengirim satu kali.")
		err = sendGratuitousARP(handle, ip, mac)
		if err != nil {
			log.Fatalf("Error: Gagal mengirim paket ARP: %v", err)
		}
		fmt.Println("✅ Berhasil mengirim satu paket ARP.")
	}
}

// runDaemon menjalankan pengiriman ARP dalam loop dan menangani sinyal untuk keluar dengan aman
func runDaemon(handle *pcap.Handle, ip net.IP, mac net.HardwareAddr, interval time.Duration) {
	// Buat ticker untuk pengiriman berkala
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Buat channel untuk menangkap sinyal interupsi (Ctrl+C)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Loop utama
	for {
		select {
		case <-ticker.C:
			// Saat ticker berbunyi, kirim paket ARP
			err := sendGratuitousARP(handle, ip, mac)
			if err != nil {
				log.Printf("Error: Gagal mengirim paket ARP: %v", err)
			} else {
				log.Printf("✅ [%s] Berhasil mengirim broadcast ARP.", time.Now().Format("2006-01-02 15:04:05"))
			}
		case <-sigChan:
			// Saat menerima sinyal (Ctrl+C), hentikan program dengan aman
			fmt.Println("\nSinyal interupsi diterima. Berhenti...")
			return
		}
	}
}

// findInterface tidak berubah
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

// sendGratuitousARP dimodifikasi untuk menerima handle agar tidak perlu buka/tutup berulang kali
func sendGratuitousARP(handle *pcap.Handle, sourceIP net.IP, sourceMAC net.HardwareAddr) error {
	ethLayer := &layers.Ethernet{
		SrcMAC:       sourceMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   sourceMAC,
		SourceProtAddress: sourceIP,
		DstHwAddress:      net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DstProtAddress:    sourceIP,
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ethLayer, arpLayer); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}
