package main

import (
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

// pairedInterface menyimpan informasi interface dari OS dan pcap yang sudah dipasangkan
type pairedInterface struct {
	netIface  net.Interface
	pcapIface pcap.Interface
}

func main() {
	ifaceName := flag.String("iface", "eth0", "Nama network interface (e.g., Wi-Fi, Ethernet)")
	ipStr := flag.String("ip", "", "IP address yang akan diumumkan (wajib)")
	macStr := flag.String("mac", "", "MAC address yang akan diumumkan (wajib)")
	interval := flag.Duration("interval", 0, "Interval pengiriman. Contoh: 30s, 1m. Jika 0, kirim sekali lalu keluar.")
	listInterfaces := flag.Bool("list", false, "Tampilkan semua interface yang tersedia dan pasangannya")
	flag.Parse()

	if *listInterfaces {
		listPairedInterfaces()
		return
	}

	if *ipStr == "" || *macStr == "" {
		log.Fatal("Error: Flag -ip dan -mac wajib diisi.")
	}

	ip := net.ParseIP(*ipStr).To4()
	if ip == nil {
		log.Fatal("Error: Hanya mendukung alamat IPv4 yang valid.")
	}
	mac, err := net.ParseMAC(*macStr)
	if err != nil {
		log.Fatalf("Error: MAC address '%s' tidak valid: %v", *macStr, err)
	}

	// Cari dan cocokkan interface berdasarkan input user
	paired, err := findAndMatchInterface(*ifaceName)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	// Buka handle pcap menggunakan NAMA DEVICE dari pcap
	handle, err := pcap.OpenLive(paired.pcapIface.Name, 65536, false, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error: Gagal membuka handle pcap untuk device %s: %v", paired.pcapIface.Name, err)
	}
	defer handle.Close()

	fmt.Printf("Target: %s -> %s\n", ip, mac)
	fmt.Printf("Menggunakan: Interface OS '%s' dengan Device Pcap '%s' (%s)\n", paired.netIface.Name, paired.pcapIface.Name, paired.pcapIface.Description)

	if *interval > 0 {
		fmt.Printf("Mode diaktifkan: Mengirim ARP broadcast setiap %v. Tekan Ctrl+C untuk berhenti.\n", *interval)
		runDaemon(handle, ip, mac, *interval)
	} else {
		fmt.Println("Mode diaktifkan: Mengirim satu kali.")
		err = sendGratuitousARP(handle, ip, mac)
		if err != nil {
			log.Fatalf("Error: Gagal mengirim paket ARP: %v", err)
		}
		fmt.Println("✅ Berhasil mengirim satu paket ARP.")
	}
}

// findAndMatchInterface adalah fungsi utama untuk mencocokkan input user dengan interface
func findAndMatchInterface(userInput string) (*pairedInterface, error) {
	netIfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("gagal mendapatkan interface OS: %v", err)
	}

	pcapIfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("gagal mendapatkan device pcap: %v", err)
	}

	// Helper function untuk mencocokkan interface berdasarkan IP
	ipsMatch := func(netI net.Interface, pcapI pcap.Interface) bool {
		netAddrs, _ := netI.Addrs()
		for _, netAddr := range netAddrs {
			// Hanya cocokkan alamat IP
			netIP, _, _ := net.ParseCIDR(netAddr.String())
			if netIP == nil {
				continue
			}
			for _, pcapAddr := range pcapI.Addresses {
				if netIP.Equal(pcapAddr.IP) {
					return true
				}
			}
		}
		return false
	}

	// Prioritas 1: Cari interface OS yang namanya cocok, lalu cari pasangan pcap-nya
	for _, netI := range netIfaces {
		if netI.Name == userInput {
			for _, pcapI := range pcapIfaces {
				if ipsMatch(netI, pcapI) {
					return &pairedInterface{netIface: netI, pcapIface: pcapI}, nil
				}
			}
			return nil, fmt.Errorf("menemukan interface OS '%s', tetapi tidak dapat menemukan device pcap yang sesuai. Pastikan interface memiliki alamat IP dan driver Npcap aktif.", userInput)
		}
	}

	// Prioritas 2: Cari device pcap yang namanya/deskripsinya cocok, lalu cari pasangan OS-nya
	for _, pcapI := range pcapIfaces {
		if pcapI.Name == userInput || pcapI.Description == userInput {
			for _, netI := range netIfaces {
				if ipsMatch(netI, pcapI) {
					return &pairedInterface{netIface: netI, pcapIface: pcapI}, nil
				}
			}
			return nil, fmt.Errorf("menemukan device pcap '%s', tetapi tidak dapat menemukan interface OS yang sesuai. Pastikan interface memiliki alamat IP.", userInput)
		}
	}

	return nil, fmt.Errorf("tidak dapat menemukan interface atau device dengan nama '%s'. Jalankan dengan -list untuk melihat yang tersedia.", userInput)
}

// listPairedInterfaces menampilkan interface OS dan device pcap yang terpasangkan berdasarkan IP
func listPairedInterfaces() {
	fmt.Println("--- Interface yang Tersedia (Dipasangkan berdasarkan IP) ---")
	netIfaces, _ := net.Interfaces()
	pcapIfaces, _ := pcap.FindAllDevs()

	found := false
	for _, netI := range netIfaces {
		for _, pcapI := range pcapIfaces {
			// Cocokkan berdasarkan alamat IP
			netAddrs, _ := netI.Addrs()
			for _, netAddr := range netAddrs {
				netIP, _, _ := net.ParseCIDR(netAddr.String())
				if netIP == nil {
					continue
				}

				for _, pcapAddr := range pcapI.Addresses {
					if netIP.Equal(pcapAddr.IP) {
						found = true
						status := "Down"
						if netI.Flags&net.FlagUp != 0 {
							status = "Up  "
						}
						fmt.Printf("OS Nama: %-20s | Status: %-4s | MAC: %s\n", netI.Name, status, netI.HardwareAddr)
						fmt.Printf("  > Pcap Nama    : %s\n", pcapI.Name)
						fmt.Printf("  > Deskripsi    : %s\n", pcapI.Description)
						fmt.Printf("  > IP Address   : %s\n", netAddr.String())
						fmt.Println("------------------------------------")
						break // Pindah ke interface berikutnya setelah menemukan kecocokan
					}
				}
			}
		}
	}
	if !found {
		fmt.Println("Tidak ada interface yang bisa dipasangkan. Pastikan Npcap sudah terinstal dengan benar dan interface memiliki alamat IP.")
	}
}

func runDaemon(handle *pcap.Handle, ip net.IP, mac net.HardwareAddr, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			err := sendGratuitousARP(handle, ip, mac)
			if err != nil {
				log.Printf("Error: Gagal mengirim paket ARP: %v", err)
			} else {
				log.Printf("✅ [%s] Berhasil mengirim broadcast ARP.", time.Now().Format("2006-01-02 15:04:05"))
			}
		case <-sigChan:
			fmt.Println("\nSinyal interupsi diterima. Berhenti...")
			return
		}
	}
}

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
