package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	captureFile := flag.String("file", "", "Traffic Capture File")
	displayDns := flag.Bool("dns", false, "Display DNS Servers")
	displayRecursive := flag.Bool("recursive", false, "Display Recursive DNS Servers")
	displayClients := flag.Bool("clients", false, "Display Client IPs")
	reportTotal := flag.Bool("report", false, "Report Total")
	flag.Parse()
	// Return usage if no capture file is provided
	if *captureFile == "" {
		flag.Usage()
		return
	}
	// Open capture file
	p, err := pcap.OpenOffline(*captureFile)
	if err != nil {
		log.Fatal(err)
	}
	defer p.Close()
	// dnsServersFound is a map where the key is the IP address (as a string), and the value is the count
	dnsServersFound := make(map[string]int)
	recursiveDNSServerFound := make(map[string]int)
	dnsClientFound := make(map[string]int)
	// Process pcap file and display contents to stdout
	packetSource := gopacket.NewPacketSource(p, p.LinkType())
	for packet := range packetSource.Packets() {
		// Retrieve timestamp from packet metadata
		//timestamp := packet.Metadata().Timestamp
		//fmt.Println(timestamp)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			ipLayer = packet.Layer(layers.LayerTypeIPv6)
		}
		if ipLayer != nil {
			//var srcIP, dstIP string
			var dstIP string
			switch ip := ipLayer.(type) {
			case *layers.IPv4:
				//srcIP = ip.SrcIP.String()
				dstIP = ip.DstIP.String()
			case *layers.IPv6:
				//srcIP = ip.SrcIP.String()
				dstIP = ip.DstIP.String()
			}
			var srcPort, dstPort layers.UDPPort
			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				udp := udpLayer.(*layers.UDP)
				srcPort = udp.SrcPort
				dstPort = udp.DstPort
			} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp := tcpLayer.(*layers.TCP)
				srcPort = layers.UDPPort(tcp.SrcPort)
				dstPort = layers.UDPPort(tcp.DstPort)
			}
			if dstPort == 53 {
				//fmt.Println("DNS Server Found", dstIP)
				// Check if the destination IP is already in the dnsServersFound map
				if count, found := dnsServersFound[dstIP]; found {
					// If found, increment the count
					dnsServersFound[dstIP] = count + 1
				} else {
					// If not found, initialize the count to 1
					dnsServersFound[dstIP] = 1
				}
			}
			if srcPort == 53 {
				if count, found := dnsClientFound[dstIP]; found {
					dnsClientFound[dstIP] = count + 1
				} else {
					dnsClientFound[dstIP] = 1
				}
				// Check if client IP was in DNS servers list to determine if IP is a recursive DNS server
				if existingCount, rServerExists := dnsServersFound[dstIP]; rServerExists {
					if _, exists := recursiveDNSServerFound[dstIP]; exists {
						recursiveDNSServerFound[dstIP] = existingCount + 1
					} else {
						recursiveDNSServerFound[dstIP] = existingCount
					}
				}
			}
		}
	}
	for dnsServer, _ := range recursiveDNSServerFound {
		if _, exists := dnsServersFound[dnsServer]; exists {
			delete(dnsClientFound, dnsServer)
			delete(dnsServersFound, dnsServer)
		}
	}
	if *displayDns {
		fmt.Println("Total Servers Found:", len(dnsServersFound))
		fmt.Println("DNS Servers")
		fmt.Println("| Server | Count |")
		// d for DNS server
		for d, c := range dnsServersFound {
			fmt.Printf("| %s | %d |\n", d, c)
		}
	}
	if *displayRecursive {
		// r for recursive
		fmt.Println("Total Servers Found: ", len(recursiveDNSServerFound))
		fmt.Println("Recursive DNS Servers")
		fmt.Println("| Server | Count |")
		for r, c := range recursiveDNSServerFound {
			fmt.Printf("| %s | %d |\n", r, c)
		}
	}
	if *displayClients {
		fmt.Println("Total Clients Found: ", len(dnsClientFound))
		fmt.Println("| Client | Count |")
		// w is for workstation :-D
		for w, c := range dnsClientFound {
			fmt.Printf("| %s | %d |\n", w, c)
		}
	}
	if *reportTotal {
		fmt.Println("Total DNS Servers:", len(dnsServersFound))
		fmt.Println("Total Recursive Servers:", len(recursiveDNSServerFound))
		fmt.Println("Total Clients:", len(dnsClientFound))
	}
}
