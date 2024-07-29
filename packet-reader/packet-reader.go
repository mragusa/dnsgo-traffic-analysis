package main

import (
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <pcap file>\n", os.Args[0])
		os.Exit(1)
	}

	pcapFile := os.Args[1]
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		timestamp := packet.Metadata().Timestamp
		fmt.Println(timestamp)
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				ipLayer = packet.Layer(layers.LayerTypeIPv6)
			}
			if ipLayer != nil {
				var srcIP, dstIP string
				switch ip := ipLayer.(type) {
				case *layers.IPv4:
					srcIP = ip.SrcIP.String()
					dstIP = ip.DstIP.String()
				case *layers.IPv6:
					srcIP = ip.SrcIP.String()
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

				fmt.Printf("DNS Packet:\n")
				fmt.Printf("  Source IP: %s\n", srcIP)
				fmt.Printf("  Source Port: %d\n", srcPort)
				fmt.Printf("  Destination IP: %s\n", dstIP)
				fmt.Printf("  Destination Port: %d\n", dstPort)
				fmt.Printf("  ID: %d\n", dns.ID)
				fmt.Printf("  Opcode: %d\n", dns.OpCode)
				fmt.Printf("  ResponseCode: %d\n", dns.ResponseCode)
				fmt.Printf("  QDCount: %d\n", dns.QDCount)
				fmt.Printf("  ANCount: %d\n", dns.ANCount)
				fmt.Printf("  NSCount: %d\n", dns.NSCount)
				fmt.Printf("  ARCount: %d\n", dns.ARCount)
				for _, question := range dns.Questions {
					fmt.Printf("  Question: %s %d %d\n", string(question.Name), question.Type, question.Class)
				}
				for _, answer := range dns.Answers {
					fmt.Printf("  Answer: %s %d %d %v\n", string(answer.Name), answer.Type, answer.Class, answer.IP)
				}
			}
		}
	}
}
