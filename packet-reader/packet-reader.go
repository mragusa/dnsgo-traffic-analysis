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
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)
			fmt.Println("DNS Packet:")
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
