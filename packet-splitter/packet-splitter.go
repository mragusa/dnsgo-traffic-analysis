package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	captureFile := flag.String("file", "", "Traffic Capture File")
	queryID := flag.String("qid", "", "DNS Query ID")
	outputFile := flag.String("output", "", "PCAP Output File")
	verbose := flag.Bool("verbose", false, "Verbose Output")

	flag.Parse()

	if *captureFile == "" || *queryID == "" {
		flag.Usage()
		return
	}
	// If output file is empty, assign default name as QueryID.pcap
	if *outputFile == "" {
		*outputFile = *queryID + ".pcap"
	}
	// Open pcap file for processing
	p, err := pcap.OpenOffline(*captureFile)
	if err != nil {
		log.Fatal(err)
	}
	defer p.Close()
	// Process pcap file
	packetSource := gopacket.NewPacketSource(p, p.LinkType())
	// Convert queryID to int
	qID, err := strconv.ParseUint(*queryID, 10, 16)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	// Create file to save output
	f, err := os.Create(*outputFile)
	if err != nil {
		log.Fatal("Error creating output file:", err)
	}
	// Defer closing file until processing is done
	defer f.Close()
	writer := pcapgo.NewWriter(f)
	// Determine linktype from packet source
	linkType := p.LinkType()
	writer.WriteFileHeader(65536, linkType)
	// Iternate thru file to find packets matching query ID
	for packet := range packetSource.Packets() {
		// Verify DNS layer is not empty
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)
			// Match DNS Query ID against user supplied QID
			if dns.ID == uint16(qID) {
				fmt.Println("Matching Packet Found for Query ID", *queryID)
				// Print verbose statements
				if *verbose {
					fmt.Println("Matched packet:", packet)
					fmt.Println("Packet Metadata:", packet.Metadata().CaptureInfo)
					fmt.Println("Packet Data:", packet.Data())
				}
				captureInfo := packet.Metadata().CaptureInfo
				captureInfo.CaptureLength = len(packet.Data()) // Ensure CaptureLength matches packet data length
				// Write packets to output file
				// Write packeet requires metadata and raw packet data to write pcap files
				err := writer.WritePacket(captureInfo, packet.Data())
				if err != nil {
					fmt.Println("Error writing packet:", err)
					return
				}
			}
		}
	}
	fmt.Println("Finished writing matching packets to " + *outputFile)
}
