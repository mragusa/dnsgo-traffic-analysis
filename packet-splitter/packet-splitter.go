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

	if *outputFile == "" {
		*outputFile = *queryID + ".pcap"
	}

	handle, err := pcap.OpenOffline(*captureFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	qID, err := strconv.ParseUint(*queryID, 10, 16)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	f, err := os.Create(*outputFile)
	if err != nil {
		log.Fatal("Error creating output file:", err)
	}
	defer f.Close()
	writer := pcapgo.NewWriter(f)
	linkType := handle.LinkType()
	writer.WriteFileHeader(65536, linkType)
	for packet := range packetSource.Packets() {
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
				//err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
				captureInfo := packet.Metadata().CaptureInfo
				captureInfo.CaptureLength = len(packet.Data()) // Ensure CaptureLength matches packet data length
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
