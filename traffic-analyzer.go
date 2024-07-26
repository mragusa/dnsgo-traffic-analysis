package main

import (
	"bufio"
	//"encoding/binary"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type DnsAnalyzer struct {
	captureFile      string
	sourceIP         string
	timeDelay        time.Duration
	outputFile       string
	reportFile       string
	verbose          bool
	queriesReceived  []DnsQuery
	responsesSent    []DnsResponse
	recordName       map[string]int
	recordNameID     map[string][]uint16
	recordTypes      map[uint16]int
	recordTypeLookup map[uint16]string
}

type DnsQuery struct {
	QueryID      uint16
	QueryRequest string
	QueryTime    time.Time
}

type DnsResponse struct {
	QueryID      uint16
	ResponseTime time.Time
	RRName       string
}

func NewDnsAnalyzer(captureFile, sourceIP string, timeDelay time.Duration, outputFile, reportFile string, verbose bool) *DnsAnalyzer {
	return &DnsAnalyzer{
		captureFile:  captureFile,
		sourceIP:     sourceIP,
		timeDelay:    timeDelay,
		outputFile:   outputFile,
		reportFile:   reportFile,
		verbose:      verbose,
		recordName:   make(map[string]int),
		recordNameID: make(map[string][]uint16),
		recordTypes:  make(map[uint16]int),
		recordTypeLookup: map[uint16]string{
			1: "A", 28: "AAAA", 62: "CSYNC", 49: "DHCID", 32769: "DLV",
			39: "DNAME", 48: "DNSKEY", 43: "DS", 108: "EUI48", 109: "EUI64",
			13: "HINFO", 55: "HIP", 65: "HTTPS", 45: "IPSECKEY", 25: "KEY",
			36: "KX", 29: "LOC", 15: "MX", 35: "NAPTR", 2: "NS", 47: "NSEC",
			50: "NSEC3", 51: "NSEC3PARAM", 61: "OPENPGPKEY", 12: "PTR",
			17: "RP", 46: "RRSIG", 24: "SIG", 53: "SMIMEA", 6: "SOA",
			33: "SRV", 44: "SSHFP", 64: "SVCB", 32768: "TA", 249: "TKEY",
			52: "TLSA", 250: "TSIG", 16: "TXT", 256: "URI", 63: "ZONEMD",
			255: "*", 252: "AXFR", 251: "IXFR", 41: "OPT", 3: "MD", 4: "MF",
			254: "MAILA", 7: "MB", 8: "MG", 9: "MR", 14: "MINFO", 253: "MAILB",
			11: "WKS", 10: "NULL", 38: "A6", 30: "NXT",
			19: "X25", 20: "ISDN", 21: "RT", 22: "NSAP", 23: "NSAP-PTR",
			26: "PX", 31: "EID", 32: "NIMLOC",
			34: "ATMA", 40: "SINK", 27: "GPOS", 100: "UINFO",
			101: "UID", 102: "GID", 103: "UNSPEC", 99: "SPF", 56: "NINFO",
			57: "RKEY", 58: "TALINK", 104: "NID", 105: "L32", 106: "L64",
			107: "LP", 259: "DOA", 18: "AFSDB", 42: "APL", 257: "CAA",
			60: "CDNSKEY", 59: "CDS", 37: "CERT", 5: "CNAME",
		},
	}
}

func (analyzer *DnsAnalyzer) processPacket(packet gopacket.Packet) {
	if analyzer.verbose {
		fmt.Println(packet)
	}
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ip, _ := ipLayer.(*layers.IPv4)
		if ip.DstIP.String() == analyzer.sourceIP || ip.SrcIP.String() == analyzer.sourceIP {
			if analyzer.verbose {
				fmt.Println(dns)
			}
			if dns.QR == false { // DNS query
				if ip.DstIP.String() == analyzer.sourceIP {
					analyzer.queriesReceived = append(analyzer.queriesReceived, DnsQuery{
						QueryID:      dns.ID,
						QueryRequest: string(dns.Questions[0].Name),
						QueryTime:    packet.Metadata().Timestamp,
					})
					analyzer.recordTypes[dns.Questions[0].Type]++
					analyzer.recordName[string(dns.Questions[0].Name)]++
					analyzer.recordNameID[string(dns.Questions[0].Name)] = append(analyzer.recordNameID[string(dns.Questions[0].Name)], dns.ID)
				}
			} else { // DNS response
				for _, ans := range dns.Answers {
					analyzer.responsesSent = append(analyzer.responsesSent, DnsResponse{
						QueryID:      dns.ID,
						ResponseTime: packet.Metadata().Timestamp,
						RRName:       string(ans.Name),
					})
					if analyzer.verbose {
						fmt.Printf("%d %s %s\n", dns.ID, ans.Name, packet.Metadata().Timestamp)
					}
				}
			}
		}
	}
}

func (analyzer *DnsAnalyzer) analyze() {
	handle, err := pcap.OpenOffline(analyzer.captureFile)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	totalPackets := 0

	for range packetSource.Packets() {
		totalPackets++
	}

	fmt.Printf("Total packets found %d in %s\n\n", totalPackets, analyzer.captureFile)

	packetSource = gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		analyzer.processPacket(packet)
	}

	fmt.Printf("Number of queries received: %d\n", len(analyzer.queriesReceived))
	fmt.Printf("Number of responses sent: %d\n\n", len(analyzer.responsesSent))

	var latencyTimes []time.Duration
	var slowQueries []DnsQuery

	for _, query := range analyzer.queriesReceived {
		queryMatch := false
		for _, response := range analyzer.responsesSent {
			if query.QueryID == response.QueryID {
				latencyTime := response.ResponseTime.Sub(query.QueryTime)
				if analyzer.verbose {
					fmt.Printf("Query ID: %d, Latency Time: %s\n", query.QueryID, latencyTime)
				}
				latencyTimes = append(latencyTimes, latencyTime)
				queryMatch = true
				if latencyTime > analyzer.timeDelay {
					slowQueries = append(slowQueries, query)
				}
				break
			}
		}
		if !queryMatch && analyzer.verbose {
			fmt.Printf("No response found for Query ID: %d\n", query.QueryID)
		}
	}

	fmt.Printf("Total Slow Queries: %d\n", len(slowQueries))
	fmt.Println("Saving slow queries to file")

	file, err := os.Create(analyzer.outputFile)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for _, query := range slowQueries {
		fmt.Fprintf(writer, "Query: %s, Query ID: %d, Latency: %s\n", query.QueryRequest, query.QueryID, query.QueryTime)
	}
	writer.Flush()

	if len(latencyTimes) > 0 {
		sort.Slice(latencyTimes, func(i, j int) bool {
			return latencyTimes[i] < latencyTimes[j]
		})
		fmt.Printf("Lowest Latency: %s\n", latencyTimes[0])
		fmt.Printf("Highest Latency: %s\n", latencyTimes[len(latencyTimes)-1])
		fmt.Printf("Median Latency: %s\n", latencyTimes[len(latencyTimes)/2])
	}

	total := totalPackets
	slow := len(slowQueries)
	percentageDifference := float64((total - slow)) * 100
	fmt.Printf("\nTotal Packets: %d\n", total)
	fmt.Printf("Slow Queries: %d\n", slow)
	fmt.Printf("Percentage Difference: %.2f%%\n", percentageDifference)

	// Save sorted record names and their counts to the report file
	fmt.Println("Saving Total Names Queried Report")
	reportFile, err := os.Create(analyzer.reportFile)
	if err != nil {
		panic(err)
	}
	defer reportFile.Close()
	reportWriter := bufio.NewWriter(reportFile)
	sortedRecordNames := make([]string, 0, len(analyzer.recordName))
	for k := range analyzer.recordName {
		sortedRecordNames = append(sortedRecordNames, k)
	}
	sort.Slice(sortedRecordNames, func(i, j int) bool {
		return analyzer.recordName[sortedRecordNames[i]] > analyzer.recordName[sortedRecordNames[j]]
	})
	for _, query := range sortedRecordNames {
		fmt.Fprintf(reportWriter, "Query: %s Count: %d Query ID: %v\n", query, analyzer.recordName[query], analyzer.recordNameID[query])
	}
	reportWriter.Flush()

	// Print total record types queried
	fmt.Println("Total Record Types Queried")
	for k, v := range analyzer.recordTypes {
		fmt.Printf("Type: %s Count: %d\n", analyzer.recordTypeLookup[k], v)
	}
}

func main() {
	captureFile := flag.String("file", "", "Traffic Capture File")
	sourceIP := flag.String("source", "", "DNS Server IP Address")
	timeDelay := flag.Float64("time", 0.5, "Latency delay measured in seconds")
	reportFile := flag.String("report", "query_traffic_count.txt", "Query Traffic Report Count")
	outputFile := flag.String("output", "slow_queries.txt", "Name of slow queries file output")
	verbose := flag.Bool("verbose", false, "Verbose output")

	flag.Parse()

	if *captureFile == "" || *sourceIP == "" {
		flag.Usage()
		return
	}

	analyzer := NewDnsAnalyzer(*captureFile, *sourceIP, time.Duration(*timeDelay*float64(time.Second)), *outputFile, *reportFile, *verbose)
	analyzer.analyze()
}
