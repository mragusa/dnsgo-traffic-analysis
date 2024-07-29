package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"sort"
	"sync"
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
	responsesSent    map[string][]DnsResponse
	recordName       map[string]int
	recordNameID     map[string][]uint16
	recordTypes      map[uint16]int
	recordTypeLookup map[uint16]string
}

type DnsQuery struct {
	QueryID      uint16
	QueryRequest string
	QueryTime    time.Time
	Key          string
}

type DnsResponse struct {
	QueryID      uint16
	ResponseTime time.Time
	RRName       string
	Latency      time.Duration
}

type SlowResponse struct {
	Query    DnsQuery
	Response DnsResponse
}

func calculateMean(latencies []time.Duration) time.Duration {
	if len(latencies) == 0 {
		return 0
	}

	var mean int64
	for i, latency := range latencies {
		mean += int64(int64(latency)-mean) / int64(i+1)
	}

	return time.Duration(mean)
}

func NewDnsAnalyzer(captureFile, sourceIP string, timeDelay time.Duration, outputFile, reportFile string, verbose bool) *DnsAnalyzer {
	return &DnsAnalyzer{
		captureFile:   captureFile,
		sourceIP:      sourceIP,
		timeDelay:     timeDelay,
		outputFile:    outputFile,
		reportFile:    reportFile,
		verbose:       verbose,
		responsesSent: make(map[string][]DnsResponse),
		recordName:    make(map[string]int),
		recordNameID:  make(map[string][]uint16),
		recordTypes:   make(map[uint16]int),
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
	//fmt.Printf("Packet: %+v\n", packet)
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
			if !dns.QR { // DNS query
				if ip.DstIP.String() == analyzer.sourceIP {
					analyzer.queriesReceived = append(analyzer.queriesReceived, DnsQuery{
						QueryID:      dns.ID,
						QueryRequest: string(dns.Questions[0].Name),
						QueryTime:    packet.Metadata().Timestamp,
						Key:          fmt.Sprintf("%d%s", dns.ID, ip.SrcIP.String()),
					})
					analyzer.recordTypes[uint16(dns.Questions[0].Type)]++
					analyzer.recordName[string(dns.Questions[0].Name)]++
					analyzer.recordNameID[string(dns.Questions[0].Name)] = append(analyzer.recordNameID[string(dns.Questions[0].Name)], dns.ID)
				}
			} else { // DNS response
				answers := ""
				for _, ans := range dns.Answers {
					answers += string(ans.Name) + ", "
				}
				response := DnsResponse{
					QueryID:      dns.ID,
					ResponseTime: packet.Metadata().Timestamp,
					RRName:       string(answers),
				}
				key := fmt.Sprintf("%d%s", response.QueryID, ip.DstIP.String())

				oldRes, found := analyzer.responsesSent[key]
				if found {
					analyzer.responsesSent[key] = append(oldRes, response)
				} else {
					analyzer.responsesSent[key] = []DnsResponse{response}
				}
				if analyzer.verbose {
					fmt.Printf("%d %s %s\n", dns.ID, answers, packet.Metadata().Timestamp)
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

	for packet := range packetSource.Packets() {
		totalPackets++
		analyzer.processPacket(packet)
	}
	fmt.Printf("|  %10s  |  %10s  |\n", "File Name", analyzer.captureFile)
	fmt.Printf("|  %10s  |  %10d  |\n", "Total Packets", totalPackets)
	fmt.Printf("|  %10s  |  %10d  |\n", "Queries Received", len(analyzer.queriesReceived))
	fmt.Printf("|  %10s  |  %10d  |\n", "Query Responses", len(analyzer.responsesSent))

	var latencyTimes []time.Duration
	var slowResps []SlowResponse
	var addMtx sync.Mutex
	//var wg sync.WaitGroup

	for _, query := range analyzer.queriesReceived {
		//fmt.Printf("Considering query; %+v\n", query)

		//wg.Add(1)
		//Add a query goroutine to the waitgroup
		//In this construction unlimited goroutines are spun up. Maybe limit to runtime.NumCPUs()
		//go func() {
		//Remove yourself from the workgroup after work is done.
		//defer wg.Done()
		queryMatch := false
		responseArr, found := analyzer.responsesSent[query.Key]
		if found {
			for _, response := range responseArr {
				//fmt.Printf("Considering response; %+v\n", response)
				if query.QueryID == response.QueryID {
					latencyTime := response.ResponseTime.Sub(query.QueryTime)
					response.Latency = latencyTime
					if latencyTime < 0 || latencyTime > time.Minute*10 {
						//reused qid
						continue
					}
					if analyzer.verbose {
						fmt.Printf("Query ID: %d, Latency Time: %s\n", query.QueryID, latencyTime)
					}
					latencyTimes = append(latencyTimes, latencyTime)
					queryMatch = true
					if latencyTime > analyzer.timeDelay {
						//Lock so that multiple threads dont access slowResps at the same time.
						addMtx.Lock()
						slowResps = append(slowResps, SlowResponse{Query: query, Response: response})
						//Unlock after you're done.
						addMtx.Unlock()
					}
				}
			}
		}
		if !queryMatch && analyzer.verbose {
			fmt.Printf("No response found for Query ID: %d\n", query.QueryID)
		}
		//}()
	}

	//Wait for all my threads to finish.
	//wg.Wait()

	fmt.Printf("|  %10s  |  %10d  |\n", "Slow Queries", len(slowResps))
	fmt.Printf("\nSaving slow queries to file\n\n")

	file, err := os.Create(analyzer.outputFile)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for _, query := range slowResps {
		fmt.Fprintf(writer, "Query: %s, Query ID: %d, Latency: %s\n", query.Query.QueryRequest, query.Query.QueryID, query.Response.Latency)
	}
	writer.Flush()

	if len(latencyTimes) > 0 {
		sort.Slice(latencyTimes, func(i, j int) bool {
			return latencyTimes[i] < latencyTimes[j]
		})

		// Determine median of Latency Times
		median := latencyTimes[len(latencyTimes)/2]
		if len(latencyTimes)%2 == 0 {
			median = (latencyTimes[len(latencyTimes)/2-1] + latencyTimes[len(latencyTimes)/2]) / 2
		}

		// Determine mean of latency times
		mean := calculateMean(latencyTimes)

		// Print output of various latency statistics
		fmt.Printf("|  %10s  |  %10v  |\n", "Lowest Latency", latencyTimes[0])
		fmt.Printf("|  %10s  |  %10v  |\n", "Highest Latency", latencyTimes[len(latencyTimes)-1])
		fmt.Printf("|  %10s  |  %10v  |\n", "Median Latency", median)
		fmt.Printf("|  %10s  |  %10v  |\n\n", "Mean Latency", mean)
	}

	total := totalPackets
	slow := len(slowResps)
	percentageDifference := float64((total - slow)) / float64(total) * 100
	fmt.Printf("|  %10s  |  %10d  |\n", "Total Packets", total)
	fmt.Printf("|  %10s  |  %10d  |\n", "Slow Queries", slow)
	fmt.Printf("|  %10s  |  %10.3f  |\n\n", "Percentage of Good Traffic", percentageDifference)

	// Save sorted record names and their counts to the report file
	fmt.Printf("Saving Total Names Queried Report\n\n")
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
	fmt.Printf("|  %10s  |  %-10s  |\n", "Type", "Count")
	for k, v := range analyzer.recordTypes {
		fmt.Printf("|  %10s  |  %-10d  |\n", analyzer.recordTypeLookup[k], v)
	}
}

func main() {
	captureFile := flag.String("file", "", "Traffic Capture File")
	sourceIP := flag.String("source", "", "DNS Server IP Address")
	timeDelay := flag.Float64("time", 0.5, "Latency delay measured in seconds")
	reportFile := flag.String("report", "query_traffic_count.txt", "Query Traffic Report Count")
	outputFile := flag.String("output", "slow_queries.txt", "Name of slow queries file output")
	verbose := flag.Bool("verbose", false, "Verbose output")
	var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to `file`")
	var memprofile = flag.String("memprofile", "", "write memory profile to `file`")

	flag.Parse()

	if *captureFile == "" || *sourceIP == "" {
		flag.Usage()
		return
	}
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close() // error handling omitted for example
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}

	analyzer := NewDnsAnalyzer(*captureFile, *sourceIP, time.Duration(*timeDelay*float64(time.Second)), *outputFile, *reportFile, *verbose)
	analyzer.analyze()

	if *memprofile != "" {
		f, err := os.Create(*memprofile)
		if err != nil {
			log.Fatal("could not create memory profile: ", err)
		}
		defer f.Close() // error handling omitted for example
		runtime.GC()    // get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
	}
}
