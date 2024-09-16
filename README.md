# dnsgo-traffic-analysis
Tools for analyzing PCAP files to identify DNS queries with high latency written in [go](https://go.dev/)

# Overview
Clients frequently ask engineers to identify slow DNS queries in response to customer complaints about resolution issues. This often results in lengthy troubleshooting sessions using tools like tcpdump and Wireshark, along with extended customer interactions. The following tools can help streamline the investigation process and provide detailed reports directly from the CLI, reducing time spent on diagnostics.

Inspred by [dns-traffic-analysis](https://github.com/mragusa/dns-traffic-analysis) but written in go

* traffic-analyzer
  - read a pcap file and report on dns queries slower than the specified time duration
  - writes total queries and slow queries found to files for review
  - imports pprof module for deeper dive into application internals
  - capable of reading 1G pcap files in under 90 seconds
* packet-reader
  - reads pcap file and displays DNS packet content to stdout
* packet-splitter
  - reads pcap file and creates a new pcap file based on the DNS Query ID provided

## Requirements
  - [Go](https://go.dev/dl/) version 1.22 or higher
  - [gopacket](https://pkg.go.dev/github.com/google/gopacket)

## Build Instructions
1. **Clone repository**
```
git clone https://github.com/mragusa/dnsgo-traffic-analysis.git
```
2. **Install modules**
```
go mod init gopacket
go mod tidy
```
3. **Build binary**
```
cd traffic-analyzer  && go build traffic-analyzer.go
```

## Usage
### traffic-analyzer
```
traffic-analyzer -help
Usage of ./traffic-analyzer:
  -cpuprofile file
        write cpu profile to file
  -file string
        Traffic Capture File
  -memprofile file
        write memory profile to file
  -output string
        Name of slow queries file output (default "slow_queries.txt")
  -report string
        Query Traffic Report Count (default "query_traffic_count.txt")
  -source string
        DNS Server IP Address
  -time float
        Latency delay measured in seconds (default 0.5)
  -verbose
        Verbose output
```
#### Example
```
traffic-analyzer -file traffic.cap -source 10.249.12.135
```
##### Output
```
|   File Name  |  traffic.cap  |
|  Total Packets  |     5013134  |
|  Queries Received  |     1045666  |
|  Query Responses  |      755193  |
|  Slow Queries  |      451213  |

Saving slow queries to file

|  Lowest Latency  |        61µs  |
|  Highest Latency  |  9m59.912654s  |
|  Median Latency  |   188.986ms  |
|  Mean Latency  |  50.305955021s  |

|  Total Packets  |     5013134  |
|  Slow Queries  |      451213  |
|  Percentage of Good Traffic  |      90.999  |

Saving Total Names Queried Report

Total Record Types Queried
|        Type  |  Count       |
|       CNAME  |  14          |
|           A  |  686908      |
|         URI  |  60          |
|        SVCB  |  7708        |
|         TXT  |  1159        |
|      DNSKEY  |  2           |
|       NAPTR  |  1           |
|         SOA  |  61123       |
|         PTR  |  56213       |
|          NS  |  575         |
|          MX  |  14981       |
|        AAAA  |  42426       |
|          DS  |  59          |
|       HTTPS  |  166387      |
|         SRV  |  8050        |
```
### packet-reader
```
packet-reader.go -h
  -file string
        Traffic Capture File
```
#### Example 
```
packet-reader -file 38188.pcap
```
##### Output 
```
2024-04-18 18:31:12.540219 -0400 EDT
DNS Packet:
  Source IP: 10.47.11.105
  Source Port: 35621
  Destination IP: 10.249.12.135
  Destination Port: 53
  ID: 38188
  Opcode: 0
  ResponseCode: 0
  QDCount: 1
  ANCount: 0
  NSCount: 0
  ARCount: 0
  Question: a6.sphotos.ak.fbcdn.net 1 1
2024-04-18 18:31:12.540411 -0400 EDT
DNS Packet:
  Source IP: 10.249.12.135
  Source Port: 53
  Destination IP: 10.47.11.105
  Destination Port: 35621
  ID: 38188
  Opcode: 0
  ResponseCode: 3
  QDCount: 1
  ANCount: 0
  NSCount: 1
  ARCount: 0
  Question: a6.sphotos.ak.fbcdn.net 1 1
```
### packet-splitter
#### Usage
```
packet-splitter.go -help
  -file string
        Traffic Capture File
  -output string
        PCAP Output File
  -qid string
        DNS Query ID
  -verbose
        Verbose Output
```
#### Example
```
packet-splitter.go -file small_slow_packets -qid 13451
packet-splitter.go -file small_slow_packets -qid 13451 -verbose
```
##### Output
```
Matching Packet Found for Query ID 13451
Matching Packet Found for Query ID 13451
Finished writing matching packets to 13451.pcap
```
###### Verbose Output
```
Matched packet: PACKET: 126 bytes, wire length 126 cap length 126 @ 2024-04-18 18:29:33.728351 -0400 EDT
- Layer 1 (16 bytes) = Linux SLL        {Contents=[..16..] Payload=[..110..] PacketType=outgoing AddrLen=6 Addr=00:00:5e:00:01:80 EthernetType=IPv4 AddrType=1}
- Layer 2 (20 bytes) = IPv4     {Contents=[..20..] Payload=[..90..] Version=4 IHL=5 TOS=0 Length=110 Id=44256 Flags= FragOffset=0 TTL=64 Protocol=UDP Checksum=49898 SrcIP=10.249.12.135 DstIP=198.51.45.1 Options=[] Padding=[]}
- Layer 3 (08 bytes) = UDP      {Contents=[..8..] Payload=[..82..] SrcPort=45075 DstPort=53(domain) Length=90 Checksum=2848}
- Layer 4 (82 bytes) = DNS      {Contents=[..82..] Payload=[] ID=13451 QR=false OpCode=Query AA=false TC=false RD=false RA=false Z=0 ResponseCode=No Error QDCount=1 ANCount=0 NSCount=0 ARCount=1 Questions=[{Name=[..53..] Type=AAAA Class=IN}] Answers=[] Authorities=[] Additionals=[{Name=[] Type=OPT Class=Unknown TTL=32768 DataLength=0 Data=[] IP=<nil> NS=[] CNAME=[] PTR=[] TXTs=[] SOA={ MName=[] RName=[] Serial=0 Refresh=0 Retry=0 Expire=0 Minimum=0} SRV={ Priority=0 Weight=0 Port=0 Name=[]} MX={ Preference=0 Name=[]} OPT=[] URI={ Priority=0 Weight=0 Target=[]} TXT=[]}]}

Packet Metadata: {2024-04-18 18:29:33.728351 -0400 EDT 126 126 0 []}
Packet Data: [0 4 0 1 0 6 0 0 94 0 1 128 0 0 8 0 69 0 0 110 172 224 0 0 64 17 194 234 10 249 12 135 198 51 45 1 176 19 0 53 0 90 11 32 52 139 0 0 0 1 0 0 0 0 0 1 36 105 115 116 105 111 45 107 56 115 45 118 105 100 97 122 111 111 45 112 45 117 115 45 110 121 99 49 45 101 120 116 101 114 110 97 108 7 118 105 100 97 122 111 111 8 115 101 114 118 105 99 101 115 0 0 28 0 1 0 0 41 4 196 0 0 128 0 0 0]
Matched packet: PACKET: 191 bytes, wire length 191 cap length 191 @ 2024-04-18 18:29:33.737143 -0400 EDT
- Layer 1 (16 bytes) = Linux SLL        {Contents=[..16..] Payload=[..175..] PacketType=host AddrLen=6 Addr=b4:0c:25:e3:00:68 EthernetType=IPv4 AddrType=1}
- Layer 2 (20 bytes) = IPv4     {Contents=[..20..] Payload=[..155..] Version=4 IHL=5 TOS=0 Length=175 Id=50423 Flags=DF FragOffset=0 TTL=43 Protocol=UDP Checksum=32658 SrcIP=198.51.45.1 DstIP=10.249.12.135 Options=[] Padding=[]}
- Layer 3 (08 bytes) = UDP      {Contents=[..8..] Payload=[..147..] SrcPort=53(domain) DstPort=45075 Length=155 Checksum=51436}
- Layer 4 (147 bytes) = DNS     {Contents=[..147..] Payload=[] ID=13451 QR=true OpCode=Query AA=true TC=false RD=false RA=false Z=0 ResponseCode=No Error QDCount=1 ANCount=0 NSCount=1 ARCount=1 Questions=[{Name=[..53..] Type=AAAA Class=IN}] Answers=[] Authorities=[{Name=[..16..] Type=SOA Class=IN TTL=3600 DataLength=53 Data=[..53..] IP=<nil> NS=[] CNAME=[] PTR=[] TXTs=[] SOA={ MName=[..18..] RName=[..20..] Serial=1690203605 Refresh=43200 Retry=7200 Expire=1209600 Minimum=3600} SRV={ Priority=0 Weight=0 Port=0 Name=[]} MX={ Preference=0 Name=[]} OPT=[] URI={ Priority=0 Weight=0 Target=[]} TXT=[]}] Additionals=[{Name=[] Type=OPT Class=Unknown TTL=32768 DataLength=0 Data=[] IP=<nil> NS=[] CNAME=[] PTR=[] TXTs=[] SOA={ MName=[] RName=[] Serial=0 Refresh=0 Retry=0 Expire=0 Minimum=0} SRV={ Priority=0 Weight=0 Port=0 Name=[]} MX={ Preference=0 Name=[]} OPT=[] URI={ Priority=0 Weight=0 Target=[]} TXT=[]}]}

Packet Metadata: {2024-04-18 18:29:33.737143 -0400 EDT 191 191 0 []}
Packet Data: [0 0 0 1 0 6 180 12 37 227 0 104 0 0 8 0 69 0 0 175 196 247 64 0 43 17 127 146 198 51 45 1 10 249 12 135 0 53 176 19 0 155 200 236 52 139 132 0 0 1 0 0 0 1 0 1 36 105 115 116 105 111 45 107 56 115 45 118 105 100 97 122 111 111 45 112 45 117 115 45 110 121 99 49 45 101 120 116 101 114 110 97 108 7 118 105 100 97 122 111 111 8 115 101 114 118 105 99 101 115 0 0 28 0 1 192 49 0 6 0 1 0 0 14 16 0 53 4 100 110 115 49 3 112 48 49 5 110 115 111 110 101 3 110 101 116 0 10 104 111 115 116 109 97 115 116 101 114 192 92 100 190 117 213 0 0 168 192 0 0 28 32 0 18 117 0 0 0 14 16 0 0 41 4 208 0 0 128 0 0 0]
Finished writing matching packets to 13451.pcap
```
### find-dns-servers
#### Usage
```
find-dns-servers.go -help
  -clients
        Display Client IPs
  -dns
        Display DNS Servers
  -file string
        Traffic Capture File
  -recursive
        Display Recursive DNS Servers
  -report
        Report Total
```
##### Example
```
find-dns-servers.go -file small_slow_packets -report
```
##### Output
```
Total DNS Servers: 689
Total Recursive Servers: 3
Total Clients: 2082
```
