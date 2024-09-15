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
#### Usage
```
packet-reader 38188.pcap
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
