# dnsgo‑traffic‑analysis

[![Go](https://img.shields.io/badge/go-1.22%2B-blue.svg)](https://go.dev/)  
[![License: BSD‑2‑Clause](https://img.shields.io/badge/License-BSD%202%20Clause-green.svg)](LICENSE)  
[![Status](https://img.shields.io/badge/status-active-success.svg)]()  
[![Contributions welcome](https://img.shields.io/badge/contributions-welcome-orange.svg)](https://github.com/mragusa/dnsgo‑traffic‑analysis/issues)

> High‑performance DNS traffic analysis tools written in Go for parsing PCAP files and identifying high‑latency DNS queries.

---

## 🧭 Overview

Many network engineers and DevOps teams face complaints about slow DNS resolutions. Investigating large packet capture (PCAP) files with tools like Wireshark or tcpdump can be time‑intensive.  
`dnsgo‑traffic‑analysis` provides command‑line utilities that process PCAPs, detect slow DNS queries or unusual traffic patterns, extract relevant packet subsets, and help accelerate diagnostics and root‑cause analysis.

This Go‑based toolkit is inspired by the Python version [dns‑traffic‑analysis](https://github.com/mragusa/dns‑traffic‑analysis) but optimized for larger captures, speed, and scalability.

Key capabilities:

- Read large PCAP files (1 GB+ scale) efficiently  
- Identify DNS servers, clients, query counts, and traffic distribution  
- Detect DNS queries with latency above a configurable threshold  
- Extract packet subsets and produce summary reports  
- CLI‑friendly with profiling support (CPU/memory) for performance tuning  

---

## ✨ Features

- ⚙️ Multi‑tool suite:  
  - `traffic‑analyzer`: scans PCAPs for slow DNS queries  
  - `packet‑reader`: prints detailed DNS packet fields  
  - `packet‑splitter`: extracts packets for a given DNS query ID  
  - `find‑dns‑servers`: identifies DNS servers, clients, and recursive servers  
  - `ad-keytabs`: Read Active Directory keytab files for Realm, Keytype(supported encryption type), and KVNO
- 🚀 High performance: optimized for multi‑core environments and large PCAPs  
- 🔍 Profiling support: built‑in `pprof` flags to analyze CPU/memory use  
- 🧰 Minimal external dependencies (uses Go’s ecosystem and `gopacket`)  
- 📊 Generates summary output files: slow query logs, traffic reports  

---

## 🗂️ Project Structure

```
dnsgo‑traffic‑analysis/
├── ad-keytabs/              # Go module to Active Directory Keytabs 
├── find‑dns‑servers/        # Go module to find DNS servers and clients
├── packet‑reader/           # Go module to parse and print DNS packets
├── packet‑splitter/         # Go module to extract PCAP subset by query ID
├── traffic‑analyzer/        # Go module to detect slow DNS queries in PCAP
├── go.mod
├── go.sum
└── README.md                # This file
```

---

## ⚙️ Installation

### Requirements

- Go version **1.22+**  
- PCAP capture file(s) containing DNS traffic (e.g., captured via `tcpdump`, `Wireshark`)  
- Optionally: large memory and SSD storage for high‑volume processing  

### Build Instructions

```bash
git clone https://github.com/mragusa/dnsgo‑traffic‑analysis.git
cd dnsgo‑traffic‑analysis
go mod tidy
```

To build each tool individually:

```bash
cd traffic‑analyzer
go build -o traffic‑analyzer traffic‑analyzer.go
```

Similarly for `ad-keytabs`, `packet‑reader`, `packet‑splitter`, and `find‑dns‑servers`.

---

## 🚀 Usage

### traffic‑analyzer

```bash
./traffic‑analyzer -file path/to/traffic.pcap -source 10.249.12.135 -time 0.5
```

**Flags overview:**

- `-file string` : Traffic capture file (PCAP)  
- `-source string` : DNS server IP address (optional)  
- `-time float` : Latency threshold in seconds, defaults to 0.5  
- `-output string` : Path for slow‑queries output (default: `slow_queries.txt`)  
- `-report string` : Path for query traffic count summary (default: `query_traffic_count.txt`)  
- `-cpuprofile string`, `-memprofile string` : Profiling output  
- `-verbose` : Enable verbose logging  

**Example output:**

```
|   File Name         | traffic.pcap     |
|   Total Packets     | 5013134          |
|   Queries Received  | 1045666          |
|   Query Responses   | 755193           |
|   Slow Queries      | 451213           |
...
```

### packet‑reader

```bash
./packet‑reader -file path/to/traffic.pcap
```

Prints detailed DNS packet fields: source/destination IPs & ports, DNS ID, flags, question/answer counts, packet timestamps.

### packet‑splitter

```bash
./packet‑splitter -file traffic.pcap -qid 13451 -output 13451.pcap
```

Extracts all packets matching DNS query ID `13451` into a separate PCAP file for further inspection.

### find‑dns‑servers

```bash
./find‑dns‑servers -file traffic.pcap -dns -clients -recursive -report
```

Identifies DNS servers, clients, and recursive servers based on PCAP traffic.

### ad-keytabs
```bash
./ad-keytabs.go -keytab /path/to/file
```
**Flags overview:**
- `-aes-only` :  Show only AES enctypes (17, 18)
- `-json` : Print raw JSON from kt.JSON() and exit
- `-keytab` : Path to keytab file (required)
- `-principle` : Filter to a specific principal, e.g. DNS/ns.example.com@EXAMPLE.COM

---

## 🧠 Tips & Best Practices

- For massive PCAP files (> 1 GB), ensure you run on a system with sufficient RAM and fast I/O.  
- Use the `-time` flag to adjust for realistic DNS latency thresholds (e.g., 1 s for WAN environments).  
- Use profiling flags (`-cpuprofile`, `-memprofile`) to optimize performance or debug memory use.  
- After exporting slow‑query results, analyze them by query name, client, or timestamp to find recurring offenders.  
- Securely handle PCAPs—they may contain sensitive network data.

---

## 🤝 Contributing

Contributions are encouraged! Whether you want to enhance packet analysis, add filtering options, or optimize performance — you’re welcome to help improve the toolset.

To contribute:

1. Fork the repository  
2. Create a feature branch (`git checkout -b feature/my‑tool`)  
3. Commit your improvements and tests  
4. Submit a Pull Request  

Follow Go best practices (`gofmt`, `golint`, `go vet`) and update documentation for new features.

---

## 📜 License

This project is licensed under the [BSD‑2‑Clause License](LICENSE).

---

## 📚 References

- [Go (golang)](https://go.dev) — programming language used for this project  
- [gopacket](https://pkg.go.dev/github.com/google/gopacket) — PCAP parsing library used  
- [tcpdump](https://www.tcpdump.org) — for capturing PCAP files  
- [Wireshark](https://www.wireshark.org) — for detailed packet and DNS inspection  

---

## 💬 Support & Issues

If you encounter bugs or have feature ideas, please [open an issue](https://github.com/mragusa/dnsgo‑traffic‑analysis/issues).  
For extended use or enterprise integration, feel free to reach out.

> _Maintained by [Mike Ragusa](https://github.com/mragusa)_
