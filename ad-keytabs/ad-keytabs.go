package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/jcmturner/gokrb5/v8/keytab"
)

type KeytabJSON struct {
	Entries []Entry `json:"Entries"`
}

type Entry struct {
	Principal struct {
		Realm      string   `json:"Realm"`
		Components []string `json:"Components"`
		NameType   int      `json:"NameType"`
	} `json:"Principal"`

	Timestamp string `json:"Timestamp"`

	KVNO8 int `json:"KVNO8"`
	KVNO  int `json:"KVNO"`

	Key struct {
		KeyType int `json:"KeyType"`
	} `json:"Key"`
}

var etypeName = map[int]string{
	1:  "des-cbc-crc (weak/obsolete)",
	3:  "des-cbc-md5 (weak/obsolete)",
	17: "aes128-cts-hmac-sha1-96",
	18: "aes256-cts-hmac-sha1-96",
	23: "rc4-hmac (legacy)",
}

func etypeToString(id int) string {
	if s, ok := etypeName[id]; ok {
		return s
	}
	return fmt.Sprintf("unknown (%d)", id)
}

func main() {
	var (
		keytabPath string
		aesOnly    bool
		principal  string
		asJSON     bool
	)

	flag.StringVar(&keytabPath, "keytab", "", "Path to keytab file (required)")
	flag.BoolVar(&aesOnly, "aes-only", false, "Show only AES enctypes (17, 18)")
	flag.StringVar(&principal, "principal", "", "Filter to a specific principal, e.g. DNS/ns.example.com@EXAMPLE.COM")
	flag.BoolVar(&asJSON, "json", false, "Print raw JSON from kt.JSON() and exit")
	flag.Parse()

	if keytabPath == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -keytab is required")
		flag.Usage()
		os.Exit(2)
	}

	kt, err := keytab.Load(keytabPath)
	if err != nil {
		log.Fatalf("load keytab: %v", err)
	}

	js, err := kt.JSON()
	if err != nil {
		log.Fatalf("keytab JSON: %v", err)
	}

	if asJSON {
		fmt.Println(js)
		return
	}

	var parsed KeytabJSON
	if err := json.Unmarshal([]byte(js), &parsed); err != nil {
		log.Fatalf("unmarshal: %v", err)
	}

	// Stable output: sort by principal, kvno, keytype
	sort.Slice(parsed.Entries, func(i, j int) bool {
		pi := fmt.Sprintf("%s@%s", strings.Join(parsed.Entries[i].Principal.Components, "/"), parsed.Entries[i].Principal.Realm)
		pj := fmt.Sprintf("%s@%s", strings.Join(parsed.Entries[j].Principal.Components, "/"), parsed.Entries[j].Principal.Realm)
		if pi != pj {
			return pi < pj
		}
		if parsed.Entries[i].KVNO != parsed.Entries[j].KVNO {
			return parsed.Entries[i].KVNO < parsed.Entries[j].KVNO
		}
		return parsed.Entries[i].Key.KeyType < parsed.Entries[j].Key.KeyType
	})

	for _, e := range parsed.Entries {
		p := fmt.Sprintf("%s@%s", strings.Join(e.Principal.Components, "/"), e.Principal.Realm)

		if principal != "" && !strings.EqualFold(p, principal) {
			continue
		}

		if aesOnly && e.Key.KeyType != 17 && e.Key.KeyType != 18 {
			continue
		}

		fmt.Printf("Principal: %s\n", p)
		fmt.Printf("KVNO: %d\n", e.KVNO)
		fmt.Printf("KeyType: %d (%s)\n", e.Key.KeyType, etypeToString(e.Key.KeyType))
		fmt.Printf("Timestamp: %s\n", e.Timestamp)
		fmt.Println("----")
	}
}
