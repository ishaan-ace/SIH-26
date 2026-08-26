package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"securemailscope/analyzer/pcap"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <pcap_file>", os.Args[0])
	}

	filePath := os.Args[1]

	findings, err := pcap.AnalyzeFile(filePath)
	if err != nil {
		log.Fatalf("Error analyzing pcap: %v", err)
	}

	// Print JSON to stdout for the Node backend to consume
	output, err := json.Marshal(findings)
	if err != nil {
		log.Fatalf("Error marshaling JSON: %v", err)
	}

	fmt.Println(string(output))
}
