package pcap

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type Session struct {
	SessionID string   `json:"session_id"`
	Protocol  string   `json:"protocol"`
	Client    string   `json:"client"`
	Server    string   `json:"server"`
	StartTLS  bool     `json:"starttls"`
	TLS       *TLSInfo `json:"tls,omitempty"`
	Findings  []string `json:"findings"`
}

type TLSInfo struct {
	Version     string `json:"version"`
	CipherSuite string `json:"cipher_suite"`
}

var currentSessions map[string]*Session

type StreamFactory struct{}

type Stream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (f *StreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	s := &Stream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go s.run()
	return &s.r
}

func (s *Stream) run() {
	var payload []byte
	buf := make([]byte, 4096)

	src := fmt.Sprintf("%s:%s", s.net.Src().String(), s.transport.Src().String())
	dst := fmt.Sprintf("%s:%s", s.net.Dst().String(), s.transport.Dst().String())

	var sessionID string
	if src < dst {
		sessionID = src + "-" + dst
	} else {
		sessionID = dst + "-" + src
	}

	session, exists := currentSessions[sessionID]
	if !exists {
		session = &Session{
			SessionID: sessionID,
			Client:    src,
			Server:    dst,
			Findings:  []string{},
		}
		currentSessions[sessionID] = session
	}

	for {
		numBytes, err := s.r.Read(buf)
		if err != nil {
			break
		}
		chunk := buf[:numBytes]
		payload = append(payload, chunk...)

		strChunk := string(chunk)
		if session.Protocol == "" {
			if strings.Contains(strChunk, "EHLO") || strings.Contains(strChunk, "220 ") {
				session.Protocol = "SMTP"
			} else if strings.Contains(strChunk, "* OK") || strings.Contains(strChunk, "CAPABILITY") {
				session.Protocol = "IMAP"
			} else if strings.Contains(strChunk, "+OK") || strings.Contains(strChunk, "USER ") {
				session.Protocol = "POP3"
			}
		}

		// Detect STARTTLS
		if strings.Contains(strChunk, "STARTTLS") || strings.Contains(strChunk, "STLS") {
			session.StartTLS = true
		}

		// Dynamic TLS Server Hello Parsing
		if session.TLS == nil && len(payload) > 45 {
			for i := 0; i < len(payload)-45; i++ {
				// TLS Handshake (0x16) and Server Hello (0x02)
				if payload[i] == 0x16 && payload[i+1] == 0x03 && payload[i+5] == 0x02 {
					vMajor, vMinor := payload[i+9], payload[i+10]
					versionStr := "Unknown TLS"
					if vMajor == 0x03 {
						switch vMinor {
						case 0x01: versionStr = "TLS 1.0"
						case 0x02: versionStr = "TLS 1.1"
						case 0x03: versionStr = "TLS 1.2"
						case 0x04: versionStr = "TLS 1.3"
						}
					}

					sessionIDLen := int(payload[i+43])
					if i+44+sessionIDLen+1 < len(payload) {
						cs1 := payload[i+44+sessionIDLen]
						cs2 := payload[i+44+sessionIDLen+1]
						
						cipherStr := fmt.Sprintf("0x%02X%02X", cs1, cs2)
						if cs1 == 0x00 && cs2 == 0x0a {
							cipherStr = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
						} else if cs1 == 0xc0 && cs2 == 0x2f {
							cipherStr = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
						} else if cs1 == 0xc0 && cs2 == 0x30 {
							cipherStr = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
						}

						session.TLS = &TLSInfo{
							Version:     versionStr,
							CipherSuite: cipherStr,
						}
						session.Findings = append(session.Findings, "TLS_DETECTED")
						if versionStr == "TLS 1.0" || versionStr == "TLS 1.1" {
							session.Findings = append(session.Findings, "OBSOLETE_VERSION_DETECTED")
						}
						break
					}
				}
			}
		}
	}
}

func AnalyzeFile(filePath string) ([]Session, error) {
	currentSessions = make(map[string]*Session)

	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap file: %v", err)
	}
	defer f.Close()

	var packetSource *gopacket.PacketSource

	// Try reading as PCAPNG first
	ngReader, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err == nil {
		packetSource = gopacket.NewPacketSource(ngReader, ngReader.LinkType())
	} else {
		// Rewind and try classic PCAP
		f.Seek(0, 0)
		pcapReader, err2 := pcapgo.NewReader(f)
		if err2 != nil {
			return nil, errors.New("failed to read as pcap or pcapng")
		}
		packetSource = gopacket.NewPacketSource(pcapReader, pcapReader.LinkType())
	}

	streamFactory := &StreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	for packet := range packetSource.Packets() {
		if packet == nil {
			continue
		}

		tcp := packet.Layer(layers.LayerTypeTCP)
		if tcp != nil {
			tcpLayer := tcp.(*layers.TCP)
			assembler.AssembleWithTimestamp(
				packet.NetworkLayer().NetworkFlow(),
				tcpLayer,
				packet.Metadata().Timestamp,
			)
		}
	}

	assembler.FlushAll()
	time.Sleep(1 * time.Second)

	results := make([]Session, 0)
	for _, s := range currentSessions {
		if s.Protocol != "" {
			results = append(results, *s)
		}
	}

	return results, nil
}
