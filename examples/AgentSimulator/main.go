package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var input = flag.String("i", "", "Input filename")
var destAddr = flag.String("dest", "10.229.255.126", "dest ip addr")
var ronly = flag.Bool("ronly", false, "Read file only, do not sent, dafault: false")
var u = flag.Bool("u", true, "send udp data only, dafault: true")

func onTcpRead(conn *net.TCPConn) {
	msg := make([]byte, 100)
	for {
		n, err := conn.Read(msg)

		if err != nil || err == io.EOF {
			fmt.Println(err)
			break
		}
		if n > 0 {
			fmt.Println(string(msg[0:n]))
		}
	}
}

func main() {
	var handler *pcap.Handle
	var err error
	flag.Parse()
	if *input == "" {
		log.Fatalf("Please specify input filename")
	}
	if handler, err = pcap.OpenOffline(*input); err != nil {
		log.Fatalf("Failed to open: %s: %s", *input, err)
	}
	args := flag.Args()
	if len(args) > 0 {
		filter := strings.Join(args, " ")
		if err := handler.SetBPFFilter(filter); err != nil {
			log.Fatalf("Failed to set BPF filter \"%s\": %s", filter, err)
		}
		handler.Stats()
	}

	serverAddr6 := *destAddr + ":9996"
	udp6, err := net.Dial("udp", serverAddr6)
	if err != nil {
		log.Fatal("error connect to server:", err)
	}
	defer udp6.Close()

	serverAddr5 := *destAddr + ":9995"
	udp5, err := net.Dial("udp", serverAddr5)
	if err != nil {
		log.Fatal("error connect to server:", err)
	}
	defer udp5.Close()

	address := *destAddr + ":9994"
	tcpAddr, _ := net.ResolveTCPAddr("tcp", address)
	tcp4, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		log.Fatal("error connect to server:", err)
	}
	defer tcp4.Close()
	if *ronly == false || *u {
		go onTcpRead(tcp4)
	}

	var decoder gopacket.Decoder
	var ok bool
	linkType := fmt.Sprintf("%s", handler.LinkType())
	if decoder, ok = gopacket.DecodersByLayerName[linkType]; !ok {
		log.Fatalf("Failed to find decoder to pcap's linktype %s", linkType)
	}
	source := gopacket.NewPacketSource(handler, decoder)
	count := uint64(0)
	pktNonTcp := uint64(0)
	pktTcp := uint64(0)
	for packet := range source.Packets() {
		count++
		udp := packet.Layer(layers.LayerTypeUDP)
		if udp == nil {
			tcp := packet.Layer(layers.LayerTypeTCP)
			if tcp == nil {
				continue
			} else {
				if *u {
					continue
				}
				tcp := tcp.(*layers.TCP)
				if 9994 == tcp.DstPort {
					pktTcp++
					// fmt.Printf("send tcp to: %d \n", tcp.DstPort)
					if *ronly == false {
						_, err = tcp4.Write(tcp.Payload)
						if err != nil {
							log.Printf("error send tcp data.", err)
							tcp4.Close()
							time.Sleep(3 * time.Millisecond)
							tcp4, err = net.DialTCP("tcp", nil, tcpAddr)
							if err != nil {
								log.Fatal("error connect to server:", err)
							}
							defer tcp4.Close()
							tcp4.Write(tcp.Payload)
							go onTcpRead(tcp4)
						} else {
							time.Sleep(time.Millisecond)
						}
					}
				}
			}
		} else {
			pktNonTcp++
			udp := udp.(*layers.UDP)
			//fmt.Printf("packet: %s\n", tcp)
			//var b bytes.Buffer
			//b.WriteString("{\n")
			// TCP
			//b.WriteString("tcp: layers.TCP{\n")
			/*if udp.SYN {
				b.WriteString("  SYN: true,\n")
			}
			if udp.ACK {
				b.WriteString("  ACK: true,\n")
			}
			if udp.RST {
				b.WriteString("  RST: true,\n")
			}
			if udp.FIN {
				b.WriteString("  FIN: true,\n")
			}*/
			//b.WriteString(fmt.Sprintf("  SrcPort: %d,\n", udp.SrcPort))
			//b.WriteString(fmt.Sprintf("  DstPort: %d,\n", udp.DstPort))
			//b.WriteString(fmt.Sprintf("  Seq: %d,\n", udp.Seq))
			//b.WriteString(fmt.Sprintf("  Ack: %d,\n", udp.Ack))
			//b.WriteString("  BaseLayer: layers.BaseLayer{Payload: []byte{")
			if *u {
				fmt.Printf("send udp to: %d \n", udp.DstPort)
			}

			if *ronly == false {
				if 9996 == udp.DstPort {
					udp6.Write(udp.Payload)
				} else if 9995 == udp.DstPort {
					udp5.Write(udp.Payload)
				}
			}
			//b.WriteString(string(udp.Payload))
			//b.WriteString("}},\n")
			//b.WriteString("},\n")
			// CaptureInfo
			//b.WriteString("ci: gopacket.CaptureInfo{\n")
			//ts := packet.Metadata().CaptureInfo.Timestamp
			//b.WriteString(fmt.Sprintf("  Timestamp: time.Unix(%d,%d),\n", ts.Unix(), ts.Nanosecond()))
			//b.WriteString("},\n")
			// Struct
			//b.WriteString("},\n")
			//fmt.Print(b.String())
			//break
		}

	}

	fmt.Fprintf(os.Stderr, "Total: %d, TCP: %d, UDP: %d\n", count, pktTcp, pktNonTcp)
}
