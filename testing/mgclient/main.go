// A CONNECT-UDP client built on the masque-go *library* (the reference
// implementation), used to exercise the zeromasque server. It dials the proxy,
// tunnels one datagram to the target, and prints the reply.
//
// Usage: mgclient <proxy-uri-template> <target host:port> <message>
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	tmpl, target, msg := os.Args[1], os.Args[2], os.Args[3]
	cl := masque.Client{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}},
		QUICConfig:      &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350},
	}
	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pconn, rsp, err := cl.Dial(ctx, uritemplate.MustNew(tmpl), raddr)
	if err != nil {
		fmt.Println("DIAL FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("CONNECT-UDP response status:", rsp.StatusCode)
	if _, err := pconn.WriteTo([]byte(msg), raddr); err != nil {
		fmt.Println("WRITE FAILED:", err)
		os.Exit(1)
	}
	pconn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := pconn.ReadFrom(buf)
	if err != nil {
		fmt.Println("READ FAILED:", err)
		os.Exit(1)
	}
	fmt.Printf("TUNNELED RESPONSE (%d bytes): %s\n", n, string(buf[:n]))
}
