// A trivial UDP echo server used as the tunnel target in interop tests.
// It prefixes a marker (default "echo:") so the client can confirm a round trip
// and tell two echo servers apart. Usage: udpecho <addr> [prefix]
package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	prefix := "echo:"
	if len(os.Args) > 2 {
		prefix = os.Args[2]
	}
	pc, err := net.ListenPacket("udp", os.Args[1])
	if err != nil {
		panic(err)
	}
	fmt.Println("udp echo on", pc.LocalAddr(), "prefix", prefix)
	buf := make([]byte, 65535)
	for {
		n, a, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		pc.WriteTo(append([]byte(prefix), buf[:n]...), a)
	}
}
