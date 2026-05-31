// A trivial UDP echo server used as the tunnel target in interop tests.
// It prefixes "echo:" so the client can confirm a round trip.
package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	pc, err := net.ListenPacket("udp", os.Args[1])
	if err != nil {
		panic(err)
	}
	fmt.Println("udp echo on", pc.LocalAddr())
	buf := make([]byte, 65535)
	for {
		n, a, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		pc.WriteTo(append([]byte("echo:"), buf[:n]...), a)
	}
}
