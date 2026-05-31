// udpsend <addr> <message>: send one UDP datagram and print the first reply.
// Used to drive the zeromasque client's local UDP proxy in interop tests.
package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	c, err := net.Dial("udp", os.Args[1])
	if err != nil {
		fmt.Println("DIAL", err)
		os.Exit(1)
	}
	defer c.Close()
	if _, err := c.Write([]byte(os.Args[2])); err != nil {
		fmt.Println("WRITE", err)
		os.Exit(1)
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		fmt.Println("READ ERROR:", err)
		os.Exit(1)
	}
	fmt.Printf("%s\n", string(buf[:n]))
}
