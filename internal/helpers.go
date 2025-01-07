package internal

import "net"

func AssertTCPConn(conn net.Conn) *net.TCPConn {
	if tcpConn, ok := conn.(*net.TCPConn); !ok {
		panic("Not a tcp conn")
	} else {
		return tcpConn
	}
}
