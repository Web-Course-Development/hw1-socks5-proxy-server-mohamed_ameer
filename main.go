package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
)

func main() {
	port := flag.Int("port", 1080, "proxy listen port")
	flag.Parse()

	addr := fmt.Sprintf(":%d", *port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Printf("Failed to listen: %v\n", err)
		return
	}
	fmt.Printf("Proxy listening on %s\n", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}



func handleConnection(conn net.Conn) {
	defer conn.Close()

	method, err := negotiateAuth(conn)
	if err != nil {
		fmt.Println("Handshake error:", err)
		return
	}

	if method == 0x02 {
		if err := authenticateUserPass(conn); err != nil {
			fmt.Println("Auth error:", err)
			return
		}
	}

	targetAddr, err := readConnectRequest(conn)
	if err != nil {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		fmt.Println("Read connect request error:", err)
		return
	}

	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		// שולחים הודעת שגיאה כללית ללקוח במקרה של כישלון
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		fmt.Printf("Failed to connect to target %s: %v\n", targetAddr, err)
		return
	}
	defer targetConn.Close()

	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		fmt.Println("Failed to send success reply:", err)
		return
	}

	relay(conn, targetConn)
}




func negotiateAuth(conn net.Conn) (byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, err
	}
	
	if header[0] != 0x05 {
		return 0, fmt.Errorf("unsupported SOCKS version")
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, err
	}

	reqUser := os.Getenv("PROXY_USER")
	requiredMethod := byte(0x00)
	if reqUser != "" {
		requiredMethod = 0x02
	}

	methodSupported := false
	for _, m := range methods {
		if m == requiredMethod {
			methodSupported = true
			break
		}
	}

	if !methodSupported {
		conn.Write([]byte{0x05, 0xFF})
		return 0, fmt.Errorf("method not supported")
	}

	conn.Write([]byte{0x05, requiredMethod})
	return requiredMethod, nil
}




func authenticateUserPass(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	
	if header[0] != 0x01 {
		return fmt.Errorf("unsupported auth version")
	}

	uLen := int(header[1])
	uName := make([]byte, uLen)
	if _, err := io.ReadFull(conn, uName); err != nil {
		return err
	}

	pLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, pLenBuf); err != nil {
		return err
	}

	pLen := int(pLenBuf[0])
	passWD := make([]byte, pLen)
	if _, err := io.ReadFull(conn, passWD); err != nil {
		return err
	}

	expectedUser := os.Getenv("PROXY_USER")
	expectedPass := os.Getenv("PROXY_PASS")

	if string(uName) == expectedUser && string(passWD) == expectedPass {
		conn.Write([]byte{0x01, 0x00})
		return nil
	}

	conn.Write([]byte{0x01, 0x01})
	return fmt.Errorf("authentication failed")
}


func readConnectRequest(conn net.Conn) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

	if header[0] != 0x05 || header[1] != 0x01 {
		return "", fmt.Errorf("unsupported command or version")
	}

	atyp := header[3]
	var host string

	switch atyp {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}
		domainLen := int(lenBuf[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		host = string(domain)
	default:
		return "", fmt.Errorf("unsupported address type")
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return fmt.Sprintf("%s:%d", host, port), nil
}


func relay(clientConn net.Conn, targetConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// מעביר מידע מהלקוח לשרת המטרה
	go func() {
		defer wg.Done()
		io.Copy(targetConn, clientConn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// מעביר מידע משרת המטרה חזרה ללקוח
	go func() {
		defer wg.Done()
		io.Copy(clientConn, targetConn)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}