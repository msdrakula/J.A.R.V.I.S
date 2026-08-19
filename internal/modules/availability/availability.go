package availability

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/msdrakula/J.A.R.V.I.S/internal/storage"
)

type Checker struct {
	store *storage.Store
}

func New(store *storage.Store) *Checker {
	return &Checker{store: store}
}

func (c *Checker) CheckTCP(scanID, host string, port int) (*storage.ServiceAvailability, error) {
	if c == nil {
		return nil, fmt.Errorf("availability checker is not initialized")
	}
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	result := &storage.ServiceAvailability{Host: host, Port: port, State: "closed"}
	if err != nil {
		if c.store != nil {
			_ = c.store.AddServiceAvailability(scanID, *result)
		}
		return result, nil
	}
	defer conn.Close()

	result.State = "open"
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if port == 80 || port == 443 {
		_, _ = conn.Write([]byte("GET / HTTP/1.0\r\nHost: " + host + "\r\n\r\n"))
	}

	reader := bufio.NewReader(conn)
	buf := make([]byte, 256)
	n, _ := reader.Read(buf)
	banner := strings.TrimSpace(string(buf[:n]))
	result.Banner = banner
	result.Service = guessService(port, banner)

	if c.store != nil {
		_ = c.store.AddServiceAvailability(scanID, *result)
	}
	return result, nil
}

func guessService(port int, banner string) string {
	b := strings.ToLower(banner)
	switch {
	case strings.Contains(b, "ssh"):
		return "ssh"
	case strings.Contains(b, "http"):
		return "http"
	case port == 443:
		return "https"
	case port == 80:
		return "http"
	case port == 22:
		return "ssh"
	default:
		return "unknown"
	}
}
