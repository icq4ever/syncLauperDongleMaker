// internal/rp/serial.go
package rp

import (
	"bufio"
	"path/filepath"
	"fmt"
	"runtime"
	"sort"
	"time"

	"github.com/tarm/serial"
)

// ListCDCSerialPorts finds likely CDC/ACM ports on the host (same logic as before).
func ListCDCSerialPorts() []string {
	var globs []string
	switch runtime.GOOS {
	case "linux":
		globs = []string{"/dev/ttyACM*", "/dev/ttyUSB*"}
	case "darwin":
		globs = []string{"/dev/tty.usbmodem*", "/dev/tty.usbserial*"}
	case "windows":
		var ports []string
		for i := 1; i <= 40; i++ {
			ports = append(ports, fmt.Sprintf("COM%d", i))
		}
		return ports
	default:
		globs = []string{"/dev/ttyACM*", "/dev/ttyUSB*"}
	}
	m := map[string]bool{}
	for _, g := range globs {
		ms, _ := filepath.Glob(g)
		for _, p := range ms {
			m[p] = true
		}
	}
	ports := make([]string, 0, len(m))
	for p := range m {
		ports = append(ports, p)
	}
	sort.Strings(ports)
	return ports
}

// OpenCDC opens a serial port and returns *serial.Port and *bufio.Reader
func OpenCDC(port string, baud int) (*serial.Port, *bufio.Reader, error) {
	c := &serial.Config{Name: port, Baud: baud, ReadTimeout: 2 * time.Second}
	s, err := serial.OpenPort(c)
	if err != nil {
		return nil, nil, err
	}
	br := bufio.NewReader(s)
	_ = s.Flush()
	return s, br, nil
}
