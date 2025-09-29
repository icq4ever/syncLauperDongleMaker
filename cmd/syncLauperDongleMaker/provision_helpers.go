// cmd/syncLauperDongleMaker/provision_helpers.go
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/tarm/serial"
	"syncLauperDongleMaker/internal/keys"
)

// ----------------- Serial helpers (used by provision.go) -----------------

func listCDCSerialPorts() []string {
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

func mustOpenSerial(port string, baud int) (*serial.Port, *bufio.Reader) {
	c := &serial.Config{Name: port, Baud: baud, ReadTimeout: 2 * time.Second}
	s, err := serial.OpenPort(c)
	if err != nil {
		fatal("open serial %s: %v", port, err)
	}
	br := bufio.NewReader(s)
	// Flush if available (ignore error)
	_ = s.Flush()
	return s, br
}

func writeLine(w io.Writer, s string) {
	io.WriteString(w, s)
	io.WriteString(w, "\n")
}

func writeExact(w io.Writer, b []byte) error {
	n, err := w.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	return nil
}

// readLineWithDuration reads a line from bufio.Reader with timeout (returns trimmed line or "")
func readLineWithDuration(r *bufio.Reader, d ...time.Duration) string {
	timeout := 5 * time.Second
	if len(d) > 0 && d[0] > 0 {
		timeout = d[0]
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	type resp struct {
		line string
		err  error
	}
	ch := make(chan resp, 1)
	go func() {
		line, err := r.ReadString('\n')
		if err == nil {
			line = strings.TrimRight(line, "\r\n")
		}
		ch <- resp{line: line, err: err}
	}()

	select {
	case <-ctx.Done():
		return ""
	case x := <-ch:
		if x.err != nil {
			return ""
		}
		return strings.TrimSpace(x.line)
	}
}

// expectUIDLine: try a few times to read a non-empty line (return uppercase)
func expectUIDLine(r *bufio.Reader) (string, error) {
	for i := 0; i < 8; i++ {
		l := strings.TrimSpace(readLineWithDuration(r, 2*time.Second))
		if l == "" {
			continue
		}
		// accept raw UID text (if you used "UID XXXXX" protocol adjust here)
		return strings.ToUpper(l), nil
	}
	return "", fmt.Errorf("UID not received")
}

// waitFor: keep reading lines until one equals or has prefix in wants (ignore DBG: lines)
// returns the matched full line
func waitFor(r *bufio.Reader, timeout time.Duration, wants ...string) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		l := strings.TrimSpace(readLineWithDuration(r, 2*time.Second))
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "DBG:") {
			fmt.Println("[DEV]", l)
			continue
		}
		for _, w := range wants {
			if l == w || strings.HasPrefix(l, w) {
				return l, nil
			}
		}
		// otherwise ignore and continue
	}
	return "", fmt.Errorf("timeout waiting for %v", wants)
}

func expectOK(r *bufio.Reader) error {
	_, err := waitFor(r, 5*time.Second, "OK")
	return err
}
func expectReady(r *bufio.Reader) error {
	_, err := waitFor(r, 5*time.Second, "OK:READY")
	return err
}
func expectWrote(r *bufio.Reader) error {
	_, err := waitFor(r, 5*time.Second, "OK:WROTE")
	return err
}
func expectRebooting(r *bufio.Reader) error {
	_, err := waitFor(r, 8*time.Second, "OK:REBOOTING", "OK")
	return err
}

// ----------------- misc helpers -----------------

func randomNonceHex(nBytes int) string {
	if nBytes <= 0 {
		nBytes = 12
	}
	buf := make([]byte, nBytes)
	_, _ = rand.Read(buf)
	return strings.ToUpper(hex.EncodeToString(buf))
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func parseRFC3339Z(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// mustLoadPriv: internal/keys의 LoadEd25519PrivFromPEM을 호출하고 실패하면 종료.
// provision.go 등에서 기존에 기대한 동작(must* 스타일)을 보장.
func mustLoadPriv(path string) ed25519.PrivateKey {
	priv, err := keys.LoadEd25519PrivFromPEM(path)
	if err != nil {
		fatal("read key %s: %v", path, err)
	}
	return priv
}

func printIssuedUTCandKST(label string, t time.Time) {
	utc := t.UTC().Format(time.RFC3339)
	loc, _ := time.LoadLocation("Asia/Seoul")
	kst := t.In(loc).Format(time.RFC3339)
	fmt.Printf("  %-10s = UTC %s\n", label, utc)
	fmt.Printf("               KST %s\n", kst)
}
