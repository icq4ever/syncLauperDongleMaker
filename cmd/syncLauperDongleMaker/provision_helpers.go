package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"syncLauperDongleMaker/internal/keys"

	"github.com/tarm/serial"
)

/* ----------------- key helpers ----------------- */

// mustLoadPriv: internal/keys의 LoadEd25519PrivFromPEM을 호출하고 실패하면 fatal.
// provision.go 등에서 기존에 기대한 동작(must* 스타일)을 보장.
func mustLoadPriv(path string) ed25519.PrivateKey {
	priv, err := keys.LoadEd25519PrivFromPEM(path)
	if err != nil {
		fatal("read key %s: %v", path, err)
	}
	return priv
}

/* ----------------- misc crypto / time helpers ----------------- */

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// decodeSignature: 서명 파일이 base64인지 바이너리인지 자동 판별하여 디코딩
// Ed25519 서명은 64바이트여야 함
func decodeSignature(data []byte) ([]byte, error) {
	// 이미 64바이트 바이너리면 그대로 반환
	if len(data) == 64 {
		return data, nil
	}

	// base64 디코딩 시도
	trimmed := strings.TrimSpace(string(data))
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err == nil && len(decoded) == 64 {
		return decoded, nil
	}

	// 둘 다 실패하면 에러
	return nil, fmt.Errorf("invalid signature format (expected 64 bytes or base64, got %d bytes)", len(data))
}

func randomNonceHex(nBytes int) string {
	if nBytes <= 0 {
		nBytes = 12
	}
	buf := make([]byte, nBytes)
	_, err := crand.Read(buf)
	if err != nil {
		// crypto/rand 실패 시 fallback to time-seeded pseudo random (best-effort)
		for i := range buf {
			buf[i] = byte(time.Now().UnixNano() >> (uint(i%8) * 8))
		}
	}
	return strings.ToUpper(hex.EncodeToString(buf))
}

func parseRFC3339Z(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

func printIssuedUTCandKST(label string, t time.Time) {
	utc := t.UTC().Format(time.RFC3339)
	loc, _ := time.LoadLocation("Asia/Seoul")
	kst := t.In(loc).Format(time.RFC3339)
	fmt.Printf("  %-10s = UTC %s\n", label, utc)
	fmt.Printf("               KST %s\n", kst)
}

/* ----------------- serial / io helpers ----------------- */

// listCDCSerialPorts: platform-specific globs for CDC devices
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

// mustOpenSerial: open serial port and return it + bufio.Reader
func mustOpenSerial(port string, baud int) (*serial.Port, *bufio.Reader) {
	c := &serial.Config{Name: port, Baud: baud, ReadTimeout: 2 * time.Second}
	s, err := serial.OpenPort(c)
	if err != nil {
		fatal("open serial %s: %v", port, err)
	}
	br := bufio.NewReader(s)
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

// readLineWithDuration: r.ReadString('\n') but with an overall timeout
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

// expectUIDLine: GET-UID 후 나오는 UID를 읽음. (몇 번 재시도)
func expectUIDLine(r *bufio.Reader) (string, error) {
	for i := 0; i < 8; i++ {
		l := strings.TrimSpace(readLineWithDuration(r, 2*time.Second))
		if l == "" {
			continue
		}
		// Accept lines like "DBG: UID=..." as well: extract token after '=' if present
		if strings.HasPrefix(l, "DBG:") {
			// print the debug for operator
			fmt.Println("[DEV]", l)
			if idx := strings.Index(l, "UID="); idx >= 0 {
				val := strings.TrimSpace(l[idx+4:])
				if val != "" {
					return val, nil
				}
			}
			continue
		}
		// otherwise take the line
		return l, nil
	}
	return "", fmt.Errorf("UID not received")
}

// expectBindingLine: GET-BINDING 후 나오는 BINDING 라인을 읽음
// 예상 포맷: "BINDING fs_uuid=XXXX partuuid=YYYY ptuuid=ZZZZ"
func expectBindingLine(r *bufio.Reader) (string, error) {
	for i := 0; i < 8; i++ {
		l := strings.TrimSpace(readLineWithDuration(r, 2*time.Second))
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "DBG:") {
			fmt.Println("[DEV]", l)
			// DBG 라인에 BINDING이 있는 경우도 처리
			if idx := strings.Index(l, "BINDING"); idx >= 0 {
				rest := strings.TrimSpace(l[idx+7:])
				if rest != "" {
					return rest, nil
				}
			}
			continue
		}
		// "BINDING ..." 형태 또는 key=value 형태 둘 다 받음
		if strings.HasPrefix(l, "BINDING ") {
			return strings.TrimSpace(l[8:]), nil
		}
		// 그냥 key=value 나열인 경우도 받음
		if strings.Contains(l, "=") {
			return l, nil
		}
	}
	return "", fmt.Errorf("BINDING not received")
}

// parseBindingLine: "fs_uuid=XXXX partuuid=YYYY ptuuid=ZZZZ" → binding key 생성
// USB 동글의 BuildKeyV1과 동일한 방식: "fs_uuid|partuuid|ptuuid"
func parseBindingLine(line string) string {
	fields := strings.Fields(line)
	binds := make(map[string]string)
	for _, f := range fields {
		parts := strings.SplitN(f, "=", 2)
		if len(parts) == 2 {
			binds[parts[0]] = parts[1]
		}
	}
	// USB 동글과 동일한 키 순서
	fsUUID := strings.ToUpper(strings.TrimSpace(binds["fs_uuid"]))
	partUUID := strings.ToLower(strings.TrimSpace(binds["partuuid"]))
	ptUUID := strings.ToLower(strings.TrimSpace(binds["ptuuid"]))

	return fsUUID + "|" + partUUID + "|" + ptUUID
}

// waitFor: read lines until a wanted line or prefix appears (ignores DBG: lines)
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
		// otherwise ignore and loop
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

// expectRebootOrDisconnect waits for OK:REBOOTING or device disconnect (portPath disappears).
func expectRebootOrDisconnect(br *bufio.Reader, portPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	consecutiveEmptyReads := 0
	sawOK := false

	for time.Now().Before(deadline) {
		l := strings.TrimSpace(readLineWithDuration(br, 2*time.Second))

		if l == "" {
			consecutiveEmptyReads++
			// After multiple empty reads, assume device disconnected
			if consecutiveEmptyReads >= 3 {
				// check if port file disappeared (re-enumeration)
				if _, err := os.Stat(portPath); os.IsNotExist(err) {
					fmt.Println("Device disconnected (port disappeared)")
					return nil
				}
				// Port still exists but no data - if we already saw OK, consider it success
				if sawOK {
					fmt.Println("Device disconnected (saw OK, now silent)")
					return nil
				}
			}
			continue
		}

		// Reset counter on successful read
		consecutiveEmptyReads = 0

		if strings.HasPrefix(l, "DBG:") {
			fmt.Println("[DEV]", l)
			continue
		}

		if l == "OK" || strings.HasPrefix(l, "OK:REBOOTING") || strings.HasPrefix(l, "OK:") {
			fmt.Println("Got OK response, waiting for device reconnection...")
			sawOK = true
			// Don't return immediately, wait a bit for disconnect
			continue
		}

		if strings.HasPrefix(l, "ERR:") {
			return fmt.Errorf("%s", strings.TrimPrefix(l, "ERR:"))
		}
	}

	// final check: port gone -> success
	if _, err := os.Stat(portPath); os.IsNotExist(err) {
		fmt.Println("Device disconnected (timeout but port gone)")
		return nil
	}

	// If we saw OK but timeout, consider it success (device may have rebooted)
	if sawOK {
		fmt.Println("Device likely rebooted (saw OK)")
		return nil
	}

	return fmt.Errorf("timeout waiting for OK or device disconnect")
}