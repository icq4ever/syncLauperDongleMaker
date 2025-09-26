package rp

import (
	"os/exec"
	"strings"

	"syncLauperDongleMaker/internal/device"
)

type CDCInspector struct {
	Port string // e.g. /dev/ttyACM0
}

func (c CDCInspector) Snapshot() (device.Snapshot, error) {
	var s device.Snapshot

	// 최소 구현: CDC 인터페이스의 USB Serial만 채움
	// udevadm info --query=property --name /dev/ttyACM0
	out, err := exec.Command("udevadm", "info", "--query=property", "--name", c.Port).Output()
	if err != nil {
		return s, err
	}
	m := parseKVEq(string(out))
	serial := strings.TrimSpace(m["ID_SERIAL"])
	if serial == "" {
		serial = strings.TrimSpace(m["ID_SERIAL_SHORT"])
	}
	s.USBSerialFull = strings.ToUpper(serial)
	// FsUUID/PartUUID/PTUUID는 CDC만으로 얻기 어려워 우선 공란 유지.
	return s, nil
}

func parseKVEq(s string) map[string]string {
	m := map[string]string{}
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		i := strings.IndexByte(ln, '=')
		if i <= 0 {
			continue
		}
		k := strings.TrimSpace(ln[:i])
		v := strings.TrimSpace(ln[i+1:])
		m[k] = v
	}
	return m
}
