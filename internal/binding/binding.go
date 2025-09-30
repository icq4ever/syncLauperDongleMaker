package binding

import (
	"os/exec"
	"strings"

	"syncLauperDongleMaker/internal/device"
	"syncLauperDongleMaker/internal/utils"
)

func CollectBindingInfo(devPart string) (device.Snapshot, error) {
	var d device.Snapshot

	// FS UUID, PARTUUID, PKNAME(부모 디스크 이름)
	uout, err := exec.Command("lsblk", "-no", "UUID,PARTUUID,PKNAME", devPart).Output()
	if err != nil {
		return d, err
	}
	fs := strings.Fields(string(uout))
	if len(fs) > 0 {
		d.FsUUID = strings.ToUpper(strings.TrimSpace(fs[0]))
	}
	if len(fs) > 1 {
		d.PartUUID = strings.ToLower(strings.TrimSpace(fs[1]))
	}

	parent := ""
	if len(fs) > 2 {
		parent = strings.TrimSpace(fs[2])
	}

	if parent != "" {
		// PTUUID: 부모 디스크 기준
		pout, _ := exec.Command("lsblk", "-no", "PTUUID", "/dev/"+parent).Output()
		pt := strings.Fields(string(pout))
		if len(pt) > 0 {
			d.PTUUID = strings.ToLower(strings.TrimSpace(pt[0]))
		}

		// udev props: 부모 디스크 기준(시리얼/VID/PID 등은 여기)
		props, _ := exec.Command("udevadm", "info", "--query=property", "--name", "/dev/"+parent).Output()
		kv := utils.ParseKVEq(string(props))
		serialFull := kv["ID_SERIAL"]
		if serialFull == "" {
			serialFull = kv["ID_SERIAL_SHORT"]
		}
		d.USBSerialFull = strings.ToUpper(strings.TrimSpace(serialFull))
	} else {
		// 부모를 못 찾았으면 최소한 devPart로 시도(폴백)
		props, _ := exec.Command("udevadm", "info", "--query=property", "--name", devPart).Output()
		kv := utils.ParseKVEq(string(props))
		serialFull := kv["ID_SERIAL"]
		if serialFull == "" {
			serialFull = kv["ID_SERIAL_SHORT"]
		}
		d.USBSerialFull = strings.ToUpper(strings.TrimSpace(serialFull))
	}

	return d, nil
}

// 바인딩: UUID 3종 + 컨트롤러 시리얼(Full)
func BuildKeyV1(d device.Snapshot) string {
	return strings.Join([]string{
		strings.ToUpper(d.FsUUID),
		strings.ToLower(d.PartUUID),
		strings.ToLower(d.PTUUID),
		strings.ToUpper(d.USBSerialFull),
	}, "|")
}

// BuildKeyV2은 UID까지 포함하는 바인딩 키를 생성한다.
func BuildKeyV2(d device.Snapshot, uid string) string {
	return strings.Join([]string{
		strings.ToUpper(d.FsUUID),
		strings.ToLower(d.PartUUID),
		strings.ToLower(d.PTUUID),
		strings.ToUpper(strings.TrimSpace(uid)),
	}, "|")
}
