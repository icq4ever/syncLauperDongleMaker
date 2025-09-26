package main

import (
	"fmt"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"strings"

	"syncLauperDongleMaker/internal/binding"
	"syncLauperDongleMaker/internal/device"
	"syncLauperDongleMaker/internal/utils"
	"syncLauperDongleMaker/internal/disk"
	"syncLauperDongleMaker/internal/rp"
)

// === PROBE(식별자 조회) ===

// USB 디스크 후보만 수집 (TYPE=disk, TRAN=usb). nvme0n1 제외.
type usbDev struct {
    Path   string // /dev/sdX
    Size   string
    Model  string
    Serial string
}
func listUSBDiskCandidates() ([]usbDev, error) {
    out, err := exec.Command("lsblk", "-dn", "-o", "NAME,SIZE,MODEL,SERIAL,TRAN,TYPE").Output()
    if err != nil { return nil, err }
    var res []usbDev
    for _, ln := range strings.Split(strings.TrimSpace(string(out)), "\n") {
        if strings.TrimSpace(ln) == "" { continue }
        f := strings.Fields(ln)
        if len(f) < 6 { continue }
        name, size, tran, typ := f[0], f[1], f[len(f)-2], f[len(f)-1]
        if typ != "disk" || strings.ToLower(tran) != "usb" { continue }
        if name == "nvme0n1" { continue }
        model := strings.Join(f[2:len(f)-3], " ")
        serial := f[len(f)-3]
        res = append(res, usbDev{
            Path: "/dev/" + name, Size: size, Model: strings.TrimSpace(model), Serial: serial,
        })
    }
    return res, nil
}

// 부모 디스크(/dev/sdX) ↔ 파티션(/dev/sdX1) 정규화
func normalizePartAndParent(dev string) (part string, parent string, err error) {
    tby, _ := exec.Command("lsblk", "-no", "TYPE", dev).Output()
    typ := strings.TrimSpace(string(tby))
    if typ == "disk" {
        // 첫 파티션 선택
        pth, _ := exec.Command("bash", "-lc", fmt.Sprintf(`lsblk -nr -o PATH,TYPE "%s" | awk '$2=="part"{print $1; exit}'`, dev)).Output()
        p := strings.TrimSpace(string(pth))
        if p == "" { return "", "", fmt.Errorf("no partition found under %s", dev) }
        return p, dev, nil
    }
    // part → parent
    pk, _ := exec.Command("lsblk", "-no", "PKNAME", dev).Output()
    if strings.TrimSpace(string(pk)) == "" {
        return dev, "", fmt.Errorf("failed to get parent for %s", dev)
    }
    return dev, "/dev/" + strings.TrimSpace(string(pk)), nil
}

// 대화형: USB 리스트 → 번호 선택 → 식별자 일괄 표시
func interactiveProbe() error {
	list, err := listUSBDiskCandidates()
	if err != nil { return err }
	if len(list) == 0 { return fmt.Errorf("no USB disks found") }

	fmt.Println("Select USB disk to probe:")
	for i, d := range list {
		tag := ""
		if d.Serial != "" { tag = "  (" + d.Serial + ")" }
		fmt.Printf("  [%d] %s  %s  %s%s\n", i, d.Path, d.Size, d.Model, tag)
	}
	fmt.Print("Enter number [0]: ")
	var raw string
	var idx int
	if _, err := fmt.Scanln(&raw); err == nil && strings.TrimSpace(raw) != "" {
		fmt.Sscanf(raw, "%d", &idx)
	}
	if idx < 0 || idx >= len(list) { idx = 0 }
	disk := list[idx].Path

	// 파티션/부모 정규화
	part, parent, err := normalizePartAndParent(disk)
	if err != nil { return err }

	// UUID/크기
	fsu, _ := exec.Command("lsblk", "-no", "UUID", part).Output()
	pu,  _ := exec.Command("lsblk", "-no", "PARTUUID", part).Output()
	ptu, _ := exec.Command("lsblk", "-no", "PTUUID", parent).Output()
	size, _ := exec.Command("lsblk", "-no", "SIZE", parent).Output()
	sect, _ := exec.Command("blockdev", "--getsz", parent).Output()

	// udev props (부모 디스크 기준: 컨트롤러 시리얼/VID/PID 등)
	up, _ := exec.Command("udevadm", "info", "--query=property", "--name", parent).Output()
	kv := utils.ParseKVEq(string(up))
	idSerial      := strings.TrimSpace(kv["ID_SERIAL"])
	idSerialShort := strings.TrimSpace(kv["ID_SERIAL_SHORT"])
	vid := strings.ToLower(strings.TrimSpace(kv["ID_VENDOR_ID"]))
	pid := strings.ToLower(strings.TrimSpace(kv["ID_MODEL_ID"]))
	ven := strings.TrimSpace(kv["ID_VENDOR"])
	mod := strings.TrimSpace(kv["ID_MODEL"])
	wwn := strings.TrimSpace(kv["ID_WWN"])
	path := strings.TrimSpace(kv["ID_PATH"])

	// 출력
	fmt.Println("=== USB identifiers (probe) ===")
	fmt.Printf("device.part        : %s\n", part)
	fmt.Printf("device.parent      : %s\n", parent)
	fmt.Printf("size               : %s  (sectors=%s)\n", strings.TrimSpace(string(size)), strings.TrimSpace(string(sect)))
	// 첫 토큰만(개행/중복 방지)
	fF := func(b []byte) string { fs := strings.Fields(string(b)); if len(fs)>0 { return fs[0] }; return "" }
	fmt.Printf("fs_uuid            : %s\n", strings.ToUpper(fF(fsu)))
	fmt.Printf("partuuid           : %s\n", strings.ToLower(fF(pu)))
	fmt.Printf("ptuuid             : %s\n", strings.ToLower(fF(ptu)))
	fmt.Printf("id_serial          : %s\n", idSerial)
	fmt.Printf("id_serial_short    : %s\n", idSerialShort)
	fmt.Printf("vid_pid            : %s:%s\n", vid, pid)
	fmt.Printf("vendor_model       : %s %s\n", ven, mod)
	if wwn != ""  { fmt.Printf("id_wwn             : %s\n", wwn) }
	if path != "" { fmt.Printf("id_path            : %s\n", path) }
	
	// 바인딩 키 샘플(현재 baker 규칙과 동일)
	serialFull := idSerial
	if serialFull == "" { serialFull = idSerialShort }
	binding := strings.Join([]string{
		strings.ToUpper(fF(fsu)),
		strings.ToLower(fF(pu)),
		strings.ToLower(fF(ptu)),
		strings.ToUpper(strings.TrimSpace(serialFull)),
	}, "|")
	fmt.Printf("binding_key(sample): %s\n", binding)

	// 공용/의심 시리얼 경고
	s := strings.ToUpper(serialFull)
	if s == "" || strings.Contains(s, "GENERAL_UDISK") || s == "000000" || s == "123456" {
		fmt.Println("WARN: ID_SERIAL looks generic/empty. Consider blocking this model for issuance.")
	}
	return nil
}

func cmdProbe() {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)

	devFlag   := fs.String("device", "", "block device or partition (e.g. /dev/sdX or /dev/sdX1)")
	mountFlag := fs.String("mount",  "", "mount point (e.g. /media/usb)")
	portFlag  := fs.String("port",   "", "RP CDC port (e.g. /dev/ttyACM0)")

	jsonOut := fs.Bool("json",   false, "print snapshot as JSON")
	detail  := fs.Bool("detail", false, "verbose output")
	_ = fs.Parse(os.Args[2:])

	var insp device.Inspector

	switch {
	case *portFlag != "":
		// RP(Serial CDC) 백엔드
		insp = rp.CDCInspector{Port: *portFlag}

	case *devFlag != "":
		// 디스크: 파티션/디스크 직접 지정
		insp = disk.PartInspector{PartDev: *devFlag}

	case *mountFlag != "":
		// 디스크: 마운트 지점으로부터 디바이스 해석
		part, err := disk.DevFromMount(*mountFlag)
		must(err)
		insp = disk.PartInspector{PartDev: part}

	default:
		fatal("probe: either --port or --device/--mount is required")
	}

	snap, err := insp.Snapshot()
	must(err)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(snap)
		return
	}

	// 텍스트 출력
	if *detail {
		fmt.Println("=== device snapshot ===")
	}
	if snap.FsUUID != ""        { fmt.Printf("fs_uuid        : %s\n", snap.FsUUID) }
	if snap.PartUUID != ""      { fmt.Printf("partuuid       : %s\n", snap.PartUUID) }
	if snap.PTUUID != ""        { fmt.Printf("ptuuid         : %s\n", snap.PTUUID) }
	if snap.USBSerialFull != "" { fmt.Printf("usb_serial     : %s\n", snap.USBSerialFull) }

	// 바인딩 키 (디스크 기반일 때 의미 있음)
	if snap.FsUUID != "" || snap.PartUUID != "" || snap.PTUUID != "" {
		key := binding.BuildKeyV1(snap)
		fmt.Printf("binding_key    : %s\n", key)
	}
}