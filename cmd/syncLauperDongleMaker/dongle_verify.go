// cmd/dongle_verify.go
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"syncLauperDongleMaker/internal/binding"
	"syncLauperDongleMaker/internal/config"
	"syncLauperDongleMaker/internal/device"
	"syncLauperDongleMaker/internal/disk"
	"syncLauperDongleMaker/internal/keys"
	"syncLauperDongleMaker/internal/licmodel"
	"syncLauperDongleMaker/internal/utils"
)

func cmdDongleVerify() {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)

	mountFlag := fs.String("mount", "", "mount point of the dongle (e.g. /media/dongle)")
	devFlag := fs.String("device", "", "device/partition (e.g. /dev/sdX1); overrides --mount if set")
	portFlag := fs.String("port", "", "CDC serial port for RP dongle (required for version 2)")
	pubPath := fs.String("pub", config.ProvPubDefault, "Ed25519 public key PEM (PKIX)")
	detail := fs.Bool("detail", false, "show device snapshot and calculated keys")
	jsonOut := fs.Bool("json", false, "print result as JSON")
	_ = fs.Parse(os.Args[2:])

	if *pubPath == "" {
		fatal("verify: --pub is required")
	}

	const defaultMount = "/media/dongle"
	mountPath := strings.TrimSpace(*mountFlag)
	partDev := strings.TrimSpace(*devFlag)
	if mountPath == "" && partDev == "" {
		mountPath = defaultMount
	}
	if partDev == "" {
		if mountPath == "" {
			fatal("verify: either --mount or --device is required")
		}
		dev, err := disk.DevFromMount(mountPath)
		must(err)
		partDev = dev
	}

	// 2) license 파일 로드
	licBytes, sigBytes := readLicensePair(mountPath, partDev)

	// 2.5) 서명 디코딩 (바이너리 또는 base64 자동 판별)
	// 현재는 바이너리 64바이트를 표준으로 사용 (USB 동글과 통일)
	// 하지만 이전 base64 형식도 호환성을 위해 지원
	sigDecoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigBytes)))
	if err != nil || len(sigDecoded) != 64 {
		// base64 디코딩 실패 또는 길이 불일치 시 원본 바이너리 사용
		sigDecoded = sigBytes
	}

	// 3) 서명 검증
	pub, err := keys.LoadEd25519PubFromPEM(*pubPath)
	must(err)
	if !keys.VerifyEd25519(pub, licBytes, sigDecoded) {
		// Verify 실패는 명확하게 코드 10으로 나눔
		fmt.Println("signature: BAD")
		os.Exit(10)
	}
	fmt.Println("signature: OK")

	// 4) license.json 파싱
	var lic licmodel.License
	must(json.Unmarshal(licBytes, &lic))

	// 5) 로컬 스냅샷 → 바인딩/시리얼 재계산
	snap, err := binding.CollectBindingInfo(partDev)
	must(err)
	// 안전하게 트림
	snap.FsUUID = strings.ToUpper(strings.TrimSpace(snap.FsUUID)) // 예: 대문자 유지용 헬퍼가 없으면 아래와 같이 직접 Trim만
	snap.PartUUID = strings.ToLower(strings.TrimSpace(snap.PartUUID))
	snap.PTUUID = strings.ToLower(strings.TrimSpace(snap.PTUUID))
	snap.USBSerialFull = strings.ToUpper(strings.TrimSpace(snap.USBSerialFull))

	var (
		localBinding string
		uidUsed      string
	)

	switch lic.Version {
	case 0, 1:
		localBinding = binding.BuildKeyV1(snap)
	case 2:
		port := strings.TrimSpace(*portFlag)
		if port == "" {
			ports := listCDCSerialPorts()
			if len(ports) == 0 {
				fatal("verify: version 2 license requires a CDC port, none detected")
			}
			fmt.Println("Select CDC port for UID probe:")
			for i, p := range ports {
				fmt.Printf("  [%d] %s\n", i, p)
			}
			fmt.Print("Enter number [0]: ")
			r := newLineReader()
			choice := strings.TrimSpace(readLine(r))
			if choice == "" {
				choice = "0"
			}
			idx := 0
			fmt.Sscanf(choice, "%d", &idx)
			if idx < 0 || idx >= len(ports) {
				fatal("verify: invalid port selection")
			}
			port = ports[idx]
			fmt.Printf("Using port %s\n", port)
		}
		s, br := mustOpenSerial(port, 115200)
		defer s.Close()
		writeLine(s, "GET-UID")
		uid, err := expectUIDLine(br)
		if err != nil {
			fatal("GET-UID: %v", err)
		}
		uidUsed = strings.ToUpper(strings.TrimSpace(uid))
		if uidUsed == "" {
			fatal("verify: empty UID received from %s", port)
		}
		writeLine(s, "GET-BINDING")
		bindingLine, err := expectBindingLine(br)
		if err != nil {
			fatal("GET-BINDING: %v", err)
		}
		remoteSnap := parseBindingLine(bindingLine)
		if remoteSnap.FsUUID != "" {
			snap.FsUUID = remoteSnap.FsUUID
		}
		if remoteSnap.PartUUID != "" {
			snap.PartUUID = remoteSnap.PartUUID
		}
		if remoteSnap.PTUUID != "" {
			snap.PTUUID = remoteSnap.PTUUID
		}
		localBinding = binding.BuildKeyV2(remoteSnap, uidUsed)
	default:
		fatal("verify: unsupported license version %d", lic.Version)
	}

	localSerial := utils.Sha256Hex(localBinding + "|" + lic.IssuedAt.UTC().Format(time.RFC3339))

	// 6) detail 출력
	if *detail {
		fmt.Println("device snapshot (admin view):")
		if snap.FsUUID != "" {
			fmt.Printf("  fs_uuid        = %s\n", snap.FsUUID)
		}
		if snap.PartUUID != "" {
			fmt.Printf("  partuuid       = %s\n", snap.PartUUID)
		}
		if snap.PTUUID != "" {
			fmt.Printf("  ptuuid         = %s\n", snap.PTUUID)
		}
		if snap.USBSerialFull != "" {
			fmt.Printf("  usb_serial     = %s\n", snap.USBSerialFull)
		}

		fmt.Println("calculated keys:")
		utils.PrintIssuedUTCandKST("issued_at", lic.IssuedAt)
		fmt.Printf("  binding_key (local)    = %s\n", localBinding)
		if lic.Version == 2 && uidUsed != "" {
			fmt.Printf("  uid (cdc)              = %s\n", uidUsed)
		}
		fmt.Printf("  serial_key (license)   = %s\n", lic.SerialKey)
		fmt.Printf("  serial_key (local)     = %s\n", localSerial)
	}

	// 7) 결과
	match := utils.SubtleConstTimeEq(localSerial, lic.SerialKey)

	if *jsonOut {
		type verifyOut struct {
			SignatureOK bool             `json:"signature_ok"`
			Match       bool             `json:"serial_key_match"`
			License     licmodel.License `json:"license"`
			Snapshot    device.Snapshot  `json:"snapshot"`
			LocalSerial string           `json:"local_serial"`
			BindingKey  string           `json:"binding_key"`
			UID         string           `json:"uid,omitempty"`
		}
		out := verifyOut{
			SignatureOK: true,
			Match:       match,
			License:     lic,
			Snapshot:    snap,
			LocalSerial: localSerial,
			BindingKey:  localBinding,
			UID:         uidUsed,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	} else {
		if match {
			fmt.Println("verify: serial_key match (OK)")
		} else {
			fmt.Println("verify: serial_key mismatch")
			os.Exit(10)
		}
	}
}

// license.json / license.sig를 로드한다.
// - mount가 비어있으면 partDev를 임시 마운트해서 읽고 언마운트한다.
// - mount가 주어지면 그 경로에서 직접 읽는다.
func readLicensePair(mount, partDev string) (licBytes, sigBytes []byte) {
	var base string
	if mount != "" {
		base = mount
	} else {
		// 임시 마운트
		mp := tmpMountPoint
		must(os.MkdirAll(mp, 0755))
		must(execCommand("mount", partDev, mp))
		defer execCommand("umount", mp)
		base = mp
	}
	licPath := filepath.Join(base, "license.json")
	sigPath := filepath.Join(base, "license.sig")

	b1, err := os.ReadFile(licPath)
	must(err)
	b2, err := os.ReadFile(sigPath)
	must(err)
	return b1, b2
}

// 작은 exec 래퍼 (stderr 메시지 깔끔히)
func execCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}
