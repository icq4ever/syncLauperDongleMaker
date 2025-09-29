// cmd/syncLauperDongleMaker/dongle_bake.go
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"syncLauperDongleMaker/internal/config"
	"syncLauperDongleMaker/internal/binding"
	"syncLauperDongleMaker/internal/disk"
	"syncLauperDongleMaker/internal/keys"
	"syncLauperDongleMaker/internal/licmodel"
	"syncLauperDongleMaker/internal/utils"
)

// main.go 스위치:
// case "bake":
//     cmdDongleBake()

func cmdDongleBake() {
	fs := flag.NewFlagSet("bake", flag.ExitOnError)

	device    := fs.String("device", "", "target disk device (e.g. /dev/sdX)")
	label     := fs.String("label",  labelName, "FAT32 volume label")
	licensee  := fs.String("licensee", "", "licensee name")
	privPath  := fs.String("priv",     config.ProvPrivDefault, "Ed25519 private key (PKCS#8 PEM)")
	readme    := fs.String("readme",   "", "optional README.pdf to copy to the dongle")
	yes       := fs.Bool("yes", false, "non-interactive; proceed without prompt")
	preview   := fs.Bool("preview", false, "only show what will run (no write)")
	_ = fs.Parse(os.Args[2:])

	// 0) Private key 존재 확인
	if st, err := os.Stat(*privPath); err != nil || st.IsDir() {
		fatal("private key not found: %s", *privPath)
	}

	// 0.1) Licensee 필수
	if strings.TrimSpace(*licensee) == "" {
		if *yes {
			fatal("--licensee is required when --yes is set")
		}
		// 대화형 입력
		r := newLineReader()
		for {
			fmt.Print("Licensee: ")
			v := strings.TrimSpace(readLine(r))
			if v != "" {
				*licensee = v
				break
			}
			fmt.Println("  (required)")
		}
	}

// 0.2) README 포함 여부 확인 (대화형 전용)
	if !*yes && strings.TrimSpace(*readme) == "" {
		r := newLineReader()
		fmt.Print("Add README.pdf? (y/N): ")
		resp := strings.ToLower(strings.TrimSpace(readLine(r)))
		if resp == "y" || resp == "yes" {
			for {
				fmt.Print("README.pdf path: ")
				p := strings.TrimSpace(readLine(r))
				if p == "" {
					fmt.Println("  (required or press Ctrl+C to abort)")
					continue
				}
				fi, err := os.Stat(p)
				if err != nil || fi.IsDir() {
					fmt.Printf("  not found or is a directory: %s\n", p)
					continue
				}
				*readme = p
				break
			}
		}
	}
	// --yes 모드에서는 사용자가 --readme를 준 경우만 사용 (빈 경우 스킵)
	if *yes && strings.TrimSpace(*readme) != "" {
		if fi, err := os.Stat(*readme); err != nil || fi.IsDir() {
			fatal("README file not found or is a directory: %s", *readme)
		}
	}

	// 1) 타깃 디스크 결정 (없으면 대화형 선택)
	devPath := strings.TrimSpace(*device)
	if devPath == "" {
		if *yes {
			fatal("--device is required with --yes")
		}
		// 기존 대화형 선택 함수 재사용
		d, prev := pickTargetDiskByIndex(newLineReader())
		if d == "" {
			fatal("no disk selected")
		}
		devPath = d
		if prev != "" {
			fmt.Println(prev)
		}
	}

	// README 검증 (있으면)
	if *readme != "" {
		if fi, err := os.Stat(*readme); err != nil || fi.IsDir() {
			fatal("README file not found or is a directory: %s", *readme)
		}
	}

	// 2) 요약 출력
	fmt.Println("\nSummary:")
	fmt.Printf("  Target    = %s\n", devPath)
	fmt.Printf("  Label     = %s\n", *label)
	fmt.Printf("  Licensee  = %s\n", *licensee)
	fmt.Printf("  PrivKey   = %s\n", *privPath)
	if *readme != "" {
		fmt.Printf("  README    = %s\n", *readme)
	} else {
		fmt.Printf("  README    = (none)\n")
	}

	// 3) 확인 프롬프트
	if !*yes {
		fmt.Print("Proceed? (y/N): ")
		resp := strings.ToLower(strings.TrimSpace(readLine(newLineReader())))
		if resp != "y" && resp != "yes" {
			fatal("aborted by user")
		}
	}
	if *preview {
		fmt.Println("(preview) no changes applied.")
		return
	}

	// === 작업 시작 ===
	fmt.Printf("\nFormatting %s as FAT32 (%s)...\n", devPath, *label)
	must(disk.FormatFAT32SinglePartition(devPath, *label))
	partDev := disk.FindFirstPartition(devPath)

	// 바인딩 정보 수집
	snap, err := binding.CollectBindingInfo(partDev)
	must(err)
	issued := time.Now().UTC()
	bindingKey := binding.BuildKeyV1(snap)

	// serial_key = SHA256(binding || "|" || issued_at_RFC3339)
	serialKey := utils.Sha256Hex(bindingKey + "|" + issued.Format(time.RFC3339Nano))

	// license.json
	lic := licmodel.License{
		Version:     1,
		Licensee:    strings.TrimSpace(*licensee),
		LicensePlan: "Standard",
		IssuedAt:    issued,
		ExpiresAt:   nil,
		SerialKey:   serialKey,
	}
	licBytes, err := json.MarshalIndent(lic, "", "  ")
	must(err)

	// 서명
	priv, err := keys.LoadEd25519PrivFromPEM(*privPath)
	must(err)
	sig := keys.SignEd25519(priv, licBytes) // 없으면 ed25519.Sign 직접 사용해도 됨

	// 마운트/쓰기/속성/RO remount
	must(os.MkdirAll(tmpMountPoint, 0755))
	defer exec.Command("umount", tmpMountPoint).Run()

	// 1) RW 마운트
	must(exec.Command("mount", partDev, tmpMountPoint).Run())

	// 2) 파일 기록
	licPath := filepath.Join(tmpMountPoint, "license.json")
	sigPath := filepath.Join(tmpMountPoint, "license.sig")
	must(os.WriteFile(licPath, licBytes, 0644))
	must(os.WriteFile(sigPath, sig, 0644))
	var readmeDst string
	if *readme != "" {
		readmeDst = filepath.Join(tmpMountPoint, filepath.Base(*readme))
		must(utils.CopyFile(*readme, readmeDst))
	}

	// 3) sync
	must(exec.Command("sync").Run())

	// 4) DOS Read-only 비트 + 폴백 chmod a-w
	_ = setDOSReadOnlyOnDevice(partDev, "::/license.json", licPath)
	_ = setDOSReadOnlyOnDevice(partDev, "::/license.sig", sigPath)
	if readmeDst != "" {
		_ = setDOSReadOnlyOnDevice(partDev, "::/README.pdf", readmeDst)
	}

	// 5) sync → 언마운트 → RO 재마운트
	must(exec.Command("sync").Run())
	must(exec.Command("umount", tmpMountPoint).Run())
	must(exec.Command("mount", "-o", "ro", partDev, tmpMountPoint).Run())

	fmt.Printf("\nFAT32 baked: %s (label=%s)\n", partDev, *label)
}

func newLineReader() *bufio.Reader {
	return bufio.NewReader(os.Stdin)
}
