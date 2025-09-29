package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"syncLauperDongleMaker/internal/binding"
	"syncLauperDongleMaker/internal/disk"
	"syncLauperDongleMaker/internal/keys"
	"syncLauperDongleMaker/internal/licmodel"
	"syncLauperDongleMaker/internal/utils"
)

/* =========================
   bake (대화형) : FAT32 + DOS R 속성 + RO 재마운트
   ========================= */
func cmdBakeInteractive() {
	reader := bufio.NewReader(os.Stdin)

	// Licensee (필수)
	licensee := ""
	for {
		fmt.Print("Licensee: ")
		licensee = readLine(reader)
		if strings.TrimSpace(licensee) != "" {
			break
		}
		fmt.Println("  (required)")
	}

	// Private key: 고정 경로 확인
	if _, err := os.Stat(privPathFix); err != nil {
		fatal("private key not found: %s (run `keygen` or place Ed25519 PEM)", privPathFix)
	}

	// README.pdf path (optional)
	fmt.Print("README.pdf path (optional, empty to skip): ")
	readmePath := strings.TrimSpace(readLine(reader))
	if readmePath != "" {
		if fi, err := os.Stat(readmePath); err != nil || fi.IsDir() {
			fatal("README file not found or is a directory: %s", readmePath)
		}
	}

	// 타깃 디스크 선택 (번호만 입력 → 즉시 진행, nvme0n1 제외)
	devPath, preview := pickTargetDiskByIndex(reader)
	if devPath == "" {
		fatal("no disk selected")
	}

	// 요약 + 확인 (y/N)
	fmt.Println("\nSummary:")
	fmt.Println("  Mode=fat32")
	fmt.Printf("  Target=%s\n", devPath)
	fmt.Printf("  Label=%s\n", labelName)
	fmt.Printf("  Licensee=%s\n", licensee)
	fmt.Printf("  Priv=%s\n", privPathFix)

	if readmePath != "" {
		fmt.Printf("  README=%s\n", readmePath)
	} else {
		fmt.Printf("  README=\n")
	}
	fmt.Print("Proceed? (y/N): ")
	
	resp := strings.ToLower(strings.TrimSpace(readLine(reader)))
	if resp != "y" && resp != "yes" {
		fatal("aborted by user")
	}

	// === 작업 시작 ===
	fmt.Printf("\nFormatting %s as FAT32 (%s)...\n", devPath, labelName)
	must(disk.FormatFAT32SinglePartition(devPath, labelName))
	part := disk.FindFirstPartition(devPath)

	// 바인딩 정보 수집(내부용)
	devInfo, err := binding.CollectBindingInfo(part)
	must(err)
	issued := time.Now().UTC()
	bindingKey := binding.BuildKeyV1(devInfo)

	// serial_key = SHA256(binding || "|" || issued_at_RFC3339)
	serialKey := utils.Sha256Hex(bindingKey + "|" + issued.Format(time.RFC3339))

	// license.json (public)
	lic := licmodel.License{
		Version:     1,
		Licensee:    licensee,
		LicensePlan: "Standard",
		IssuedAt:    issued,
		ExpiresAt:   nil,
		SerialKey:   serialKey,
	}

	licBytes, err := json.MarshalIndent(lic, "", "  ")
	must(err)

	// 서명 (Ed25519: 원문 바이트에 그대로 서명)
	priv, err := keys.LoadEd25519PrivFromPEM(privPathFix)
	must(err)
	sig := ed25519.Sign(priv, licBytes)

	// 마운트 RW → 파일 기록 → DOS R 속성(mattrib -i <part> ::/path) + chmod 폴백 → sync → 언마운트 → RO 재마운트
	must(os.MkdirAll(tmpMountPoint, 0755))
	defer exec.Command("umount", tmpMountPoint).Run()

	// 1) RW 마운트
	must(exec.Command("mount", part, tmpMountPoint).Run())

	// 2) 파일 기록
	licPath := filepath.Join(tmpMountPoint, "license.json")
	sigPath := filepath.Join(tmpMountPoint, "license.sig")
	must(os.WriteFile(licPath, licBytes, 0644))
	must(os.WriteFile(sigPath, sig, 0644))
	var readmeDst string
	if readmePath != "" {
		readmeDst = filepath.Join(tmpMountPoint, filepath.Base(readmePath))
		must(utils.CopyFile(readmePath, readmeDst))
	}

	// 3) sync (mattrib가 디바이스로 직접 작업하므로 캐시 반영)
	must(exec.Command("sync").Run())

	// 4) DOS Read-only 속성 시도 (장치 지정 방식) + 폴백 chmod a-w
	_ = setDOSReadOnlyOnDevice(part, "::/license.json", licPath)
	_ = setDOSReadOnlyOnDevice(part, "::/license.sig", sigPath)
	if readmeDst != "" {
		_ = setDOSReadOnlyOnDevice(part, "::/README.pdf", readmeDst)
	}

	// 5) sync → 언마운트 → RO 재마운트
	must(exec.Command("sync").Run())
	must(exec.Command("umount", tmpMountPoint).Run())
	must(exec.Command("mount", "-o", "ro", part, tmpMountPoint).Run())

	fmt.Printf("\nFAT32 baked: %s (label=%s)\n", part, labelName)
	if preview != "" {
		fmt.Println(preview)
	}
}
