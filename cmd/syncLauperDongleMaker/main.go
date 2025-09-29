// main.go — Ed25519 only, hardened binding, mattrib(-i ::/path) + chmod fallback, RO remount
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	labelName     = "SL-DONGLE"      // FAT32 라벨 고정
	tmpMountPoint = "/mnt/sd-dongle" // 임시 마운트 지점
	privPathFix   = "privkey.pem"    // Ed25519 개인키 고정 경로 (PKCS#8)
)


func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "keygen":
		cmdKeygen()
	case "bake":
		cmdDongleBake()
	case "verify":
		cmdDongleVerify()
	case "probe":
    if err := interactiveProbe(); err != nil {
			fatal("probe: %v", err)
    }
	case "upload":
		cmdProvision(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	prog := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, `Usage:
  %s keygen --out-priv privkey.pem --out-pub pubkey.pem
  %s bake   # 대화형 발급: 포맷(FAT32), 라벨=SL-DONGLE, privkey.pem 고정, device/binding 미노출
  %s verify --mount /path --pub pubkey.pem
  %s probe  # 대화형: USB 디스크 리스트 → 번호 선택 → 식별자 일괄 표시
`, prog, prog, prog, prog)
}
