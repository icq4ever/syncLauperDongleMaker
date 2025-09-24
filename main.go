package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ===== 기본값 =====
const DefaultLabel = "SL-DONGLE"
const AlgoVersionV1 = "v1"

// ===== 모델 =====
type License struct {
	// legacy (호환용)
	KeyID     string `json:"key_id,omitempty"`
	FSUUID    string `json:"fs_uuid,omitempty"`
	PARTUUID  string `json:"partuuid,omitempty"`
	USBSerial string `json:"usb_serial,omitempty"` // SHORT 우선, 없으면 LONG 폴백
	IssuedAt  int64  `json:"issued_at"`

	// v1
	KeyVersion string `json:"key_version,omitempty"` // "v1"
	LicenseKey string `json:"license_key,omitempty"` // SHA256 hex
	Licensee   string `json:"licensee,omitempty"`
	IssueDate  string `json:"issue_date,omitempty"`

	// 옵션
	NotBefore int64 `json:"nbf,omitempty"`
	ExpiresAt int64 `json:"exp,omitempty"`
}

func (l *License) Marshal() ([]byte, error) { return json.Marshal(l) }

// ===== 유틸 =====
func normLower(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "__MISSING__"
	}
	return strings.ToLower(s)
}

// v1: (fs_uuid, partuuid, usb_serial, vendor_id, model_id, sector_count) 고정 순서
func makeLicenseKeyV1(fsUUID, partUUID, usbSerial, vendorID, modelID, sectorCount string) string {
	canonical := fmt.Sprintf("fs=%s|part=%s|usb=%s|vid=%s|mid=%s|sects=%s",
		normLower(fsUUID), normLower(partUUID), normLower(usbSerial),
		normLower(vendorID), normLower(modelID), normLower(sectorCount))
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// ===== 키 I/O =====
func saveKeyPair(priv ed25519.PrivateKey, pub ed25519.PublicKey) error {
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}

	privBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: privDER}
	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}

	if err := os.WriteFile("privkey.pem", pem.EncodeToMemory(privBlock), 0600); err != nil {
		return err
	}
	if err := os.WriteFile("pubkey.pem", pem.EncodeToMemory(pubBlock), 0644); err != nil {
		return err
	}
	return nil
}

func execCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		return "", fmt.Errorf("%s %v: %w: %s", name, args, err, s)
	}
	return s, nil
}

func sourceDevice(mount string) (part string, parent string, err error) {
	src, err := execCmd("findmnt", "-no", "SOURCE", mount) // e.g. /dev/sdb1
	if err != nil {
		return "", "", err
	}
	part = strings.TrimSpace(src)
	pk, err := execCmd("lsblk", "-no", "PKNAME", part) // e.g. sdb
	if err != nil || strings.TrimSpace(pk) == "" {
		return part, "", fmt.Errorf("failed to get parent for %s", part)
	}
	parent = "/dev/" + strings.TrimSpace(pk)
	return part, parent, nil
}

// SHORT/LONG 둘 다 얻기
func getUSBSerials(dev string) (shortID, longID string) {
	out, _ := execCmd("udevadm", "info", "--query=property", "--name", dev)
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "ID_SERIAL_SHORT=") {
			shortID = strings.TrimSpace(strings.TrimPrefix(ln, "ID_SERIAL_SHORT="))
		}
		if strings.HasPrefix(ln, "ID_SERIAL=") {
			longID = strings.TrimSpace(strings.TrimPrefix(ln, "ID_SERIAL="))
		}
	}
	return
}

// 규칙: SHORT 우선, SHORT 없으면 LONG
func pickUSB(shortID, longID string) string {
	if shortID != "" {
		return shortID
	}
	return longID
}

func readSerial(dev string) (serialShort, serial string) { // 기존 헬퍼 호환
	return getUSBSerials(dev)
}

// 추가 속성: vendor_id, model_id (udev), sector_count(blockdev --getsz)
func getVendorModelIDs(dev string) (vendorID, modelID string) {
	out, _ := execCmd("udevadm", "info", "--query=property", "--name", dev)
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "ID_VENDOR_ID=") {
			vendorID = strings.TrimSpace(strings.TrimPrefix(ln, "ID_VENDOR_ID="))
		}
		if strings.HasPrefix(ln, "ID_MODEL_ID=") {
			modelID = strings.TrimSpace(strings.TrimPrefix(ln, "ID_MODEL_ID="))
		}
	}
	return
}

func getSectorCount(dev string) string {
	// blockdev --getsz: 512-byte 섹터 수
	if out, err := execCmd("sudo", "blockdev", "--getsz", dev); err == nil && strings.TrimSpace(out) != "" {
		return strings.TrimSpace(out)
	}
	// 폴백: lsblk -bn -o SIZE /dev/sdX  → bytes / 512
	if out, err := execCmd("lsblk", "-bn", "-o", "SIZE", dev); err == nil && strings.TrimSpace(out) != "" {
		if sz, err2 := strconv.ParseUint(strings.TrimSpace(out), 10, 64); err2 == nil && sz > 0 {
			return fmt.Sprintf("%d", sz/512)
		}
	}
	return "__MISSING__"
}

func gatherIDs(mount string) (usbSerial, fsUUID, partUUID string, err error) {
	part, parent, err := sourceDevice(mount)
	if err != nil {
		return "", "", "", err
	}
	ss, s := readSerial(parent)
	usbSerial = pickUSB(ss, s)
	fsUUID, _ = execCmd("blkid", "-s", "UUID", "-o", "value", part)
	partUUID, _ = execCmd("blkid", "-s", "PARTUUID", "-o", "value", part)
	return strings.TrimSpace(usbSerial), strings.TrimSpace(fsUUID), strings.TrimSpace(partUUID), nil
}

func loadPrivKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	k, ok := keyAny.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not ed25519 private key")
	}
	return k, nil
}
func loadPubKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	keyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	k, ok := keyAny.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not ed25519 public key")
	}
	return k, nil
}

// ===== 서명 =====
func sign(bytes []byte, priv ed25519.PrivateKey) []byte  { return ed25519.Sign(priv, bytes) }
func verify(bytes, sig []byte, pub ed25519.PublicKey) bool { return ed25519.Verify(pub, bytes, sig) }

// ===== 파일 IO =====
func writeIfChanged(path string, data []byte, mode fs.FileMode) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return nil
	}
	return os.WriteFile(path, data, mode)
}
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

// ===== 기본 명령들 =====
func cmdGenKey() error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := saveKeyPair(priv, pub); err != nil {
		return err
	}
	fmt.Println("generated privkey.pem, pubkey.pem")
	return nil
}

func cmdVerify(ctx context.Context, mount, pubPath string) error {
	jb, err := os.ReadFile(filepath.Join(mount, "license.json"))
	if err != nil {
		return fmt.Errorf("read license.json: %w", err)
	}
	sb64, err := os.ReadFile(filepath.Join(mount, "license.sig"))
	if err != nil {
		return fmt.Errorf("read license.sig: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sb64)))
	if err != nil {
		return fmt.Errorf("decode sig: %w", err)
	}
	pub, err := loadPubKey(pubPath)
	if err != nil {
		return err
	}
	if !verify(jb, sig, pub) {
		return errors.New("signature invalid")
	}

	var lic License
	if err := json.Unmarshal(jb, &lic); err != nil {
		return err
	}

	// 현재 장치 식별자 수집
	part, parent, err := sourceDevice(mount)
	if err != nil {
		return err
	}
	devShort, devLong := getUSBSerials(parent)
	devUSB := pickUSB(devShort, devLong)
	fsUUID, _ := execCmd("blkid", "-s", "UUID", "-o", "value", part)
	partUUID, _ := execCmd("blkid", "-s", "PARTUUID", "-o", "value", part)
	fsUUID = strings.TrimSpace(fsUUID)
	partUUID = strings.TrimSpace(partUUID)

	// 확장 속성
	vid, mid := getVendorModelIDs(parent)
	sects := getSectorCount(parent)

	// v1 경로
	if strings.EqualFold(lic.KeyVersion, AlgoVersionV1) && lic.LicenseKey != "" {
		expect := makeLicenseKeyV1(fsUUID, partUUID, devUSB, vid, mid, sects)
		fmt.Println("signature: OK")
		fmt.Printf("device: fs_uuid=%q, partuuid=%q, usb_serial=%q, vendor_id=%q, model_id=%q, sector_count=%q\n",
			fsUUID, partUUID, devUSB, vid, mid, sects)
		if lic.LicenseKey != expect {
			return fmt.Errorf("binding check failed (v1): license_key mismatch")
		}
		fmt.Println("binding: OK (v1 license_key matches)")
		return nil
	}

	// 존재하는 필드만 비교 (legacy)
	mismatch := []string{}
	if lic.FSUUID != "" && lic.FSUUID != fsUUID {
		mismatch = append(mismatch, fmt.Sprintf("fs_uuid mismatch (lic=%q, dev=%q)", lic.FSUUID, fsUUID))
	}
	if lic.PARTUUID != "" && lic.PARTUUID != partUUID {
		mismatch = append(mismatch, fmt.Sprintf("partuuid mismatch (lic=%q, dev=%q)", lic.PARTUUID, partUUID))
	}
	if lic.USBSerial != "" && lic.USBSerial != devUSB {
		mismatch = append(mismatch, fmt.Sprintf("usb_serial mismatch (lic=%q, dev=%q)", lic.USBSerial, devUSB))
	}

	fmt.Println("signature: OK")
	fmt.Printf("device: fs_uuid=%q, partuuid=%q, usb_serial=%q\n", fsUUID, partUUID, devUSB)
	if len(mismatch) > 0 {
		return fmt.Errorf("binding check failed:\n  - %s", strings.Join(mismatch, "\n  - "))
	}
	fmt.Println("binding: OK (all specified identifiers match)")
	return nil
}

// ===== Bake (iso | fat32 | ext4 | update-only) =====
type BakeMode string

const (
	ModeISO   BakeMode = "iso"
	ModeFAT32 BakeMode = "fat32"
	ModeEXT4  BakeMode = "ext4"
)

type BakeOpts struct {
	Mode       BakeMode
	Target     string
	PrivPath   string
	Licensee   string
	KeyID      string
	Label      string
	Readme     string // 루트에 README.pdf로 배치(옵션)
	Force      bool
	Timeout    time.Duration

	UpdateOnly bool   // true면 포맷/파티션 없이 라이선스만 갱신
	MountPath  string // --update-only일 때 필요
}

func checkTool(name string) error {
	_, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("tool %q not found in PATH", name)
	}
	return nil
}
func confirmErase(dev string) error {
	fmt.Printf("!!! ALL DATA ON %s WILL BE ERASED. Continue? [yes/NO] ", dev)
	var s string
	if _, err := fmt.Scanln(&s); err != nil {
		return fmt.Errorf("aborted")
	}
	if strings.TrimSpace(s) != "yes" {
		return fmt.Errorf("aborted")
	}
	return nil
}

// 모든 파티션 언마운트 + udisksctl/automounter 개입 차단 시도
func unmountAllUnder(dev string) {
	_ = exec.Command("bash", "-lc", fmt.Sprintf(`
set -e
disk="%s"
# 파티션 목록: 두 번째 라인부터
parts=$(lsblk -ln -o NAME "$disk" | tail -n +2 | sed 's#^#/dev/#')

# 1) 마운트 경로 기준 언마운트
for p in $parts; do
  # udisksctl로 시도 (있으면)
  if command -v udisksctl >/dev/null 2>&1; then
    udisksctl unmount -b "$p" >/dev/null 2>&1 || true
  fi
  # device로 직접
  sudo umount -f "$p" >/dev/null 2>&1 || true
  # 해당 디바이스가 마운트된 모든 타깃을 찾아 언마운트
  for m in $(findmnt -rn -S "$p" -o TARGET); do
    sudo umount -f "$m" >/dev/null 2>&1 || true
  done
done
sudo udevadm settle || true
`, dev)).Run()
}

// 파티션테이블/시그니처 정리
func zapPartitionTable(dev string) {
	// 가능하면 sgdisk --zap-all
	if _, err := exec.LookPath("sgdisk"); err == nil {
		_ = exec.Command("sudo", "sgdisk", "--zap-all", dev).Run()
	}
	// wipefs -a 로 잔여 시그니처 제거
	if _, err := exec.LookPath("wipefs"); err == nil {
		_ = exec.Command("sudo", "wipefs", "-a", dev).Run()
	}
	// 앞부분 8MiB 제로필(고집센 컨트롤러용)
	_ = exec.Command("sudo", "dd", "if=/dev/zero", "of="+dev, "bs=1M", "count=8", "conv=fsync").Run()
	_ = exec.Command("sudo", "blockdev", "--rereadpt", dev).Run()
	_ = exec.Command("sudo", "partprobe", dev).Run()
	_ = exec.Command("sudo", "udevadm", "settle").Run()
}

// 안전한 파티션 생성: busy/레이스 대비 retry 포함
func createMBRSinglePartitionWithRetry(dev string, partType string) (string, error) {
	const maxTry = 3
	var lastErr error

	for i := 1; i <= maxTry; i++ {
		unmountAllUnder(dev)
		zapPartitionTable(dev)

		// mklabel
		if out, err := execCmd("sudo", "parted", "-s", dev, "mklabel", "msdos"); err != nil {
			lastErr = fmt.Errorf("parted mklabel failed (try %d/%d): %v\n%s", i, maxTry, err, out)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		_ = exec.Command("sudo", "udevadm", "settle").Run()

		// mkpart
		if out, err := execCmd("sudo", "parted", "-s", dev, "mkpart", "primary", partType, "1MiB", "100%"); err != nil {
			lastErr = fmt.Errorf("parted mkpart failed (try %d/%d): %v\n%s", i, maxTry, err, out)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		_ = exec.Command("sudo", "udevadm", "settle").Run()

		out, _ := execCmd("bash", "-lc", fmt.Sprintf(`lsblk -ln -o NAME "%s" | sed -n '2p'`, dev))
		part := strings.TrimSpace(out)
		if part == "" {
			lastErr = fmt.Errorf("partition create failed (try %d/%d): no child found", i, maxTry)
			time.Sleep(300 * time.Millisecond)
			continue
		}
		return "/dev/" + part, nil
	}

	// 힌트: dmesg 꼬리 붙여주기(권한 필요)
	if out, err := execCmd("sudo", "dmesg", "-T"); err == nil && strings.TrimSpace(out) != "" {
		lines := strings.Split(out, "\n")
		n := len(lines)
		from := n - 40
		if from < 0 {
			from = 0
		}
		return "", fmt.Errorf("%v\n--- dmesg tail ---\n%s", lastErr, strings.Join(lines[from:], "\n"))
	}
	return "", lastErr
}

func parentBlockName(dev string) (string, error) {
	out, err := execCmd("lsblk", "-no", "NAME,TYPE", dev)
	if err != nil {
		return "", err
	}
	f := strings.Fields(out)
	if len(f) >= 2 && f[1] == "disk" {
		return "/dev/" + f[0], nil
	}
	return "", fmt.Errorf("not a disk: %s", dev)
}

func writeLicenseFiles(dir string, lic *License, priv ed25519.PrivateKey) error {
	jb, err := lic.Marshal()
	if err != nil {
		return err
	}
	sig := sign(jb, priv)
	if err := os.WriteFile(filepath.Join(dir, "license.json"), jb, 0644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "license.sig"), []byte(base64.StdEncoding.EncodeToString(sig)), 0644)
}

// ---- Update Only (재발급 전용) ----
func bakeUpdateOnly(opts BakeOpts) error {
	if opts.MountPath == "" {
		return fmt.Errorf("--mount is required with --update-only")
	}
	if _, err := os.Stat(opts.MountPath); err != nil {
		return fmt.Errorf("mount path not accessible: %w", err)
	}

	// SHORT 우선
	part, parent, err := sourceDevice(opts.MountPath)
	if err != nil {
		return err
	}
	ss, s := readSerial(parent)
	usb := pickUSB(ss, s)
	fsu, _ := execCmd("blkid", "-s", "UUID", "-o", "value", part)
	pu, _ := execCmd("blkid", "-s", "PARTUUID", "-o", "value", part)
	vid, mid := getVendorModelIDs(parent)
	sects := getSectorCount(parent)

	priv, err := loadPrivKey(opts.PrivPath)
	if err != nil {
		return err
	}

	// v1 포맷으로 발급
	lic := &License{
		KeyID:      opts.KeyID,
		KeyVersion: AlgoVersionV1,
		LicenseKey: makeLicenseKeyV1(strings.TrimSpace(fsu), strings.TrimSpace(pu), strings.TrimSpace(usb),
			strings.TrimSpace(vid), strings.TrimSpace(mid), strings.TrimSpace(sects)),
		Licensee:  strings.TrimSpace(opts.Licensee),
		IssueDate: time.Now().Format("2006/01/02"),
		IssuedAt:  time.Now().Unix(),
	}

	if err := writeLicenseFiles(opts.MountPath, lic, priv); err != nil {
		return err
	}
	fmt.Println("license updated at", opts.MountPath)
	return nil
}

// ---- ISO ----
func bakeISO(opts BakeOpts) error {
	if err := checkTool("xorriso"); err != nil {
		return err
	}
	if err := checkTool("dd"); err != nil {
		return err
	}

	if opts.Label == "" {
		opts.Label = DefaultLabel
	}

	pb, err := parentBlockName(opts.Target)
	if err != nil {
		return err
	}
	if !opts.Force {
		if err := confirmErase(opts.Target); err != nil {
			return err
		}
	}
	unmountAllUnder(opts.Target)
	_ = exec.Command("udevadm", "settle").Run()

	// 시리얼: SHORT 우선 (ISO는 fs/part UUID가 없음)
	ss, s := getUSBSerials(pb)
	usbSerial := pickUSB(ss, s)

	priv, err := loadPrivKey(opts.PrivPath)
	if err != nil {
		return err
	}

	stage, err := os.MkdirTemp("", "dongle_stage_*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)

	if opts.Readme != "" {
		if err := copyFile(opts.Readme, filepath.Join(stage, "README.pdf")); err != nil {
			return fmt.Errorf("copy README: %w", err)
		}
	}
	// ISO는 레거시 형태 유지(USBSerial만)
	lic := &License{KeyID: opts.KeyID, Licensee: opts.Licensee, USBSerial: strings.TrimSpace(usbSerial), IssuedAt: time.Now().Unix()}
	if err := writeLicenseFiles(stage, lic, priv); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()
	f, err := os.CreateTemp("", "dongle_*.iso")
	if err != nil {
		return err
	}
	isoPath := f.Name()
	_ = f.Close()
	defer os.Remove(isoPath)

	mkisofs := exec.CommandContext(ctx, "xorriso", "-as", "mkisofs",
		"-r", "-J", "-V", opts.Label, "-o", isoPath, stage)
	mkisofs.Stdout, mkisofs.Stderr = os.Stdout, os.Stderr
	if err := mkisofs.Run(); err != nil {
		return fmt.Errorf("xorriso failed: %w", err)
	}
	fmt.Println("ISO image:", isoPath)

	dd := exec.CommandContext(ctx, "sudo", "dd", "if="+isoPath, "of="+opts.Target, "bs=16M", "oflag=direct", "status=progress")
	dd.Stdout, dd.Stderr = os.Stdout, os.Stderr
	if err := dd.Run(); err != nil {
		return fmt.Errorf("dd failed: %w", err)
	}
	_ = exec.Command("sync").Run()

	fmt.Printf("ISO baked: %s (label=%s)\n", opts.Target, opts.Label)
	_ = exec.Command("lsblk", "-f", opts.Target).Run()
	return nil
}

// ---- 공통: MBR 파티션 ----
func createMBRSinglePartition(dev string, partType string) (string, error) {
	// 유지 (직접 호출은 안 하고 retry 버전 사용)
	if err := exec.Command("sudo", "parted", "-s", dev, "mklabel", "msdos").Run(); err != nil {
		return "", fmt.Errorf("parted mklabel: %w", err)
	}
	if err := exec.Command("sudo", "parted", "-s", dev, "mkpart", "primary", partType, "1MiB", "100%").Run(); err != nil {
		return "", fmt.Errorf("parted mkpart: %w", err)
	}
	out, _ := execCmd("bash", "-lc", fmt.Sprintf(`lsblk -ln -o NAME "%s" | sed -n '2p'`, dev))
	part := strings.TrimSpace(out)
	if part == "" {
		return "", fmt.Errorf("partition create failed")
	}
	return "/dev/" + part, nil
}

// ---- FAT32 (읽기전용 속성 자동) ----
func bakeFAT32(opts BakeOpts) error {
	if err := checkTool("parted"); err != nil {
		return err
	}
	if err := checkTool("mkfs.vfat"); err != nil {
		return err
	}
	if err := checkTool("blkid"); err != nil {
		return err
	}

	if opts.Label == "" {
		opts.Label = DefaultLabel
	}

	pb, err := parentBlockName(opts.Target)
	if err != nil {
		return err
	}
	if !opts.Force {
		if err := confirmErase(opts.Target); err != nil {
			return err
		}
	}
	unmountAllUnder(opts.Target)
	_ = exec.Command("udevadm", "settle").Run()

	part, err := createMBRSinglePartitionWithRetry(opts.Target, "fat32")
	if err != nil {
		return err
	}

	if err := exec.Command("sudo", "mkfs.vfat", "-F", "32", "-n", opts.Label, part).Run(); err != nil {
		return fmt.Errorf("mkfs.vfat: %w", err)
	}
	_ = exec.Command("udevadm", "settle").Run()

	// ID/UUID + 확장 속성
	fsUUID, _ := execCmd("blkid", "-s", "UUID", "-o", "value", part)
	partUUID, _ := execCmd("blkid", "-s", "PARTUUID", "-o", "value", part)
	ss, s := getUSBSerials(pb)
	usbSerial := pickUSB(ss, s)
	vid, mid := getVendorModelIDs(pb)
	sects := getSectorCount(pb)

	// 마운트
	mnt := "/mnt/sl_dongle_tmp"
	_ = exec.Command("sudo", "mkdir", "-p", mnt).Run()
	if err := exec.Command("sudo", "mount", part, mnt).Run(); err != nil {
		return fmt.Errorf("mount: %w", err)
	}
	defer exec.Command("sudo", "umount", mnt).Run()

	// 스테이징 후 복사
	tmp, err := os.MkdirTemp("", "stage_*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if opts.Readme != "" {
		if err := copyFile(opts.Readme, filepath.Join(tmp, "README.pdf")); err != nil {
			return err
		}
	}
	priv, err := loadPrivKey(opts.PrivPath)
	if err != nil {
		return err
	}
	// v1 포맷으로 기록
	lic := &License{
		KeyID:      opts.KeyID,
		KeyVersion: AlgoVersionV1,
		LicenseKey: makeLicenseKeyV1(strings.TrimSpace(fsUUID), strings.TrimSpace(partUUID), strings.TrimSpace(usbSerial),
			strings.TrimSpace(vid), strings.TrimSpace(mid), strings.TrimSpace(sects)),
		Licensee:  opts.Licensee,
		IssueDate: time.Now().Format("2006/01/02"),
		IssuedAt:  time.Now().Unix(),
	}
	if err := writeLicenseFiles(tmp, lic, priv); err != nil {
		return err
	}
	if err := exec.Command("bash", "-lc", fmt.Sprintf(`sudo cp -a "%s"/. "%s"/`, tmp, mnt)).Run(); err != nil {
		return err
	}

	// 읽기전용 속성 지정 (mtools 있으면 FAT 속성 비트 +r)
	readmePath := filepath.Join(mnt, "README.pdf")
	licenseJSON := filepath.Join(mnt, "license.json")
	licenseSIG := filepath.Join(mnt, "license.sig")
	_, mattribErr := exec.LookPath("mattrib")
	if mattribErr == nil {
		cmds := [][]string{}
		if _, err := os.Stat(licenseJSON); err == nil {
			cmds = append(cmds, []string{"mattrib", "+r", "-i", part, "::/license.json"})
		}
		if _, err := os.Stat(licenseSIG); err == nil {
			cmds = append(cmds, []string{"mattrib", "+r", "-i", part, "::/license.sig"})
		}
		if _, err := os.Stat(readmePath); err == nil {
			cmds = append(cmds, []string{"mattrib", "+r", "-i", part, "::/README.pdf"})
		}
		for _, c := range cmds {
			if out, err := execCmd("sudo", c[0], c[1], c[2], c[3], c[4]); err != nil {
				fmt.Fprintf(os.Stderr, "mattrib warn: %v (out=%s)\n", err, out)
			}
		}
	} else {
		// 폴백: 권한으로만 쓰기 금지
		if _, err := os.Stat(licenseJSON); err == nil {
			_ = exec.Command("sudo", "chmod", "a-w", licenseJSON).Run()
		}
		if _, err := os.Stat(licenseSIG); err == nil {
			_ = exec.Command("sudo", "chmod", "a-w", licenseSIG).Run()
		}
		if _, err := os.Stat(readmePath); err == nil {
			_ = exec.Command("sudo", "chmod", "a-w", readmePath).Run()
		}
	}

	_ = exec.Command("sync").Run()

	fmt.Printf("FAT32 baked: %s1 (label=%s)\n", opts.Target, opts.Label)
	_ = exec.Command("lsblk", "-f", opts.Target).Run()
	return nil
}

// ---- EXT4 ----
func bakeEXT4(opts BakeOpts) error {
	if err := checkTool("parted"); err != nil {
		return err
	}
	if err := checkTool("mkfs.ext4"); err != nil {
		return err
	}
	if err := checkTool("blkid"); err != nil {
		return err
	}

	if opts.Label == "" {
		opts.Label = DefaultLabel
	}

	pb, err := parentBlockName(opts.Target)
	if err != nil {
		return err
	}
	if !opts.Force {
		if err := confirmErase(opts.Target); err != nil {
			return err
		}
	}
	unmountAllUnder(opts.Target)
	_ = exec.Command("udevadm", "settle").Run()

	part, err := createMBRSinglePartitionWithRetry(opts.Target, "ext4")
	if err != nil {
		return err
	}

	if err := exec.Command("sudo", "mkfs.ext4", "-F", "-L", opts.Label, part).Run(); err != nil {
		return fmt.Errorf("mkfs.ext4: %w", err)
	}
	_ = exec.Command("udevadm", "settle").Run()

	fsUUID, _ := execCmd("blkid", "-s", "UUID", "-o", "value", part)
	partUUID, _ := execCmd("blkid", "-s", "PARTUUID", "-o", "value", part)
	ss, s := getUSBSerials(pb)
	usbSerial := pickUSB(ss, s)
	vid, mid := getVendorModelIDs(pb)
	sects := getSectorCount(pb)

	mnt := "/mnt/sl_dongle_tmp"
	_ = exec.Command("sudo", "mkdir", "-p", mnt).Run()
	if err := exec.Command("sudo", "mount", part, mnt).Run(); err != nil {
		return fmt.Errorf("mount: %w", err)
	}
	defer exec.Command("sudo", "umount", mnt).Run()

	tmp, err := os.MkdirTemp("", "stage_*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if opts.Readme != "" {
		if err := copyFile(opts.Readme, filepath.Join(tmp, "README.pdf")); err != nil {
			return err
		}
	}
	priv, err := loadPrivKey(opts.PrivPath)
	if err != nil {
		return err
	}
	// v1 포맷으로 기록
	lic := &License{
		KeyID:      opts.KeyID,
		KeyVersion: AlgoVersionV1,
		LicenseKey: makeLicenseKeyV1(strings.TrimSpace(fsUUID), strings.TrimSpace(partUUID), strings.TrimSpace(usbSerial),
			strings.TrimSpace(vid), strings.TrimSpace(mid), strings.TrimSpace(sects)),
		Licensee:  opts.Licensee,
		IssueDate: time.Now().Format("2006/01/02"),
		IssuedAt:  time.Now().Unix(),
	}
	if err := writeLicenseFiles(tmp, lic, priv); err != nil {
		return err
	}
	if err := exec.Command("bash", "-lc", fmt.Sprintf(`sudo cp -a "%s"/. "%s"/`, tmp, mnt)).Run(); err != nil {
		return err
	}
	_ = exec.Command("sync").Run()

	fmt.Printf("EXT4 baked: %s1 (label=%s)\n", opts.Target, opts.Label)
	_ = exec.Command("lsblk", "-f", opts.Target).Run()
	return nil
}

func cmdBake(opts BakeOpts) error {
	if opts.UpdateOnly {
		return bakeUpdateOnly(opts)
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Minute
	}
	switch opts.Mode {
	case ModeISO:
		return bakeISO(opts)
	case ModeFAT32:
		return bakeFAT32(opts)
	case ModeEXT4:
		return bakeEXT4(opts)
	default:
		return fmt.Errorf("unknown mode: %s (use iso|fat32|ext4)", opts.Mode)
	}
}

// ===== 대화형 유틸 =====
func prompt(r *bufio.Reader, label string, def string) (string, error) {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	s, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return def, nil
	}
	return s, nil
}
func promptYN(r *bufio.Reader, label string, defNo bool) (bool, error) {
	if defNo {
		fmt.Printf("%s (y/N): ", label)
	} else {
		fmt.Printf("%s (Y/n): ", label)
	}

	s, err := r.ReadString('\n')
	if err != nil {
		return false, err
	}
	s = strings.TrimSpace(strings.ToLower(s))

	if s == "" {
		return !defNo, nil
	}
	return s == "y" || s == "yes", nil
}

type DevInfo struct {
	Path  string
	Size  string
	Model string
	Tran  string
	Type  string
	RM    string // "1" removable, "0" non-removable
}

func listCandidateDisks() ([]DevInfo, error) {
	// -P : key="val" 출력 → 공백/빈 문자열에도 안전
	out, err := execCmd("lsblk", "-dn", "-o", "NAME,SIZE,MODEL,TRAN,TYPE,RM", "-P")
	if err != nil {
		return nil, err
	}

	parseKV := func(line string) map[string]string {
		m := map[string]string{}
		// 예: NAME="sdb" SIZE="59G" MODEL="" TRAN="usb" TYPE="disk" RM="1"
		for _, tok := range strings.Fields(line) {
			kv := strings.SplitN(tok, "=", 2)
			if len(kv) != 2 {
				continue
			}
			key := kv[0]
			val := strings.Trim(kv[1], `"`)
			m[key] = val
		}
		return m
	}

	var res []DevInfo
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		kv := parseKV(ln)
		if kv["TYPE"] != "disk" {
			continue
		}

		name := kv["NAME"]
		if name == "" {
			continue
		}

		di := DevInfo{
			Path:  "/dev/" + name,
			Size:  kv["SIZE"],
			Model: kv["MODEL"], // 빈 문자열이어도 OK
			Tran:  kv["TRAN"],  // 빈 문자열이어도 OK
			Type:  kv["TYPE"],
			RM:    kv["RM"],
		}
		res = append(res, di)
	}
	return res, nil
}

func interactiveBake(base BakeOpts) (BakeOpts, error) {
	r := bufio.NewReader(os.Stdin)
	opts := base

	// 기본값
	if opts.PrivPath == "" {
		opts.PrivPath = "privkey.pem"
	}
	if opts.KeyID == "" {
		opts.KeyID = "k1"
	}
	if opts.Label == "" {
		opts.Label = DefaultLabel
	}
	if opts.Mode == "" {
		opts.Mode = ModeFAT32
	}

	// Update-only?
	upd, err := promptYN(r, "Update only (license files only, no repartition/format)?", true) // 기본 N
	if err != nil {
		return opts, err
	}
	opts.UpdateOnly = upd

	if opts.UpdateOnly {
		// 마운트 경로만 받으면 됨
		mp, err := prompt(r, "Mount path (e.g. /media/dongle)", "")
		if err != nil {
			return opts, err
		}
		if strings.TrimSpace(mp) == "" {
			return opts, fmt.Errorf("mount path is required for update-only")
		}
		opts.MountPath = mp

		// 라이선시/라벨/키/priv/README 등은 그대로 질문
		lic, err := prompt(r, "Licensee", opts.Licensee)
		if err != nil {
			return opts, err
		}
		opts.Licensee = lic
		lab, err := prompt(r, "Label", opts.Label)
		if err != nil {
			return opts, err
		}
		opts.Label = lab
		kid, err := prompt(r, "Key-ID", opts.KeyID)
		if err != nil {
			return opts, err
		}
		opts.KeyID = kid
		priv, err := prompt(r, "Private key path", opts.PrivPath)
		if err != nil {
			return opts, err
		}
		opts.PrivPath = priv

		fmt.Printf("\nSummary (update-only):\n  Mount=%s\n  Licensee=%s\n  KeyID=%s\n  Priv=%s\n",
			opts.MountPath, opts.Licensee, opts.KeyID, opts.PrivPath)
		yn, err := prompt(r, "Proceed? (yes/no)", "yes")
		if err != nil {
			return opts, err
		}
		if strings.ToLower(yn) != "yes" {
			return opts, fmt.Errorf("aborted")
		}
		return opts, nil
	}

	// 일반 제작 플로우
	m, err := prompt(r, "Mode (iso|fat32|ext4)", string(opts.Mode))
	if err != nil {
		return opts, err
	}
	opts.Mode = BakeMode(strings.ToLower(m))

	lic, err := prompt(r, "Licensee", opts.Licensee)
	if err != nil {
		return opts, err
	}
	opts.Licensee = lic

	lab, err := prompt(r, "Label", opts.Label)
	if err != nil {
		return opts, err
	}
	opts.Label = lab

	kid, err := prompt(r, "Key-ID", opts.KeyID)
	if err != nil {
		return opts, err
	}
	opts.KeyID = kid

	priv, err := prompt(r, "Private key path", opts.PrivPath)
	if err != nil {
		return opts, err
	}
	opts.PrivPath = priv

	rd, err := prompt(r, "README.pdf path (optional, empty to skip)", "")
	if err != nil {
		return opts, err
	}
	opts.Readme = strings.TrimSpace(rd)

	// 디스크 선택
	if opts.Target == "" {
		list, err := listCandidateDisks()
		if err != nil {
			return opts, err
		}
		if len(list) == 0 {
			return opts, fmt.Errorf("no disks found by lsblk")
		}

		fmt.Println("Select target disk:")
		for i, d := range list {
			tag := ""
			if strings.EqualFold(d.Tran, "usb") || d.RM == "1" {
				tag = " [USB]"
			}
			model := d.Model
			if strings.TrimSpace(model) == "" {
				model = "(no-model)"
			}
			fmt.Printf("  [%d] %s  %s  %s%s\n", i, d.Path, d.Size, model, tag)
		}
		for {
			iv, err := prompt(r, "Enter number", "0")
			if err != nil {
				return opts, err
			}
			idx, err := strconv.Atoi(iv)
			if err != nil || idx < 0 || idx >= len(list) {
				fmt.Println("invalid index, try again")
				continue
			}
			opts.Target = list[idx].Path
			break
		}
	}

	fmt.Printf("\nSummary:\n  Mode=%s\n  Target=%s\n  Label=%s\n  Licensee=%s\n  KeyID=%s\n  Priv=%s\n  README=%s\n",
		opts.Mode, opts.Target, opts.Label, opts.Licensee, opts.KeyID, opts.PrivPath, opts.Readme)
	yn, err := prompt(r, "Proceed? (yes/no)", "yes")
	if err != nil {
		return opts, err
	}
	if strings.ToLower(yn) != "yes" {
		return opts, fmt.Errorf("aborted")
	}

	opts.Force = true // 이미 확인 받았으니 강제 진행
	return opts, nil
}

// ===== main =====
func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage:")
		fmt.Println("  syncLauperDongleMaker genkey")
		fmt.Println("  syncLauperDongleMaker verify  --mount /media/dongle --pub  pubkey.pem")
		fmt.Println("  syncLauperDongleMaker bake    [--update-only --mount /media/dongle] [--mode iso|fat32|ext4] [--target /dev/sdX] [--priv privkey.pem] [--licensee NAME] [--key-id K] [--label LABEL] [--readme README.pdf] [--force]")
		fmt.Println("       (no options → interactive wizard; default: fat32)")
		os.Exit(2)
	}

	switch os.Args[1] {
	case "genkey":
		if err := cmdGenKey(); err != nil {
			fmt.Fprintln(os.Stderr, "genkey:", err)
			os.Exit(1)
		}
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		mount := fs.String("mount", "/media/dongle", "mount path of dongle")
		pub := fs.String("pub", "pubkey.pem", "ed25519 public key (PEM)")
		_ = fs.Parse(os.Args[2:])
		ctx := context.Background()
		if err := cmdVerify(ctx, *mount, *pub); err != nil {
			fmt.Fprintln(os.Stderr, "verify:", err)
			os.Exit(1)
		}
	case "bake":
		fs := flag.NewFlagSet("bake", flag.ExitOnError)
		updateOnly := fs.Bool("update-only", false, "update license files only (no repartition/format)")
		mountPath := fs.String("mount", "", "mount path (required with --update-only)")

		mode := fs.String("mode", "", "iso | fat32 | ext4")
		target := fs.String("target", "", "target disk (e.g. /dev/sdX)")
		priv := fs.String("priv", "privkey.pem", "ed25519 private key (PEM)")
		licensee := fs.String("licensee", "", "optional licensee name")
		keyID := fs.String("key-id", "k1", "optional key id")
		label := fs.String("label", DefaultLabel, "volume label")
		readme := fs.String("readme", "", "optional README.pdf path (placed at /README.pdf)")
		force := fs.Bool("force", false, "do not ask for confirmation")
		_ = fs.Parse(os.Args[2:])

		opts := BakeOpts{
			UpdateOnly: *updateOnly,
			MountPath:  *mountPath,

			Mode:     BakeMode(strings.ToLower(*mode)),
			Target:   *target,
			PrivPath: *priv,
			Licensee: *licensee, KeyID: *keyID,
			Label: *label, Readme: *readme,
			Force: *force, Timeout: 10 * time.Minute,
		}

		// 옵션이 거의 비어있으면 대화형 진입
		if !*updateOnly && *mode == "" && *target == "" && !*force && *licensee == "" && *label == DefaultLabel && *keyID == "k1" && *readme == "" && *mountPath == "" {
			var err error
			opts, err = interactiveBake(opts)
			if err != nil {
				fmt.Fprintln(os.Stderr, "bake (interactive):", err)
				os.Exit(1)
			}
		} else if *updateOnly && *mountPath == "" {
			// update-only 모드에 mount가 없으면 대화형으로 보완
			var err error
			opts2, err := interactiveBake(opts)
			if err != nil {
				fmt.Fprintln(os.Stderr, "bake (interactive):", err)
				os.Exit(1)
			}
			opts = opts2
		} else {
			// 모드 기본값
			if !opts.UpdateOnly && opts.Mode == "" {
				opts.Mode = ModeFAT32
			}
		}

		if !opts.UpdateOnly && opts.Target == "" {
			fmt.Fprintln(os.Stderr, "bake: --target /dev/sdX is required (or run without options for interactive)")
			os.Exit(2)
		}

		if err := cmdBake(opts); err != nil {
			fmt.Fprintln(os.Stderr, "bake:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		os.Exit(2)
	}
}