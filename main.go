// main.go — Ed25519 only, hardened binding, RO mount + DOS R-attr
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	labelName     = "SL-DONGLE"      // FAT32 라벨 고정
	tmpMountPoint = "/mnt/sd-dongle" // 임시 마운트 지점
	privPathFix   = "privkey.pem"    // Ed25519 개인키 고정 경로 (PKCS#8)
)

/* ===== Public JSON schema (device/binding 미노출) ===== */
type License struct {
	Version     int        `json:"version"`
	Licensee    string     `json:"licensee"`
	LicensePlan string     `json:"license_plan,omitempty"`
	IssuedAt    time.Time  `json:"issued_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	SerialKey   string     `json:"serial_key"` // SHA-256(binding || "|" || issued_at_RFC3339)
	Note        string     `json:"note,omitempty"`
}

/* ===== Internal (노출 금지) ===== */
type DeviceSnapshot struct {
	FsUUID        string // UPPER
	PartUUID      string // lower
	PTUUID        string // lower (parent disk PTUUID)
	USBSerialFull string // UPPER (ID_SERIAL), fallback SHORT
	USBShort      string // UPPER (ID_SERIAL_SHORT)
	USBLong       string // UPPER (VENDOR_MODEL) — 유지하되 바인딩에는 사용 안함(원하면 추가 가능)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "keygen":
		cmdKeygen()
	case "bake":
		cmdBakeInteractive()
	case "verify":
		cmdVerify()
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  %s keygen --out-priv privkey.pem --out-pub pubkey.pem
  %s bake        # 대화형 발급: 포맷(FAT32), 라벨=SL-DONGLE, privkey.pem 고정, device/binding 미노출
  %s verify --mount /path --pub pubkey.pem
`, filepath.Base(os.Args[0]), filepath.Base(os.Args[0]), filepath.Base(os.Args[0]))
}

/* =========================
   keygen (Ed25519 전용)
   ========================= */
func cmdKeygen() {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	outPriv := fs.String("out-priv", "privkey.pem", "Ed25519 private key PEM (PKCS#8)")
	outPub := fs.String("out-pub", "pubkey.pem", "Ed25519 public key PEM (PKIX)")
	_ = fs.Parse(os.Args[2:])

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must(err)

	// PRIVATE KEY (PKCS#8)
	privDer, err := x509.MarshalPKCS8PrivateKey(priv)
	must(err)
	privBlk := &pem.Block{Type: "PRIVATE KEY", Bytes: privDer}
	must(os.WriteFile(*outPriv, pem.EncodeToMemory(privBlk), 0600))

	// PUBLIC KEY (PKIX)
	pubDer, err := x509.MarshalPKIXPublicKey(pub)
	must(err)
	pubBlk := &pem.Block{Type: "PUBLIC KEY", Bytes: pubDer}
	must(os.WriteFile(*outPub, pem.EncodeToMemory(pubBlk), 0644))

	fmt.Printf("keygen: wrote %s and %s (Ed25519)\n", *outPriv, *outPub)
}

/* =========================
   bake (대화형) : 포맷/FAT32/SL-DONGLE + RO mount + DOS R
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
	disk, preview := pickTargetDiskByIndex(reader)
	if disk == "" {
		fatal("no disk selected")
	}

	// 요약 + 확인 (y/N)
	fmt.Println("\nSummary:")
	fmt.Println("  Mode=fat32")
	fmt.Printf("  Target=%s\n", disk)
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
	fmt.Printf("\nFormatting %s as FAT32 (%s)...\n", disk, labelName)
	must(formatFAT32SinglePartition(disk, labelName))
	part := findFirstPartition(disk)

	// 바인딩 정보 수집(내부용)
	devInfo, err := collectBindingInfo(part)
	must(err)
	issued := time.Now().UTC()
	binding := buildBindingKeyV1(devInfo)
	serialKey := sha256Hex(binding + "|" + issued.Format(time.RFC3339))

	// license.json (public)
	lic := License{
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
	priv, err := loadEd25519PrivFromPEM(privPathFix)
	must(err)
	sig := ed25519.Sign(priv, licBytes)

	// 마운트 RW → 파일 기록 → DOS R 속성 시도 → RO 재마운트
	must(os.MkdirAll(tmpMountPoint, 0755))
	defer exec.Command("umount", tmpMountPoint).Run()

	// 1) RW 마운트
	must(exec.Command("mount", part, tmpMountPoint).Run())

	// 2) 파일 기록
	licPath := filepath.Join(tmpMountPoint, "license.json")
	sigPath := filepath.Join(tmpMountPoint, "license.sig")
	must(os.WriteFile(licPath, licBytes, 0644))
	must(os.WriteFile(sigPath, sig, 0644))
	if readmePath != "" {
		dst := filepath.Join(tmpMountPoint, filepath.Base(readmePath))
		must(copyFile(readmePath, dst))
	}

	// 3) DOS Read-only 속성 시도(가능한 툴 우선순위로)
	_ = setDOSReadOnly(licPath)
	_ = setDOSReadOnly(sigPath)
	if readmePath != "" {
		_ = setDOSReadOnly(filepath.Join(tmpMountPoint, filepath.Base(readmePath)))
	}

	// 4) sync → 언마운트 → RO 재마운트
	must(exec.Command("sync").Run())
	must(exec.Command("umount", tmpMountPoint).Run())
	must(exec.Command("mount", "-o", "ro", part, tmpMountPoint).Run())

	fmt.Printf("\nFAT32 baked: %s (label=%s)\n", part, labelName)
	if preview != "" {
		fmt.Println(preview)
	}
}

/* =========================
   verify (서명 + serial_key)
   ========================= */
func cmdVerify() {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	mount := fs.String("mount", "", "mount point")
	pub := fs.String("pub", "", "Ed25519 public key PEM")
	_ = fs.Parse(os.Args[2:])
	if *mount == "" || *pub == "" {
		fs.Usage()
		os.Exit(2)
	}

	// 1) 현재 장치 파티션
	dev, err := devFromMount(*mount)
	must(err)

	// 2) license 파일 로드
	licBytes, err := os.ReadFile(filepath.Join(*mount, "license.json"))
	must(err)
	sigBytes, err := os.ReadFile(filepath.Join(*mount, "license.sig"))
	must(err)

	// 3) 서명 검증
	pubKey, err := loadEd25519PubFromPEM(*pub)
	must(err)
	if !ed25519.Verify(pubKey, licBytes, sigBytes) {
		fmt.Println("signature: BAD")
		fatal("verify signature failed (Ed25519)")
	}
	fmt.Println("signature: OK")

	// 4) serial_key 비교 (장치/바인딩 노출 없음)
	var lic License
	must(json.Unmarshal(licBytes, &lic))

	info, err := collectBindingInfo(dev)
	must(err)
	localBinding := buildBindingKeyV1(info)
	localSerial := sha256Hex(localBinding + "|" + lic.IssuedAt.UTC().Format(time.RFC3339))

	if subtleConstTimeEq(localSerial, lic.SerialKey) {
		fmt.Println("verify: serial_key match (OK)")
	} else {
		fmt.Println("verify: serial_key mismatch")
		os.Exit(1)
	}
}

/* =========================
   Disk select / formatting
   ========================= */

// 번호만 입력하면 바로 진행. nvme0n1 제외.
func pickTargetDiskByIndex(reader *bufio.Reader) (string, string) {
	fmt.Println("Select target disk:")
	out, err := exec.Command("lsblk",
		"-o", "NAME,TYPE,RM,RO,SIZE,MODEL,SERIAL,TRAN,PATH",
		"-nr").Output()
	must(err)

	type cand struct {
		line string
		path string
	}
	var cands []cand
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	exNvme := regexp.MustCompile(`^nvme0n1$`)
	for _, ln := range lines {
		fs := strings.Fields(ln)
		if len(fs) < 9 {
			continue
		}
		name, typ, size, model, tran, path := fs[0], fs[1], fs[4], fs[5], fs[7], fs[8]
		if typ != "disk" {
			continue
		}
		// nvme0n1 제외
		if exNvme.MatchString(name) {
			continue
		}
		tag := ""
		if tran == "usb" {
			tag = " [USB]"
		}
		line := fmt.Sprintf("%s  %s  %s%s", path, size, model, tag)
		cands = append(cands, cand{line: line, path: path})
	}

	if len(cands) == 0 {
		fatal("no candidate disks found")
	}

	for i, c := range cands {
		fmt.Printf("  [%d] %s\n", i, c.line)
	}

	fmt.Print("Enter number [0]: ")
	sel := strings.TrimSpace(readLine(reader))
	if sel == "" {
		sel = "0"
	}
	idx := 0
	fmt.Sscanf(sel, "%d", &idx)
	if idx < 0 || idx >= len(cands) {
		fatal("invalid index")
	}
	preview := fmt.Sprintf("  Selected: %s", cands[idx].line)
	return cands[idx].path, preview
}

// 전체 포맷(FAT32) : 단일 파티션 + 라벨
func formatFAT32SinglePartition(disk, label string) error {
	_ = exec.Command("umount", disk).Run()
	_ = exec.Command("umount", disk+"1").Run()

	_ = exec.Command("wipefs", "-a", disk).Run()

	// DOS 파티션 테이블 + 단일 파티션
	sfdiskInput := "label: dos\n,;\n"
	cmd := exec.Command("sfdisk", disk)
	cmd.Stdin = strings.NewReader(sfdiskInput)
	if err := cmd.Run(); err != nil {
		// fallback: parted
		_ = exec.Command("parted", "-s", disk, "mklabel", "msdos").Run()
		if err2 := exec.Command("parted", "-s", disk, "mkpart", "primary", "fat32", "1MiB", "100%").Run(); err2 != nil {
			return fmt.Errorf("partitioning failed: %v / %v", err, err2)
		}
	}

	part := findFirstPartition(disk)
	if err := exec.Command("mkfs.vfat", "-F", "32", "-n", label, part).Run(); err != nil {
		return fmt.Errorf("mkfs.vfat: %w", err)
	}
	return nil
}

func findFirstPartition(disk string) string {
	out, err := exec.Command("lsblk", "-nr", "-o", "PATH,TYPE", disk).Output()
	if err != nil {
		return disk + "1"
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, ln := range lines {
		fs := strings.Fields(ln)
		if len(fs) == 2 && fs[1] == "part" {
			return fs[0]
		}
	}
	return disk + "1"
}

func devFromMount(mnt string) (string, error) {
	out, err := exec.Command("findmnt", "-nr", "-o", "SOURCE", "--target", mnt).Output()
	if err != nil {
		return "", err
	}
	for _, ln := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "/dev/") {
			return ln, nil
		}
	}
	return "", errors.New("no /dev/* source for mount")
}

/* =========================
   Device / Binding (internal only)
   ========================= */

func collectBindingInfo(devPart string) (DeviceSnapshot, error) {
	var d DeviceSnapshot

	// FS UUID, PARTUUID, PKNAME(부모 디스크 이름)
	uout, err := exec.Command("lsblk", "-no", "UUID,PARTUUID,PKNAME", devPart).Output()
	if err != nil {
		return d, err
	}
	fields := fieldsNoEmpty(string(uout))
	if len(fields) > 0 {
		d.FsUUID = strings.ToUpper(strings.TrimSpace(fields[0]))
	}
	if len(fields) > 1 {
		d.PartUUID = strings.ToLower(strings.TrimSpace(fields[1]))
	}
	parent := ""
	if len(fields) > 2 {
		parent = strings.TrimSpace(fields[2])
	}
	if parent != "" {
		pout, _ := exec.Command("lsblk", "-no", "PTUUID", "/dev/"+parent).Output()
		d.PTUUID = strings.ToLower(strings.TrimSpace(string(pout)))
	}

	// udev props
	props, err := exec.Command("udevadm", "info", "--query=property", "--name", devPart).Output()
	if err != nil {
		return d, err
	}
	kv := parseKVEq(string(props))
	vendor := kv["ID_VENDOR"]
	model := kv["ID_MODEL"]
	serialFull := kv["ID_SERIAL"]
	serialShort := kv["ID_SERIAL_SHORT"]

	if serialFull == "" {
		serialFull = serialShort
	}
	d.USBSerialFull = strings.ToUpper(strings.TrimSpace(serialFull))
	d.USBShort = strings.ToUpper(strings.TrimSpace(serialShort))
	usbLong := strings.TrimSpace(strings.ReplaceAll(vendor, " ", "_") + "_" + strings.ReplaceAll(model, " ", "_"))
	d.USBLong = strings.ToUpper(strings.Trim(usbLong, "_"))

	return d, nil
}

// 바인딩은 UUID 3종 + 컨트롤러 시리얼(Full)로 구성
func buildBindingKeyV1(d DeviceSnapshot) string {
	return strings.Join([]string{
		strings.ToUpper(d.FsUUID),
		strings.ToLower(d.PartUUID),
		strings.ToLower(d.PTUUID),
		strings.ToUpper(d.USBSerialFull),
	}, "|")
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

/* =========================
   Ed25519 PEM helpers
   ========================= */

func loadEd25519PrivFromPEM(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for {
		blk, rest := pem.Decode(b)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "PRIVATE KEY": // PKCS#8
			k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			if err != nil {
				return nil, err
			}
			if p, ok := k.(ed25519.PrivateKey); ok {
				return p, nil
			}
			return nil, errors.New("not Ed25519 private key")
		}
		b = rest
	}
	return nil, errors.New("no Ed25519 private key found in PEM")
}

func loadEd25519PubFromPEM(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for {
		blk, rest := pem.Decode(b)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "PUBLIC KEY": // PKIX
			pk, err := x509.ParsePKIXPublicKey(blk.Bytes)
			if err != nil {
				return nil, err
			}
			if p, ok := pk.(ed25519.PublicKey); ok {
				return p, nil
			}
			return nil, errors.New("not Ed25519 public key")
		}
		b = rest
	}
	return nil, errors.New("no Ed25519 public key found in PEM")
}

/* =========================
   DOS Read-only helper (best-effort)
   ========================= */

func setDOSReadOnly(absPath string) error {
	// 1) mtools: mattrib +r <path>
	if _, err := exec.LookPath("mattrib"); err == nil {
		// mtools는 기본적으로 /etc/mtools.conf 또는 장치 자동탐지를 사용.
		// 직접 경로 지정이 가능한 최신 mattrib는 일반 경로도 처리됨.
		if err := exec.Command("mattrib", "+r", absPath).Run(); err == nil {
			return nil
		}
	}
	// 2) fatattr (일부 배포판)
	if _, err := exec.LookPath("fatattr"); err == nil {
		if err := exec.Command("fatattr", "+r", absPath).Run(); err == nil {
			return nil
		}
	}
	// 3) fallback: 무시(RO 마운트가 1차 보호막)
	return nil
}

/* =========================
   Misc
   ========================= */

func subtleConstTimeEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte = 0
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := out.ReadFrom(in); err != nil {
		return err
	}
	return out.Sync()
}

func fieldsNoEmpty(s string) []string {
	all := strings.Fields(s)
	res := make([]string, 0, len(all))
	for _, f := range all {
		if f != "" && f != "-" {
			res = append(res, f)
		}
	}
	return res
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

func readLine(r *bufio.Reader) string {
	s, _ := r.ReadString('\n')
	return strings.TrimSpace(s)
}

func must(err error) {
	if err != nil {
		fatal("%v", err)
	}
}

func fatal(fmtStr string, a ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+fmtStr+"\n", a...)
	os.Exit(1)
}