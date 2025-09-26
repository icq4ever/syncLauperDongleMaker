package disk

import(
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// 전체 포맷(FAT32) : 단일 파티션 + 라벨
func FormatFAT32SinglePartition(disk, label string) error {
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

	part := FindFirstPartition(disk)
	if err := exec.Command("mkfs.vfat", "-F", "32", "-n", label, part).Run(); err != nil {
		return fmt.Errorf("mkfs.vfat: %w", err)
	}
	return nil
}

func FindFirstPartition(disk string) string {
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

func DevFromMount(mnt string) (string, error) {
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