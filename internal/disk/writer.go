package disk

import (
	"os"
	"os/exec"
	"path/filepath"
)

type Writer struct {
	PartDev 		string 	// /dev/sdb1
	MountPoint 	string	// /mnt/sd-dongle"
}

func (w Writer) WriteLicense(licBytes, sig []byte) error {
	if err := os.MkdirAll(w.MountPoint, 0755); err != nil { return err }
	if err := exec.Command("mount", w.PartDev, w.MountPoint).Run(); err != nil { return err }
	defer exec.Command("umount", w.MountPoint).Run()

	if err := os.WriteFile(filepath.Join(w.MountPoint, "license.json"), licBytes, 0644); err != nil { return err }
	if err := os.WriteFile(filepath.Join(w.MountPoint, "license.sig"), sig, 0644); err != nil { return err }
	// if err := exec.Command("sync").Run(); err != nil { return err }
	return nil
}