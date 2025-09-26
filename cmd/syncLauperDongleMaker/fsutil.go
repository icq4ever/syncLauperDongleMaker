package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

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

func readLine(r *bufio.Reader) string {
	s, _ := r.ReadString('\n')
	return strings.TrimSpace(s)
}

func fatal(fmtStr string, a ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+fmtStr+"\n", a...)
	os.Exit(1)
}

func must(err error) {
	if err != nil {
		fatal("%v", err)
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
