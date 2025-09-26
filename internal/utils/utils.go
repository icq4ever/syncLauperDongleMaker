package utils

import(
	"fmt"
	"strings"
	"os"
	"time"
)

func ParseKVEq(s string) map[string]string {
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

func CopyFile(src, dst string) error {
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


const issuedLabelWidth = 22

// PrintIssuedUTCandKST prints "label = UTC ..." on one line and "KST ..." on the next line, nicely aligned.
func PrintIssuedUTCandKST(label string, t time.Time) {
	utc := t.UTC().Format(time.RFC3339)

	// Try Asia/Seoul; fall back to local if load fails
	loc, err := time.LoadLocation("Asia/Seoul")
	if err != nil {
		loc = time.Local
	}
	kst := t.In(loc).Format(time.RFC3339)

	// first line
	fmt.Printf("  %-*s = UTC %s\n", issuedLabelWidth, label, utc)
	// second line (indent = "  " + issuedLabelWidth + " = ")
	indent := "  " + fmt.Sprintf("%-*s", issuedLabelWidth, "") + "   "
	fmt.Printf("%sKST %s\n", indent, kst)
}