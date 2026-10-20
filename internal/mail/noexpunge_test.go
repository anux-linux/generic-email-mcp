package mail

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoDestructiveCallsInSource scans all production Go code in the module
// for IMAP calls that permanently delete mail. The runtime guard
// (guardConn) blocks them on the wire; this keeps them out of the code.
func TestNoDestructiveCallsInSource(t *testing.T) {
	forbidden := regexp.MustCompile(`\.(Expunge|UIDExpunge|UnselectAndExpunge|Delete)\(`)
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found at %s", root)
	}
	scanned := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			// testutil hosts the fake server, which may delete freely.
			if strings.HasPrefix(d.Name(), ".") && rel != "." || rel == filepath.Join("internal", "testutil") || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		for i, line := range strings.Split(string(src), "\n") {
			code, _, _ := strings.Cut(line, "//")
			if forbidden.MatchString(code) {
				t.Errorf("%s:%d: forbidden call: %s", rel, i+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned == 0 {
		t.Fatal("no source files scanned")
	}
}
