package engagement

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditChainVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := OpenAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := a.Append(EventRequest, map[string]string{"method": "GET", "url": "https://x/"}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Entries != 5 {
		t.Fatalf("clean chain must verify: %+v", res)
	}
}

func TestAuditAppendContinuesChainAcrossOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, _ := OpenAudit(path)
	a.Append(EventScanStart, nil)
	a.Append(EventRequest, map[string]string{"url": "https://x/1"})

	// Reopen: a fresh handle must pick up the existing chain head and keep the
	// sequence and linkage intact.
	b, err := OpenAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Append(EventScanFinish, nil); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Entries != 3 {
		t.Fatalf("reopened chain must verify with 3 entries: %+v", res)
	}
}

func TestAuditDetectsTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, _ := OpenAudit(path)
	a.Append(EventRequest, map[string]string{"url": "https://in-scope/x"})
	a.Append(EventRequest, map[string]string{"url": "https://in-scope/y"})
	a.Append(EventRequest, map[string]string{"url": "https://in-scope/z"})

	// Rewrite the middle entry's URL, leaving its stored hash untouched: the
	// recomputed hash will no longer match, which is the tamper signal.
	lines := readLines(t, path)
	lines[1] = strings.Replace(lines[1], "in-scope/y", "attacker/y", 1)
	writeLines(t, path, lines)

	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("a tampered entry must fail verification")
	}
	if res.BadSeq != 2 {
		t.Errorf("expected the break at seq 2, got %d (%s)", res.BadSeq, res.Reason)
	}
}

func TestAuditDetectsTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, _ := OpenAudit(path)
	a.Append(EventRequest, map[string]string{"url": "a"})
	a.Append(EventRequest, map[string]string{"url": "b"})
	a.Append(EventRequest, map[string]string{"url": "c"})

	// Remove the last line, then remove a MIDDLE line: dropping the tail alone
	// still verifies (a prefix of a valid chain is a valid chain), so the real
	// tamper test is excising an interior entry, which breaks the linkage.
	lines := readLines(t, path)
	lines = append(lines[:1], lines[2:]...) // drop entry seq 2
	writeLines(t, path, lines)

	res, _ := Verify(path)
	if res.OK {
		t.Fatal("excising an interior entry must fail verification")
	}
	if res.BadSeq != 3 {
		t.Errorf("expected the break at the now-orphaned seq 3, got %d (%s)", res.BadSeq, res.Reason)
	}
}

func TestAuditDetectsReorder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, _ := OpenAudit(path)
	a.Append(EventRequest, map[string]string{"url": "a"})
	a.Append(EventRequest, map[string]string{"url": "b"})

	lines := readLines(t, path)
	lines[0], lines[1] = lines[1], lines[0]
	writeLines(t, path, lines)

	res, _ := Verify(path)
	if res.OK {
		t.Fatal("reordered entries must fail verification")
	}
}

func TestAuditMissingFileIsEmptyAndVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope.jsonl")
	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Entries != 0 {
		t.Fatalf("a missing audit file is an empty, valid chain: %+v", res)
	}
}

func TestAuditGarbledLineIsATamperSignal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, _ := OpenAudit(path)
	a.Append(EventRequest, map[string]string{"url": "a"})
	lines := readLines(t, path)
	lines = append(lines, "{not json")
	writeLines(t, path, lines)
	if _, err := Verify(path); err == nil {
		t.Fatal("a garbled line must surface as an integrity error, not be skipped")
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
