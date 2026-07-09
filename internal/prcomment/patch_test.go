package prcomment

import "testing"

// TestCommentableLines pins the new-side line accounting: context and added
// lines are commentable at their new-file line numbers, deletions and the
// no-newline marker are not lines, malformed input fails safe (fewer lines).
func TestCommentableLines(t *testing.T) {
	patch := "@@ -1,3 +1,4 @@\n unchanged\n+added\n another\n-removed\n third\n" +
		"@@ -40,2 +41,3 @@ func section() {\n ctx\n+new\n\\ No newline at end of file"
	got := commentableLines(patch)
	want := []int{1, 2, 3, 4, 41, 42}
	if len(got) != len(want) {
		t.Fatalf("commentable lines = %v, want %v", got, want)
	}
	for _, n := range want {
		if _, ok := got[n]; !ok {
			t.Errorf("line %d missing from commentable set %v", n, got)
		}
	}
}

func TestCommentableLinesMalformed(t *testing.T) {
	for name, patch := range map[string]string{
		"empty":          "",
		"no hunk header": " context\n+added",
		"garbage header": "@@ nonsense @@\n+added",
		"binary blob":    "Binary files a/x and b/x differ",
	} {
		if got := commentableLines(patch); len(got) != 0 {
			t.Errorf("%s: commentable lines = %v, want none", name, got)
		}
	}
	// A stray non-diff line stops the counter until the next hunk header
	// instead of attributing wrong line numbers.
	got := commentableLines("@@ -1,2 +1,2 @@\n ok\nWHAT IS THIS\n+never counted\n@@ -9,1 +9,1 @@\n back")
	if _, ok := got[1]; !ok {
		t.Errorf("line 1 should be commentable: %v", got)
	}
	if _, ok := got[9]; !ok {
		t.Errorf("line 9 (after recovery) should be commentable: %v", got)
	}
	if len(got) != 2 {
		t.Errorf("desynced counter leaked lines: %v", got)
	}
}

func TestDiffLinesCommentable(t *testing.T) {
	d := diffLines{"app/main.go": {3: {}}}
	for _, tc := range []struct {
		file string
		line int
		want bool
	}{
		{"app/main.go", 3, true},
		{"app/main.go", 4, false},
		{"other.go", 3, false},
		{"", 3, false},
		{"app/main.go", 0, false},
	} {
		if got := d.commentable(tc.file, tc.line); got != tc.want {
			t.Errorf("commentable(%q, %d) = %v, want %v", tc.file, tc.line, got, tc.want)
		}
	}
}
