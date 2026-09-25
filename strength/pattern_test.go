package strength

import "testing"

func TestIsPatterned(t *testing.T) {
	cases := []struct {
		password string
		want     bool
	}{
		{"qwertyuiop1234", true},
		{"1234567890", true},
		{"0987654321", true},
		{"asdfghjkl", true},
		{"ZXCVBNM", true}, // case-insensitive
		{"aaaaaaaa", true},
		{"1111", true},
		{"abcabcabc", true},
		{"121212", true},
		{"correct horse battery staple", false},
		{"Tr0ub4dor&3", false},
		{"aaa", false},   // below minPatternRun
		{"abc", false},   // too short to judge
		{"", false},
	}
	for _, c := range cases {
		if got := IsPatterned(c.password); got != c.want {
			t.Errorf("IsPatterned(%q) = %v, want %v", c.password, got, c.want)
		}
	}
}

func TestAnalyzePatternOverridesCategory(t *testing.T) {
	// Raw entropy alone would call this "fair": twelve characters drawn
	// from a 26-letter pool. It's a keyboard walk repeated twice, which
	// any rule-based cracker finds almost immediately.
	result := Analyze("qwertyqwerty")
	if !result.Patterned {
		t.Fatalf("expected qwertyqwerty to be flagged patterned")
	}
	if result.Category != VeryWeak {
		t.Errorf("expected patterned password to be categorized VeryWeak, got %v", result.Category)
	}
}

func TestAnalyzeCommonTakesPriorityOverPattern(t *testing.T) {
	// "qwerty" is both a keyboard walk and on the common-password list.
	// The common list implies a smaller guess count, so it should win.
	result := Analyze("qwerty")
	if !result.Common || !result.Patterned {
		t.Fatalf("expected qwerty to be flagged both common and patterned, got common=%v patterned=%v",
			result.Common, result.Patterned)
	}
	if result.OnlineCrackSeconds >= 3600 {
		t.Errorf("expected common+patterned password to crack in under an hour online, got %v seconds",
			result.OnlineCrackSeconds)
	}
}
