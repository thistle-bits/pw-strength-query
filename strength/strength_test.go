package strength

import "testing"

func TestEntropyEmptyPassword(t *testing.T) {
	if got := Entropy(""); got != 0 {
		t.Errorf("Entropy(\"\") = %v, want 0", got)
	}
}

func TestEntropyIsDeterministic(t *testing.T) {
	// Same input, called twice, must give the same answer. That's the
	// whole point of keeping this package pure.
	a := Entropy("correct horse battery staple")
	b := Entropy("correct horse battery staple")
	if a != b {
		t.Errorf("Entropy is not deterministic: %v != %v", a, b)
	}
}

func TestEntropyGrowsWithLength(t *testing.T) {
	short := Entropy("abcdef")
	long := Entropy("abcdefabcdef")
	if long <= short {
		t.Errorf("expected longer password to have higher entropy, got %v <= %v", long, short)
	}
}

func TestEntropyGrowsWithCharsetVariety(t *testing.T) {
	lowerOnly := Entropy("aaaaaaaa")
	mixed := Entropy("aA1!aA1!")
	if mixed <= lowerOnly {
		t.Errorf("expected mixed charset to have higher entropy, got %v <= %v", mixed, lowerOnly)
	}
}

func TestCategoryForThresholds(t *testing.T) {
	cases := []struct {
		entropy float64
		want    Category
	}{
		{0, VeryWeak},
		{27.9, VeryWeak},
		{28, Weak},
		{35.9, Weak},
		{36, Fair},
		{59.9, Fair},
		{60, Strong},
		{79.9, Strong},
		{80, VeryStrong},
	}
	for _, c := range cases {
		if got := CategoryFor(c.entropy); got != c.want {
			t.Errorf("CategoryFor(%v) = %v, want %v", c.entropy, got, c.want)
		}
	}
}

func TestAnalyzeCrackTimeOrdering(t *testing.T) {
	// Offline attacks are always faster than online ones in this model,
	// for any non-empty password.
	result := Analyze("Tr0ub4dor&3")
	if result.OfflineCrackSeconds > result.OnlineCrackSeconds {
		t.Errorf("expected offline crack time <= online crack time, got offline=%v online=%v",
			result.OfflineCrackSeconds, result.OnlineCrackSeconds)
	}
}

func TestIsCommon(t *testing.T) {
	cases := []struct {
		password string
		want     bool
	}{
		{"password", true},
		{"PASSWORD", true},
		{"p4ssw0rd", true},
		{"password123", true},
		{"password123!", true},
		{"Passw0rd123!", true},
		{"correct horse battery staple", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsCommon(c.password); got != c.want {
			t.Errorf("IsCommon(%q) = %v, want %v", c.password, got, c.want)
		}
	}
}

func TestAnalyzeCommonPasswordOverridesCategory(t *testing.T) {
	// Raw entropy alone would call this "strong": it's long and uses three
	// character classes. It's still one of the first guesses in any real
	// attacker's dictionary.
	result := Analyze("Passw0rd123!")
	if !result.Common {
		t.Fatalf("expected Passw0rd123! to be flagged common")
	}
	if result.Category != VeryWeak {
		t.Errorf("expected common password to be categorized VeryWeak, got %v", result.Category)
	}
	if result.OnlineCrackSeconds >= 3600 {
		t.Errorf("expected common password to crack in under an hour online, got %v seconds", result.OnlineCrackSeconds)
	}
}

func TestFormatSecondsBuckets(t *testing.T) {
	cases := []struct {
		seconds float64
		want    string
	}{
		{0.5, "instantly"},
		{30, "30 seconds"},
		{120, "2 minutes"},
		{7200, "2 hours"},
	}
	for _, c := range cases {
		if got := FormatSeconds(c.seconds); got != c.want {
			t.Errorf("FormatSeconds(%v) = %q, want %q", c.seconds, got, c.want)
		}
	}
}
