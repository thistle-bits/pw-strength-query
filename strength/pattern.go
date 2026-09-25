package strength

import "strings"

// minPatternRun is the shortest run we bother flagging, for both keyboard
// walks and repeated characters. Anything shorter than this is short enough
// that the entropy math already scores it low; below this length the
// pattern check would just add false positives.
const minPatternRun = 4

// keyboardRows are the rows of a standard US QWERTY layout, unshifted and
// shifted. This only catches walks along a row (left-to-right or
// right-to-left); it doesn't model the full keyboard adjacency graph, so
// diagonal or column walks like "qaz" or "wsx" slip through. Rows catch the
// overwhelming majority of what people actually type, and a full adjacency
// graph is a lot of code for a small remaining gain.
var keyboardRows = []string{
	"1234567890",
	"!@#$%^&*()",
	"qwertyuiop",
	"asdfghjkl",
	"zxcvbnm",
}

// IsPatterned reports whether password is built from a keyboard walk, a
// single character repeated in a run, or a short substring repeated to fill
// out the length. Raw character-class entropy scores "qwertyuiop1234" as
// strong because it's long and mixes classes, but it's one of the first
// things a rule-based cracker (hashcat, John the Ripper) tries, right after
// the dictionary itself.
func IsPatterned(password string) bool {
	return hasRepeatedRun(password) || hasPeriodicRun(password) || hasKeyboardWalk(password)
}

// hasRepeatedRun reports whether the same character appears minPatternRun
// or more times in a row, e.g. "aaaa" or "1111111".
func hasRepeatedRun(password string) bool {
	runes := []rune(password)
	run := 1
	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1] {
			run++
			if run >= minPatternRun {
				return true
			}
		} else {
			run = 1
		}
	}
	return false
}

// hasPeriodicRun reports whether the whole password is a short substring
// repeated end to end, e.g. "abcabcabc" or "1212". A period of 1 is a
// repeated single character, already covered by hasRepeatedRun, so this
// only looks at periods of 2 or more.
func hasPeriodicRun(password string) bool {
	runes := []rune(password)
	n := len(runes)
	if n < minPatternRun {
		return false
	}
	for period := 2; period <= n/2; period++ {
		if n%period != 0 {
			continue
		}
		matches := true
		for i := period; i < n; i++ {
			if runes[i] != runes[i-period] {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

// hasKeyboardWalk reports whether password contains a run of minPatternRun
// or more characters that sit next to each other, in order, on a keyboard
// row, walked in either direction.
func hasKeyboardWalk(password string) bool {
	lower := strings.ToLower(password)
	runes := []rune(lower)
	if len(runes) < minPatternRun {
		return false
	}
	for _, row := range keyboardRows {
		reversed := reverseString(row)
		for i := 0; i+minPatternRun <= len(runes); i++ {
			window := string(runes[i : i+minPatternRun])
			if strings.Contains(row, window) || strings.Contains(reversed, window) {
				return true
			}
		}
	}
	return false
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
