package strength

import "strings"

// commonPasswords is a small, well-known set of the passwords that show up
// at the top of every leaked-password frequency list. It's nowhere near a
// full dictionary attack; the point is to catch the passwords a human is
// most likely to actually type, not to be exhaustive.
var commonPasswords = map[string]bool{
	"password": true, "123456": true, "123456789": true, "12345678": true,
	"1234567": true, "1234567890": true, "12345": true, "111111": true,
	"000000": true, "qwerty": true, "qwerty123": true, "1q2w3e4r": true,
	"qazwsx": true, "zaq1zaq1": true, "letmein": true, "welcome": true,
	"monkey": true, "dragon": true, "master": true, "admin": true,
	"login": true, "abc123": true, "iloveyou": true, "trustno1": true,
	"sunshine": true, "princess": true, "flower": true, "football": true,
	"baseball": true, "superman": true, "batman": true, "starwars": true,
	"whatever": true, "freedom": true, "shadow": true, "ninja": true,
	"azerty": true, "mustang": true, "access": true, "solo": true,
	"hunter2": true, "computer": true, "internet": true, "samsung": true,
	"michael": true, "jennifer": true, "jordan": true, "harley": true,
	"hannah": true, "hello": true, "passw0rd": true, "changeme": true,
	"secret": true, "qwertyuiop": true, "1qaz2wsx": true, "zxcvbnm": true,
	"asdfghjkl": true, "oliver": true, "charlie": true, "daniel": true,
	"thomas": true, "jessica": true, "ashley": true, "nicole": true,
	"amanda": true, "matthew": true, "andrew": true, "joshua": true,
	"william": true,
}

// leetSubstitutions maps the handful of digits and symbols people use as
// stand-ins for letters when they think they're dodging a dictionary check.
// It's deliberately small and unambiguous: no entry here maps to more than
// one plausible letter.
var leetSubstitutions = map[rune]rune{
	'0': 'o',
	'1': 'l',
	'3': 'e',
	'4': 'a',
	'5': 's',
	'7': 't',
	'@': 'a',
	'$': 's',
}

// trailingDecoration is the set of characters people tack onto a common
// word to satisfy a "must contain a digit/symbol" rule without actually
// picking a harder password ("password" -> "password123!").
const trailingDecoration = "0123456789!@#$%^&*_-."

func deleet(s string) string {
	var b strings.Builder
	for _, r := range s {
		if sub, ok := leetSubstitutions[r]; ok {
			b.WriteRune(sub)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// IsCommon reports whether password matches a well-known common password,
// once case, leetspeak substitution, and decorative trailing characters are
// normalized away. It exists because raw character-class entropy scores
// "Passw0rd123!" as strong, and it isn't: it's one of the first things a
// real attacker's dictionary would try.
func IsCommon(password string) bool {
	lower := strings.ToLower(password)
	stripped := strings.TrimRight(lower, trailingDecoration)

	for _, candidate := range []string{lower, deleet(lower), stripped, deleet(stripped)} {
		if commonPasswords[candidate] {
			return true
		}
	}
	return false
}
