// Package strength estimates how hard a password would be to guess.
//
// Every exported function here is pure: given the same password it always
// returns the same answer, and none of them touch the clock, the network,
// or a dictionary file on disk. That's deliberate. A strength estimate you
// can't reproduce in a unit test is one nobody will trust when it disagrees
// with them.
package strength

import (
	"fmt"
	"math"
	"strings"
)

// Category buckets an entropy value into something a person can react to.
type Category int

const (
	VeryWeak Category = iota
	Weak
	Fair
	Strong
	VeryStrong
)

func (c Category) String() string {
	switch c {
	case VeryWeak:
		return "very weak"
	case Weak:
		return "weak"
	case Fair:
		return "fair"
	case Strong:
		return "strong"
	case VeryStrong:
		return "very strong"
	default:
		return "unknown"
	}
}

const (
	lowercase = "abcdefghijklmnopqrstuvwxyz"
	uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits    = "0123456789"
)

// Rough throughput for two attacker models. These are the numbers used
// throughout the password-cracking literature as a conservative baseline,
// not a promise about any particular service or GPU.
const (
	onlineGuessesPerSecond  = 100.0 / 3600.0 // a login form that throttles to ~100 attempts/hour
	offlineGuessesPerSecond = 1e10           // an attacker with the hash and a modern GPU rig
)

// Result is the full answer to "how strong is this password".
type Result struct {
	Length              int
	PoolSize            int
	Entropy             float64 // bits
	Common              bool    // on the common-password list, under normalization
	Category            Category
	OnlineCrackSeconds  float64
	OfflineCrackSeconds float64
}

// poolSize returns the size of the character set the password draws from,
// based on which classes of character actually appear in it. A password
// using only digits gets a pool of 10; add one uppercase letter and the
// pool jumps to 36, because now every position of that length could have
// been a digit or an uppercase letter.
func poolSize(password string) int {
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range password {
		switch {
		case strings.ContainsRune(lowercase, r):
			hasLower = true
		case strings.ContainsRune(uppercase, r):
			hasUpper = true
		case strings.ContainsRune(digits, r):
			hasDigit = true
		default:
			hasSymbol = true
		}
	}

	size := 0
	if hasLower {
		size += len(lowercase)
	}
	if hasUpper {
		size += len(uppercase)
	}
	if hasDigit {
		size += len(digits)
	}
	if hasSymbol {
		// Printable ASCII symbols and punctuation, roughly. Anything
		// outside our four named classes falls in here, which also
		// covers non-ASCII text for now (see README roadmap).
		size += 33
	}
	return size
}

// Entropy estimates the number of bits of entropy in password, assuming
// each character was chosen independently and uniformly from the pool of
// character classes actually used. That assumption is generous to real
// passwords (people are not random number generators) but it's the
// standard, well-understood starting point.
func Entropy(password string) float64 {
	if password == "" {
		return 0
	}
	pool := poolSize(password)
	if pool == 0 {
		return 0
	}
	return float64(len([]rune(password))) * math.Log2(float64(pool))
}

// CategoryFor maps a raw entropy value to a human-readable bucket. The
// thresholds come from the same rough consensus most strength meters use:
// under 28 bits falls to a guess almost immediately, 80+ bits is out of
// reach for any attacker modeled here.
func CategoryFor(entropy float64) Category {
	switch {
	case entropy < 28:
		return VeryWeak
	case entropy < 36:
		return Weak
	case entropy < 60:
		return Fair
	case entropy < 80:
		return Strong
	default:
		return VeryStrong
	}
}

// commonPasswordGuesses is the guess count assigned to anything on the
// common-password list. A dictionary attacker tries these first, so the
// character-class entropy math (which assumes a uniform random draw) is
// the wrong model for them entirely.
const commonPasswordGuesses = 10

// Analyze runs the full estimate for a single password.
func Analyze(password string) Result {
	entropy := Entropy(password)
	common := IsCommon(password)

	var guesses float64
	if entropy > 0 {
		// An attacker who searches the space in a fixed order finds the
		// password after half the guesses on average.
		guesses = math.Pow(2, entropy-1)
	}

	category := CategoryFor(entropy)
	if common {
		category = VeryWeak
		guesses = commonPasswordGuesses
	}

	return Result{
		Length:              len([]rune(password)),
		PoolSize:            poolSize(password),
		Entropy:             entropy,
		Common:              common,
		Category:            category,
		OnlineCrackSeconds:  guesses / onlineGuessesPerSecond,
		OfflineCrackSeconds: guesses / offlineGuessesPerSecond,
	}
}

// FormatSeconds turns a duration expressed in seconds into a short phrase
// suitable for a terminal report. It's kept separate from Analyze so a
// caller who wants the raw numbers for their own UI can skip it entirely.
func FormatSeconds(seconds float64) string {
	const year = 365.25 * 24 * 3600
	switch {
	case seconds < 1:
		return "instantly"
	case seconds < 60:
		return fmt.Sprintf("%.0f seconds", seconds)
	case seconds < 3600:
		return fmt.Sprintf("%.0f minutes", seconds/60)
	case seconds < 86400:
		return fmt.Sprintf("%.0f hours", seconds/3600)
	case seconds < year:
		return fmt.Sprintf("%.0f days", seconds/86400)
	case seconds < year*100:
		return fmt.Sprintf("%.0f years", seconds/year)
	default:
		return "centuries"
	}
}
