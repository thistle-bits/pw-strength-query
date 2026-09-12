# pw-strength-query

Most password strength meters give you a colored bar and no explanation.
This one answers a single question instead: given this password, how long
would it take to guess, under two different attack models?

It does that with a plain entropy estimate based on which character
classes the password actually uses, not a scoring rubric or a hidden
dictionary check. The numbers are rough on purpose — the point is that
they're reproducible and you can see exactly how they were derived.

## Usage

As a command:

```sh
go run . 'correct horse battery staple'
```

```
length:        29
charset size:  27
entropy:       137.9 bits
category:      very strong
online guess:  centuries
offline guess: centuries
```

Or leave the password off and it'll prompt for one on stdin:

```sh
go run .
password: hunter2
```

As a library:

```go
import "pw-strength-query/strength"

result := strength.Analyze("hunter2")
fmt.Println(result.Category)                          // "very weak"
fmt.Println(strength.FormatSeconds(result.OnlineCrackSeconds)) // "instantly"
```

## How the estimate works

1. Figure out which character classes appear in the password (lowercase,
   uppercase, digits, everything else) and add up the size of each class
   that's present. That's the assumed pool size.
2. Entropy is `length * log2(pool size)` — the number of bits you'd need
   to pick a password of that length from that pool at random.
3. Crack time is entropy converted to an average number of guesses
   (`2^(entropy-1)`), divided by a guesses-per-second rate for two
   attacker models: a rate-limited login form, and an offline attack
   against a stolen password hash.

This is the standard back-of-envelope model most strength meters build
on. It assumes the password was chosen uniformly at random from its
apparent character set, which real passwords never are — `Password1!`
scores well by this math despite being one of the first things a real
attacker would try. See the roadmap below.

## Design note

Every exported function in the `strength` package is pure: same input,
same output, no clock, no filesystem, no network. `Analyze` is the one
function most callers need; everything else is exposed so you can
recombine the pieces (raw entropy, category thresholds, time formatting)
without pulling apart `Analyze` itself.

## Roadmap

- Detect common passwords and simple substitutions (`Password1!`) and
  penalize them regardless of raw entropy
- Detect keyboard-walk and repeated-character patterns
- Treat non-ASCII letters as their own character class instead of
  lumping them into "symbol"
- Add a `-json` output flag for scripting
- Package as a library-only mode with no CLI dependency on stdin prompts
