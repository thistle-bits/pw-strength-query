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
common:        false
patterned:     false
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
attacker would try.

To catch that case, the password is also checked against a small list of
well-known common passwords, after lowercasing it, undoing obvious
leetspeak substitutions (`p4ssw0rd` -> `password`), and stripping
decorative trailing digits and symbols (`password123!` -> `password`). A
match forces the category down to "very weak" and the crack time down to
near-instant, regardless of what the entropy math says.

The same problem shows up in a different shape with keyboard walks and
repeated runs: `qwertyuiop1234` scores well on raw entropy because it's
long and mixes character classes, but it's not a random draw from that
pool, it's a straight line across the keyboard. `IsPatterned` catches a
run of the same character (`aaaaaaaa`), a short substring repeated to
fill out the length (`abcabcabc`), and a walk along a keyboard row in
either direction (`qwerty`, `1234567890`, `lkjhgfdsa`). A match forces
the same "very weak" category and near-instant crack time as a common
password, unless the password is already on the common list, in which
case the common-password guess count wins because it's the smaller of
the two.

## Design note

Every exported function in the `strength` package is pure: same input,
same output, no clock, no filesystem, no network. `Analyze` is the one
function most callers need; everything else is exposed so you can
recombine the pieces (raw entropy, category thresholds, time formatting)
without pulling apart `Analyze` itself.

## Roadmap

- Treat non-ASCII letters as their own character class instead of
  lumping them into "symbol"
- Add a `-json` output flag for scripting
- Package as a library-only mode with no CLI dependency on stdin prompts
