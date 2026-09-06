# PassForge

> Password generator and strength checker. Zero dependencies. Cryptographically secure.

## Why

Every service needs a password. Browser password managers are convenient but opaque — you can't see *why* a password is strong or weak. PassForge generates passwords using `secrets` (cryptographically secure), checks strength with entropy analysis and pattern detection, and estimates crack time.

## Quick Start

```bash
# Generate a 20-character password
python passforge.py generate --length 20
# Kj9#mQ2$vL7@nX4!pL3a

# Generate a passphrase (easier to remember)
python passforge.py passphrase --words 5
# Tiger-Noble-Cloud-Dawn-42

# Check password strength
python passforge.py check "MyP@ssw0rd123"
# Password: ************
# Length:   12
# Entropy:  71.4 bits
# Score:    55/100
# Rating:   Moderate
# Crack:    2.3 years
#
# Issues:
#   ! Contains dictionary word: 'pass'
#
# Suggestions:
#   + Add more characters (16+ recommended)

# Generate 100 passwords
python passforge.py batch --count 100 --length 16
```

## Features

| Feature | Description |
|---------|-------------|
| Password generation | Customizable length, charset, exclude similar chars |
| Passphrase generation | Diceware-style, word-based, easy to remember |
| Strength checking | Entropy, score, rating, crack time estimation |
| Pattern detection | Keyboard patterns, sequences, repeats, dictionary words |
| Common password check | Flags top 100 most common passwords |
| Batch generation | Generate N passwords at once |
| Cryptographic security | Uses `secrets` module, not `random` |

## Commands

```bash
passforge generate --length 20                    Generate 20-char password
passforge generate --no-symbols                     Alphanumeric only
passforge generate --exclude-similar                No l, 1, I, O, 0
passforge passphrase --words 5                      5-word passphrase
passforge passphrase --separator "." --no-number     Dotted, no number
passforge check "password123"                       Check strength
passforge batch --count 50 --length 20              Batch generate
```

## Strength Rating

| Score | Rating |
|-------|--------|
| 80-100 | Very Strong |
| 60-79 | Strong |
| 40-59 | Moderate |
| 20-39 | Weak |
| 0-19 | Very Weak |

## Testing

```bash
python passforge/tests/test_passforge.py -v
```

All 26 tests pass.

## License

MIT

## Author

solcat1007
