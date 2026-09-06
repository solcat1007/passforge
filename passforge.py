#!/usr/bin/env python3
"""
PassForge — Password strength checker and generator. Zero dependencies.

Features:
  - Generate strong passwords (customizable length, charset)
  - Generate passphrases (Diceware-style, word-based)
  - Check password strength (entropy estimation, pattern detection)
  - Identify common vulnerabilities (sequential chars, repeats, dictionary words)
  - Estimate crack time for different attack scenarios
  - Batch generate passwords

Usage:
    passforge generate --length 20             Generate a 20-char password
    passforge generate --no-symbols             Alphanumeric only
    passforge passphrase --words 5             5-word passphrase
    passforge check "MyP@ssw0rd123"            Check strength
    passforge batch --count 100 --length 16    Generate 100 passwords

Author: solcat1007
License: MIT
"""

import argparse
import math
import os
import re
import secrets
import string
import sys
from typing import List, Tuple


# Built-in word list for passphrase generation (no external files needed)
# Curated common words that are easy to remember
WORDLIST = [
    "apple", "brave", "cloud", "dance", "eagle", "flame", "globe", "heart",
    "ivory", "jungle", "knife", "lemon", "music", "noble", "ocean", "piano",
    "queen", "river", "storm", "tiger", "ultra", "viper", "world", "yacht",
    "zebra", "alpha", "blaze", "crisp", "dream", "ember", "frost", "grace",
    "haven", "input", "joker", "karma", "lunar", "magic", "north", "onset",
    "prism", "quest", "raven", "spark", "trust", "unity", "vivid", "whirl",
    "xenon", "yield", "zesty", "amber", "bliss", "charm", "dawn", "echo",
    "fable", "gleam", "harbor", "ideal", "jolt", "kayak", "lotus", "mint",
    "neon", "opal", "pearl", "quartz", "rose", "sage", "tide", "umbra",
    "vault", "wave", "xylo", "yarn", "zen", "aroma", "bloom", "cliff",
    "dune", "elf", "fjord", "glen", "helm", "isle", "jewel", "knot",
    "leaf", "moss", "nest", "oasis", "peak", "quill", "reef", "shore",
    "tide", "urge", "vine", "wisp", "xray", "yoke", "zinc", "arch",
    "beach", "cave", "dell", "field", "grove", "hill", "ice", "jet",
    "knoll", "lake", "meadow", "nook", "orchid", "pine", "quay", "ridge",
    "stream", "trail", "undue", "vale", "wood", "xenith", "yarrow", "zone",
]


class PasswordGenerator:
    """Generate passwords using cryptographically secure randomness."""

    UPPERCASE = string.ascii_uppercase
    LOWERCASE = string.ascii_lowercase
    DIGITS = string.digits
    SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"

    def generate(self, length: int = 16, uppercase: bool = True,
                 lowercase: bool = True, digits: bool = True,
                 symbols: bool = True, exclude_similar: bool = False) -> str:
        """Generate a random password.

        Uses `secrets` module for cryptographic security (not `random`).
        Guarantees at least one character from each selected charset.
        """
        pools = []
        required = []

        if lowercase:
            pool = self.LOWERCASE
            if exclude_similar:
                pool = pool.replace("l", "").replace("o", "")
            pools.append(pool)
            required.append(pool)

        if uppercase:
            pool = self.UPPERCASE
            if exclude_similar:
                pool = pool.replace("I", "").replace("O", "")
            pools.append(pool)
            required.append(pool)

        if digits:
            pool = self.DIGITS
            if exclude_similar:
                pool = pool.replace("0", "").replace("1", "")
            pools.append(pool)
            required.append(pool)

        if symbols:
            pools.append(self.SYMBOLS)
            required.append(self.SYMBOLS)

        if not pools:
            raise ValueError("At least one character set must be selected")

        all_chars = "".join(pools)

        # Generate password with guaranteed charset coverage
        password = []

        # Add one from each required pool
        for pool in required:
            password.append(secrets.choice(pool))

        # Fill remaining length
        for _ in range(length - len(required)):
            password.append(secrets.choice(all_chars))

        # Shuffle the result
        secrets.SystemRandom().shuffle(password)

        return "".join(password)

    def passphrase(self, words: int = 4, separator: str = "-",
                   capitalize: bool = True, add_number: bool = True) -> str:
        """Generate a Diceware-style passphrase.

        Example: "Tiger-Noble-Cloud-42"
        """
        chosen = []
        for _ in range(words):
            word = secrets.choice(WORDLIST)
            if capitalize:
                word = word.capitalize()
            chosen.append(word)

        result = separator.join(chosen)

        if add_number:
            result += separator + str(secrets.randbelow(100))

        return result

    def batch(self, count: int, length: int = 16, **kwargs) -> List[str]:
        """Generate multiple passwords."""
        return [self.generate(length, **kwargs) for _ in range(count)]


class PasswordChecker:
    """Check password strength and identify vulnerabilities."""

    # Common passwords to check against
    COMMON_PASSWORDS = {
        "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
        "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
        "ashley", "bailey", "shadow", "123123", "654321", "superman", "qazwsx",
        "michael", "football", "password1", "password123", "admin", "welcome",
        "hello", "charlie", "donald", "login", "starwars", "121212", "flower",
    }

    # Common keyboard patterns
    PATTERNS = [
        "qwerty", "asdfgh", "zxcvbn", "qazwsx", "1234", "abcd",
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
    ]

    def check(self, password: str) -> dict:
        """Analyze password and return a detailed report."""
        report = {
            "password": password,
            "length": len(password),
            "entropy": self._calculate_entropy(password),
            "score": 0,
            "rating": "",
            "crack_time": "",
            "issues": [],
            "suggestions": [],
        }

        # Check length
        if len(password) < 8:
            report["issues"].append("Too short (minimum 8 characters recommended)")
        elif len(password) < 12:
            report["issues"].append("Could be longer (12+ recommended)")
        elif len(password) >= 16:
            report["score"] += 25

        # Check character variety
        has_lower = bool(re.search(r"[a-z]", password))
        has_upper = bool(re.search(r"[A-Z]", password))
        has_digit = bool(re.search(r"\d", password))
        has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

        variety = sum([has_lower, has_upper, has_digit, has_symbol])
        report["score"] += variety * 15

        if not has_upper:
            report["suggestions"].append("Add uppercase letters")
        if not has_lower:
            report["suggestions"].append("Add lowercase letters")
        if not has_digit:
            report["suggestions"].append("Add numbers")
        if not has_symbol:
            report["suggestions"].append("Add symbols (!@#$...)")

        # Check for common password
        lower_password = password.lower()
        if lower_password in self.COMMON_PASSWORDS:
            report["issues"].append("This is one of the most common passwords!")
            report["score"] -= 30

        # Check for common patterns
        for pattern in self.PATTERNS:
            if pattern in lower_password:
                report["issues"].append(f"Contains keyboard pattern: '{pattern}'")
                report["score"] -= 15
                break

        # Check for sequences (abc, 123, xyz)
        for i in range(len(password) - 2):
            a, b, c = ord(password[i]), ord(password[i+1]), ord(password[i+2])
            if b == a + 1 and c == b + 1:
                report["issues"].append("Contains sequential characters (e.g. abc, 123)")
                report["score"] -= 10
                break
            if b == a - 1 and c == b - 1:
                report["issues"].append("Contains reverse sequence (e.g. cba, 321)")
                report["score"] -= 10
                break

        # Check for repeated characters
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                report["issues"].append(f"Character '{password[i]}' repeated 3+ times")
                report["score"] -= 10
                break

        # Check for dictionary words (simple check)
        for word in WORDLIST:
            if len(word) >= 4 and word in lower_password:
                report["issues"].append(f"Contains dictionary word: '{word}'")
                report["score"] -= 5
                break

        # Calculate crack time
        report["crack_time"] = self._estimate_crack_time(report["entropy"])

        # Rating
        report["score"] = max(0, min(100, report["score"]))
        if report["score"] >= 80:
            report["rating"] = "Very Strong"
        elif report["score"] >= 60:
            report["rating"] = "Strong"
        elif report["score"] >= 40:
            report["rating"] = "Moderate"
        elif report["score"] >= 20:
            report["rating"] = "Weak"
        else:
            report["rating"] = "Very Weak"

        return report

    def _calculate_entropy(self, password: str) -> float:
        """Estimate password entropy in bits."""
        charset_size = 0
        if re.search(r"[a-z]", password):
            charset_size += 26
        if re.search(r"[A-Z]", password):
            charset_size += 26
        if re.search(r"\d", password):
            charset_size += 10
        if re.search(r"[^a-zA-Z0-9]", password):
            charset_size += 32  # approximate symbol count

        if charset_size == 0:
            return 0

        return len(password) * math.log2(charset_size)

    def _estimate_crack_time(self, entropy: float) -> str:
        """Estimate time to crack at 10 billion guesses/second."""
        if entropy == 0:
            return "Instant"

        guesses = 2 ** entropy
        seconds = guesses / 10e9  # 10 billion guesses per second

        if seconds < 1:
            return "Instant"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        elif seconds < 31536000 * 100:
            return f"{seconds/31536000:.1f} years"
        elif seconds < 31536000 * 1e6:
            return f"{seconds/31536000/1000:.1f} thousand years"
        elif seconds < 31536000 * 1e9:
            return f"{seconds/31536000/1e6:.1f} million years"
        elif seconds < 31536000 * 1e12:
            return f"{seconds/31536000/1e9:.1f} billion years"
        else:
            return "centuries (effectively uncrackable)"


def main():
    parser = argparse.ArgumentParser(
        prog="passforge",
        description="Password strength checker and generator. Zero dependencies, cryptographically secure.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s generate --length 20              Strong 20-char password
  %(prog)s generate --no-symbols              Alphanumeric only
  %(prog)s passphrase --words 5               5-word passphrase
  %(prog)s check "MyP@ssw0rd123"              Check strength
  %(prog)s batch --count 10 --length 16       Generate 10 passwords
""",
    )
    sub = parser.add_subparsers(dest="command", help="Commands")

    p_gen = sub.add_parser("generate", help="Generate a strong password")
    p_gen.add_argument("--length", type=int, default=16, help="Password length (default: 16)")
    p_gen.add_argument("--no-uppercase", action="store_true", help="No uppercase letters")
    p_gen.add_argument("--no-lowercase", action="store_true", help="No lowercase letters")
    p_gen.add_argument("--no-digits", action="store_true", help="No digits")
    p_gen.add_argument("--no-symbols", action="store_true", help="No symbols")
    p_gen.add_argument("--exclude-similar", action="store_true", help="Exclude similar chars (l, 1, I, O, 0)")

    p_pass = sub.add_parser("passphrase", help="Generate a passphrase")
    p_pass.add_argument("--words", type=int, default=4, help="Number of words (default: 4)")
    p_pass.add_argument("--separator", default="-", help="Word separator (default: -)")
    p_pass.add_argument("--no-capitalize", action="store_true", help="Don't capitalize words")
    p_pass.add_argument("--no-number", action="store_true", help="Don't add a number")

    p_check = sub.add_parser("check", help="Check password strength")
    p_check.add_argument("password", help="Password to check")

    p_batch = sub.add_parser("batch", help="Generate multiple passwords")
    p_batch.add_argument("--count", type=int, default=10, help="Number to generate")
    p_batch.add_argument("--length", type=int, default=16, help="Password length")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    gen = PasswordGenerator()
    chk = PasswordChecker()

    if args.command == "generate":
        pwd = gen.generate(
            length=args.length,
            uppercase=not args.no_uppercase,
            lowercase=not args.no_lowercase,
            digits=not args.no_digits,
            symbols=not args.no_symbols,
            exclude_similar=args.exclude_similar,
        )
        print(pwd)

    elif args.command == "passphrase":
        pp = gen.passphrase(
            words=args.words,
            separator=args.separator,
            capitalize=not args.no_capitalize,
            add_number=not args.no_number,
        )
        print(pp)

    elif args.command == "check":
        report = chk.check(args.password)
        print(f"Password: {'*' * len(report['password'])}")
        print(f"Length:   {report['length']}")
        print(f"Entropy:  {report['entropy']:.1f} bits")
        print(f"Score:    {report['score']}/100")
        print(f"Rating:   {report['rating']}")
        print(f"Crack:    {report['crack_time']}")
        if report["issues"]:
            print(f"\nIssues:")
            for issue in report["issues"]:
                print(f"  ! {issue}")
        if report["suggestions"]:
            print(f"\nSuggestions:")
            for s in report["suggestions"]:
                print(f"  + {s}")

    elif args.command == "batch":
        for pwd in gen.batch(args.count, args.length):
            print(pwd)


if __name__ == "__main__":
    main()
