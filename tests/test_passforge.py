"""
Tests for PassForge — password generator and checker.
"""

import os
import re
import string
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from passforge import PasswordGenerator, PasswordChecker


class TestGeneration(unittest.TestCase):
    """Test password generation."""

    def test_default_length(self):
        gen = PasswordGenerator()
        pwd = gen.generate()
        self.assertEqual(len(pwd), 16)

    def test_custom_length(self):
        gen = PasswordGenerator()
        pwd = gen.generate(length=32)
        self.assertEqual(len(pwd), 32)

    def test_no_symbols(self):
        gen = PasswordGenerator()
        pwd = gen.generate(length=20, symbols=False)
        self.assertNotRegex(pwd, r"[^a-zA-Z0-9]")

    def test_no_uppercase(self):
        gen = PasswordGenerator()
        pwd = gen.generate(length=50, uppercase=False)
        self.assertNotRegex(pwd, r"[A-Z]")

    def test_no_digits(self):
        gen = PasswordGenerator()
        pwd = gen.generate(length=50, digits=False)
        self.assertNotRegex(pwd, r"\d")

    def test_exclude_similar(self):
        gen = PasswordGenerator()
        for _ in range(100):
            pwd = gen.generate(length=50, exclude_similar=True)
            self.assertNotIn("l", pwd)
            self.assertNotIn("I", pwd)
            self.assertNotIn("O", pwd)
            self.assertNotIn("0", pwd)
            self.assertNotIn("o", pwd.lower())  # actually just lowercase l,o

    def test_has_variety(self):
        gen = PasswordGenerator()
        pwd = gen.generate(length=20)
        self.assertRegex(pwd, r"[a-z]")
        self.assertRegex(pwd, r"[A-Z]")
        self.assertRegex(pwd, r"\d")
        self.assertRegex(pwd, r"[^a-zA-Z0-9]")

    def test_uniqueness(self):
        gen = PasswordGenerator()
        pwds = set(gen.batch(100, length=16))
        self.assertEqual(len(pwds), 100)

    def test_no_charset_raises(self):
        gen = PasswordGenerator()
        with self.assertRaises(ValueError):
            gen.generate(uppercase=False, lowercase=False, digits=False, symbols=False)


class TestPassphrase(unittest.TestCase):
    """Test passphrase generation."""

    def test_word_count(self):
        gen = PasswordGenerator()
        pp = gen.passphrase(words=5, capitalize=False, add_number=False, separator="-")
        parts = pp.split("-")
        self.assertEqual(len(parts), 5)

    def test_capitalize(self):
        gen = PasswordGenerator()
        pp = gen.passphrase(words=3, capitalize=True, add_number=False, separator="-")
        parts = pp.split("-")
        for part in parts:
            self.assertTrue(part[0].isupper())

    def test_has_number(self):
        gen = PasswordGenerator()
        pp = gen.passphrase(words=4, add_number=True, separator="-")
        last_part = pp.split("-")[-1]
        self.assertTrue(last_part.isdigit())

    def test_custom_separator(self):
        gen = PasswordGenerator()
        pp = gen.passphrase(words=3, separator=".", capitalize=False, add_number=False)
        self.assertIn(".", pp)


class TestCheck(unittest.TestCase):
    """Test password strength checking."""

    def test_weak_password(self):
        chk = PasswordChecker()
        report = chk.check("1234")
        self.assertIn(report["rating"], ["Very Weak", "Weak"])
        self.assertLess(report["score"], 40)

    def test_common_password(self):
        chk = PasswordChecker()
        report = chk.check("password")
        self.assertLess(report["score"], 30)
        self.assertTrue(len(report["issues"]) > 0)

    def test_strong_password(self):
        chk = PasswordChecker()
        report = chk.check("Kj9#mQ2$vL7@nX4!")
        self.assertGreater(report["score"], 50)

    def test_keyboard_pattern(self):
        chk = PasswordChecker()
        report = chk.check("qwerty123")
        issues = " ".join(report["issues"])
        self.assertIn("pattern", issues.lower())

    def test_sequential_chars(self):
        chk = PasswordChecker()
        report = chk.check("abc123def")
        issues = " ".join(report["issues"])
        self.assertTrue("sequential" in issues.lower() or "dictionary" in issues.lower())

    def test_repeated_chars(self):
        chk = PasswordChecker()
        report = chk.check("aaa123bbb")
        issues = " ".join(report["issues"])
        self.assertIn("repeated", issues.lower())

    def test_entropy_calculation(self):
        chk = PasswordChecker()
        report = chk.check("a")
        self.assertGreater(report["entropy"], 0)
        report2 = chk.check("Ab1!")
        self.assertGreater(report2["entropy"], report["entropy"])

    def test_crack_time_format(self):
        chk = PasswordChecker()
        report = chk.check("x")
        self.assertTrue(len(report["crack_time"]) > 0)
        report2 = chk.check("Kj9#mQ2$vL7@nX4!pL3")
        self.assertNotEqual(report["crack_time"], report2["crack_time"])

    def test_suggestions_for_weak(self):
        chk = PasswordChecker()
        report = chk.check("abc")
        self.assertTrue(len(report["suggestions"]) > 0)

    def test_empty_password(self):
        chk = PasswordChecker()
        report = chk.check("")
        self.assertEqual(report["length"], 0)


class TestBatch(unittest.TestCase):
    """Test batch generation."""

    def test_batch_count(self):
        gen = PasswordGenerator()
        pwds = gen.batch(50, length=16)
        self.assertEqual(len(pwds), 50)

    def test_batch_unique(self):
        gen = PasswordGenerator()
        pwds = gen.batch(100, length=20)
        self.assertEqual(len(set(pwds)), 100)

    def test_batch_length(self):
        gen = PasswordGenerator()
        pwds = gen.batch(10, length=24)
        for pwd in pwds:
            self.assertEqual(len(pwd), 24)


if __name__ == "__main__":
    unittest.main(verbosity=2)
