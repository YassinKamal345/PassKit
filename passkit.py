#!/usr/bin/env python3
"""
PassKit - a small password toolkit: generate, score, and check for breaches.

  generate   create a strong random password
  strength   score a password's strength and explain the result
  breach     check whether a password appears in known data breaches

The breach check uses the Have I Been Pwned range API with k-anonymity: only the
first 5 characters of the password's SHA-1 hash ever leave your machine, never the
password itself and never the full hash.

Author: Yassin Kamal - https://github.com/YassinKamal345
License: MIT
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import math
import secrets
import string
import sys
import urllib.error
import urllib.request

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"

AMBIGUOUS = "Il1O0|`'\""  # characters that are easy to confuse in some fonts


def generate(length: int, *, symbols: bool, digits: bool, upper: bool,
             avoid_ambiguous: bool) -> str:
    """Build a random password from the selected character classes."""
    pools: list[str] = [string.ascii_lowercase]
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?/")

    if avoid_ambiguous:
        pools = ["".join(c for c in pool if c not in AMBIGUOUS) for pool in pools]

    alphabet = "".join(pools)
    if length < len(pools):
        raise ValueError(f"length must be at least {len(pools)} for the chosen classes")

    # Guarantee at least one character from each selected class, then fill the rest.
    chars = [secrets.choice(pool) for pool in pools]
    chars += [secrets.choice(alphabet) for _ in range(length - len(pools))]
    # Shuffle so the guaranteed characters aren't always at the front.
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def entropy_bits(password: str) -> float:
    """Estimate entropy in bits from the character classes actually used."""
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 32
    return len(password) * math.log2(pool) if pool else 0.0


def strength_label(bits: float) -> str:
    if bits < 28:
        return "very weak"
    if bits < 36:
        return "weak"
    if bits < 60:
        return "reasonable"
    if bits < 128:
        return "strong"
    return "very strong"


def describe_strength(password: str) -> tuple[float, str, list[str]]:
    """Return (entropy_bits, label, tips)."""
    bits = entropy_bits(password)
    tips: list[str] = []
    if len(password) < 12:
        tips.append("use at least 12 characters (longer is better than complex)")
    if not any(c.isupper() for c in password):
        tips.append("add uppercase letters")
    if not any(c.isdigit() for c in password):
        tips.append("add digits")
    if not any(not c.isalnum() for c in password):
        tips.append("add symbols")
    if len(set(password)) < max(4, len(password) // 2):
        tips.append("avoid repeating the same few characters")
    return bits, strength_label(bits), tips


def pwned_count(password: str, *, timeout: float = 10.0) -> int:
    """
    Return how many times the password appears in HIBP breaches (0 = not found).

    k-anonymity: we send only the first 5 hex chars of the SHA-1 hash and match the
    rest locally against the returned list.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    request = urllib.request.Request(
        HIBP_RANGE_URL + prefix,
        headers={"User-Agent": "PassKit (https://github.com/YassinKamal345/PassKit)"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8")
    for line in body.splitlines():
        hash_suffix, _sep, count = line.partition(":")
        if hash_suffix.strip() == suffix:
            return int(count)
    return 0


def _read_password(provided: str | None) -> str:
    """Use the provided password, or prompt without echoing it to the screen."""
    if provided is not None:
        return provided
    return getpass.getpass("Password (input hidden): ")


def cmd_generate(args: argparse.Namespace) -> int:
    for _ in range(args.count):
        password = generate(
            args.length,
            symbols=not args.no_symbols,
            digits=not args.no_digits,
            upper=not args.no_upper,
            avoid_ambiguous=args.no_ambiguous,
        )
        bits, label, _ = describe_strength(password)
        print(f"{password}    ({bits:.0f} bits, {label})")
    return 0


def cmd_strength(args: argparse.Namespace) -> int:
    password = _read_password(args.password)
    bits, label, tips = describe_strength(password)
    print(f"Strength: {label} (~{bits:.0f} bits of entropy, length {len(password)})")
    if tips:
        print("Suggestions:")
        for tip in tips:
            print(f"  - {tip}")
    return 0


def cmd_breach(args: argparse.Namespace) -> int:
    password = _read_password(args.password)
    try:
        count = pwned_count(password)
    except urllib.error.URLError as exc:
        print(f"error: could not reach the breach database: {exc}", file=sys.stderr)
        return 1
    if count:
        print(f"COMPROMISED: found {count:,} times in known breaches. Do not use it.")
        return 3
    print("Not found in known breaches. (Absence is not a guarantee of safety.)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate, score and breach-check passwords.")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="Generate a strong random password.")
    gen.add_argument("-l", "--length", type=int, default=20, help="Length (default: 20).")
    gen.add_argument("-n", "--count", type=int, default=1, help="How many to generate.")
    gen.add_argument("--no-symbols", action="store_true", help="Exclude symbols.")
    gen.add_argument("--no-digits", action="store_true", help="Exclude digits.")
    gen.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters.")
    gen.add_argument("--no-ambiguous", action="store_true",
                     help="Exclude easily confused characters (Il1O0 etc.).")
    gen.set_defaults(func=cmd_generate)

    stx = sub.add_parser("strength", help="Score a password's strength.")
    stx.add_argument("password", nargs="?", help="Password (omit to be prompted securely).")
    stx.set_defaults(func=cmd_strength)

    brc = sub.add_parser("breach", help="Check a password against Have I Been Pwned.")
    brc.add_argument("password", nargs="?", help="Password (omit to be prompted securely).")
    brc.set_defaults(func=cmd_breach)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
