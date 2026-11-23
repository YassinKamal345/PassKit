# 🔐 PassKit

A small **password toolkit** in a single Python file: generate strong passwords, score their
strength, and check whether a password has appeared in known data breaches.

No third-party libraries — just the Python standard library.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

## Commands

```bash
# Generate a strong 20-character password (symbols + digits + upper by default)
python passkit.py generate

# Generate 5 passwords, length 24, without ambiguous characters (Il1O0…)
python passkit.py generate -n 5 -l 24 --no-ambiguous

# Score a password's strength (prompts securely if you omit it)
python passkit.py strength

# Check a password against Have I Been Pwned
python passkit.py breach
```

## Breach check & privacy

The `breach` command uses the **Have I Been Pwned** range API with **k-anonymity**:

1. It computes the SHA-1 hash of the password locally.
2. It sends **only the first 5 hex characters** of that hash to the API.
3. The API returns every breached hash sharing that prefix, and PassKit matches the rest
   **locally**.

Your password never leaves your machine, and neither does its full hash. If you omit the
password on the command line, PassKit prompts for it with the input hidden.

## Strength scoring

Strength is estimated from the character classes actually used and the length, expressed in
**bits of entropy** (`length × log2(pool size)`), with practical suggestions:

```
Strength: very strong (~138 bits of entropy, length 21)

Strength: weak (~31 bits of entropy, length 6)
Suggestions:
  - use at least 12 characters (longer is better than complex)
  - add uppercase letters
  - add symbols
```

Passwords are generated with Python's `secrets` module (a cryptographically secure RNG) and
always contain at least one character from each selected class.

## Exit codes

`breach` returns `3` when a password is compromised, so you can use it in scripts:

```bash
python passkit.py breach "$MY_PASS" && echo "looks clean"
```

## License

MIT - see [LICENSE](LICENSE). Author: **Yassin Kamal** ·
[Portfolio](https://portfolio-sand-eight-20.vercel.app) ·
[LinkedIn](https://www.linkedin.com/in/yassin-kamal-simo/)
