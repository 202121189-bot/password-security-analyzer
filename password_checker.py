"""
Password Checker
=================
Analyzes a single password and returns a detailed security report:
  - Length & character types
  - Common patterns (repetition, sequences)
  - Known common passwords
  - Entropy (bits)
  - Estimated crack time
  - Score (0-100) + suggestions
"""

import re
import math
import os

# --------------------------------------------------------------------
# Load common passwords wordlist
# --------------------------------------------------------------------

_WORDLIST_PATH = os.path.join("wordlists", "common_passwords.txt")
_COMMON_PASSWORDS = set()

try:
    with open(_WORDLIST_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                _COMMON_PASSWORDS.add(line.lower())
except FileNotFoundError:
    pass  # wordlist optional


# --------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------

COMMON_PATTERNS = [
    "password", "admin", "user", "welcome", "qwerty", "letmein",
    "123456", "abc123", "iloveyou", "monkey", "dragon",
]

SEQUENCES = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]

# Assumed attacker speed: 10 billion guesses/second (offline GPU attack)
GUESSES_PER_SECOND = 10_000_000_000


# --------------------------------------------------------------------
# Core analysis functions
# --------------------------------------------------------------------

def _character_sets(password):
    """Return dict of which character types are used."""
    return {
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "digits": bool(re.search(r"[0-9]", password)),
        "symbols": bool(re.search(r"[^a-zA-Z0-9]", password)),
    }


def _pool_size(sets):
    """Calculate total possible character pool."""
    size = 0
    if sets["lowercase"]:
        size += 26
    if sets["uppercase"]:
        size += 26
    if sets["digits"]:
        size += 10
    if sets["symbols"]:
        size += 33  # common symbols
    return size


def _has_repetition(password):
    """Check for 3+ repeated characters (aaa, 111)."""
    return bool(re.search(r"(.)\1{2,}", password))


def _has_sequence(password):
    """Check for sequences like abc, 123, qwerty."""
    pwd = password.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - 2):
            chunk = seq[i:i + 3]
            if chunk in pwd:
                return True
            # reverse sequence (cba, 321)
            if chunk[::-1] in pwd:
                return True
    return False


def _is_common(password):
    """Check against common passwords list + patterns."""
    pwd = password.lower()
    if pwd in _COMMON_PASSWORDS:
        return True
    for pattern in COMMON_PATTERNS:
        if pattern in pwd:
            return True
    return False


def _calculate_entropy(password, pool_size):
    """Calculate Shannon-like entropy in bits."""
    if not password or pool_size == 0:
        return 0.0
    return round(len(password) * math.log2(pool_size), 2)


def _estimate_crack_time(entropy_bits):
    """Estimate average crack time in seconds."""
    if entropy_bits == 0:
        return 0
    # Average = 2^(bits-1) guesses
    guesses = 2 ** (entropy_bits - 1)
    return guesses / GUESSES_PER_SECOND


def _format_time(seconds):
    """Convert seconds to human-readable string."""
    if seconds < 1:
        return "instantly"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f} minutes"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.1f} hours"
    days = hours / 24
    if days < 365:
        return f"{days:.1f} days"
    years = days / 365
    if years < 1_000_000:
        return f"{years:,.0f} years"
    if years < 1e12:
        return f"{years/1e9:,.0f} billion years"
    return "> trillions of years"


def _calculate_score(password, sets, entropy, has_rep, has_seq, is_common):
    """Calculate score from 0 to 100."""
    score = 0

    # Length (max 30 pts)
    length = len(password)
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 25
    elif length >= 8:
        score += 15
    elif length >= 6:
        score += 5

    # Character variety (max 30 pts)
    variety = sum(sets.values())
    score += variety * 7.5  # 4 types = 30 pts

    # Entropy (max 30 pts)
    if entropy >= 80:
        score += 30
    elif entropy >= 60:
        score += 25
    elif entropy >= 40:
        score += 15
    elif entropy >= 25:
        score += 5

    # Penalties (max 10 pts deducted)
    if has_rep:
        score -= 10
    if has_seq:
        score -= 10
    if is_common:
        score -= 30

    return max(0, min(100, round(score)))


def _generate_suggestions(password, sets, score, has_rep, has_seq, is_common):
    """Return list of suggestions to improve the password."""
    suggestions = []

    if len(password) < 12:
        suggestions.append("Use at least 12 characters (16+ is better).")

    if not sets["uppercase"]:
        suggestions.append("Add uppercase letters (A-Z).")
    if not sets["lowercase"]:
        suggestions.append("Add lowercase letters (a-z).")
    if not sets["digits"]:
        suggestions.append("Add numbers (0-9).")
    if not sets["symbols"]:
        suggestions.append("Add symbols (!@#$%^&*).")

    if has_rep:
        suggestions.append("Avoid repeating characters (e.g., 'aaa', '111').")
    if has_seq:
        suggestions.append("Avoid sequences (e.g., 'abc', '123', 'qwerty').")
    if is_common:
        suggestions.append("This password is in common password lists — change it immediately!")

    if score >= 80:
        suggestions.append("Great password! Consider using a password manager to store it safely.")
    elif score >= 50:
        suggestions.append("Decent password, but can be stronger.")

    return suggestions


def _classify_strength(score):
    """Return label and color for a score."""
    if score >= 80:
        return "VERY STRONG", "green"
    elif score >= 60:
        return "STRONG", "green"
    elif score >= 40:
        return "MEDIUM", "yellow"
    elif score >= 20:
        return "WEAK", "red"
    else:
        return "VERY WEAK", "red"


# --------------------------------------------------------------------
# Main public function
# --------------------------------------------------------------------

def analyze(password):
    """Analyze a password and return a full report dict."""
    if not password:
        return {"error": "Empty password"}

    sets = _character_sets(password)
    pool = _pool_size(sets)
    entropy = _calculate_entropy(password, pool)
    has_rep = _has_repetition(password)
    has_seq = _has_sequence(password)
    is_common = _is_common(password)

    score = _calculate_score(password, sets, entropy, has_rep, has_seq, is_common)
    label, color = _classify_strength(score)
    crack_seconds = _estimate_crack_time(entropy)
    crack_time = _format_time(crack_seconds)
    suggestions = _generate_suggestions(
        password, sets, score, has_rep, has_seq, is_common
    )

    return {
        "password_masked": password[:2] + "*" * (len(password) - 2) if len(password) > 2 else "**",
        "length": len(password),
        "character_sets": sets,
        "pool_size": pool,
        "entropy_bits": entropy,
        "has_repetition": has_rep,
        "has_sequence": has_seq,
        "is_common": is_common,
        "score": score,
        "strength": label,
        "color": color,
        "crack_time": crack_time,
        "crack_seconds": crack_seconds,
        "suggestions": suggestions,
    }