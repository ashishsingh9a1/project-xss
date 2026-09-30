"""
features.py

Turns a piece of text into a small set of numeric features the anomaly
detector can learn from. These are deliberately NOT "does it contain
<script>" style features -- that's the rule engine's job. These are
statistical/structural properties of the text, so the anomaly detector
can flag input that "looks wrong" even when it matches no known pattern.
"""

import math
import re
from collections import Counter

SPECIAL_CHARS = set("<>\"'`;(){}=&%/\\")


def special_char_ratio(text: str) -> float:
    if not text:
        return 0.0
    count = sum(1 for c in text if c in SPECIAL_CHARS)
    return count / len(text)


def tag_count(text: str) -> int:
    return len(re.findall(r"<[^>]*>", text))


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def digit_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for c in text if c.isdigit()) / len(text)


def uppercase_ratio(text: str) -> float:
    if not text:
        return 0.0
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c.isupper()) / len(letters)


def max_word_length(text: str) -> int:
    words = re.split(r"\s+", text.strip())
    return max((len(w) for w in words), default=0)


FEATURE_NAMES = [
    "length",
    "special_char_ratio",
    "tag_count",
    "entropy",
    "digit_ratio",
    "uppercase_ratio",
    "max_word_length",
]


def extract(text: str) -> list:
    """Return the feature vector for one piece of text, as a plain list
    (order matches FEATURE_NAMES) so it can go straight into sklearn."""
    return [
        len(text),
        special_char_ratio(text),
        tag_count(text),
        shannon_entropy(text),
        digit_ratio(text),
        uppercase_ratio(text),
        max_word_length(text),
    ]


if __name__ == "__main__":
    samples = [
        "Great article, thanks for sharing!",
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert(1)>",
    ]
    print(f"{'text':45} " + " ".join(f"{n:>10}" for n in FEATURE_NAMES))
    for s in samples:
        vals = extract(s)
        print(f"{s[:45]!r:45} " + " ".join(f"{v:>10.2f}" for v in vals))
