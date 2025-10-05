import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Return bits/byte Shannon entropy of data."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    if n < 2:
        return 0.0
    entropy = -sum((count / n) * math.log2(count / n) for count in counts.values())
    if n < 256:
        entropy *= math.log2(256) / math.log2(n)
    return max(0.0, min(entropy, 8.0))


def hex_histogram(data: bytes) -> dict[int, int]:
    """Histogram of byte values 0..255 present in data."""
    return dict(Counter(data))
