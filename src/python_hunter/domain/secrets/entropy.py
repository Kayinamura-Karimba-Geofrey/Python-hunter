"""Shannon Entropy Calculation Engine."""

import math
from collections import Counter


class EntropyCalculator:
    """Calculates Shannon entropy for string randomness measurement."""

    @staticmethod
    def calculate(text: str) -> float:
        """Compute Shannon entropy ($H = -\\sum p_i \\log_2 p_i$) of input text."""
        if not text:
            return 0.0

        length = len(text)
        counts = Counter(text)
        entropy = 0.0

        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)

        return round(entropy, 4)
