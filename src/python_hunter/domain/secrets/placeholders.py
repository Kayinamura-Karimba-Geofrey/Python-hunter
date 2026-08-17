"""Placeholder and False Positive Secret Filtering Engine."""

import re


class PlaceholderFilter:
    """Filters out common placeholders, dummy strings, and false-positive secret candidates."""

    KNOWN_PLACEHOLDERS = {
        "YOUR_API_KEY",
        "YOUR_SECRET_KEY",
        "YOUR_TOKEN",
        "YOUR_PASSWORD",
        "REPLACE_ME",
        "CHANGEME",
        "EXAMPLE",
        "SAMPLE",
        "DUMMY",
        "LOCALHOST",
        "PASSWORD",
        "SECRET",
        "TOKEN",
        "API_KEY",
        "TEST_KEY",
        "TEST_TOKEN",
        "INSERT_HERE",
        "ENTER_HERE",
        "MY_SECRET",
        "FOOBAR",
    }

    PLACEHOLDER_REGEXES = [
        re.compile(r"^x{4,}$", re.IGNORECASE),
        re.compile(r"^\*{4,}$"),
        re.compile(r"^0{4,}$"),
        re.compile(r"^12345678"),
        re.compile(r"^<.*>$"),
        re.compile(r"^\[.*\]$"),
        re.compile(r"your[_-]?api[_-]?key", re.IGNORECASE),
        re.compile(r"replace[_-]?me", re.IGNORECASE),
        re.compile(r"change[_-]?me", re.IGNORECASE),
    ]

    @classmethod
    def is_placeholder(cls, value: str) -> bool:
        """Determine if a secret candidate string matches known placeholder patterns."""
        cleaned = value.strip().strip("'\"").strip()
        if not cleaned:
            return True

        upper_val = cleaned.upper()
        if upper_val in cls.KNOWN_PLACEHOLDERS:
            return True

        for regex in cls.PLACEHOLDER_REGEXES:
            if regex.search(cleaned):
                return True

        return False
