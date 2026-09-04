import re

BLOCKED_PATTERN = re.compile(r"__|import|os\.|subprocess|popen|system\(", re.IGNORECASE)
BYPASS_SIGNATURE = re.compile(r"attr\(")


def contains_disallowed_pattern(text: str) -> bool:
    return bool(BLOCKED_PATTERN.search(text))


def matches_bypass_signature(text: str) -> bool:
    return bool(BYPASS_SIGNATURE.search(text))
