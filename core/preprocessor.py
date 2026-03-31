"""
preprocessor.py

Responsibilities:
- Normalize raw input text
- Extract URLs from text
- Extract phone numbers from text
- Classify input type (text / url / mixed)
- Detect basic language hints
- Prepare a clean structure for downstream modules
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any
from urllib.parse import urlparse


URL_REGEX = re.compile(
    r"""(?ix)
    \b(
        (?:
            https?://
            |
            www\.
        )
        [^\s<>"'()]+
    )
    """
)

# Optional fallback for bare domains like example.com/login
BARE_DOMAIN_REGEX = re.compile(
    r"""(?ix)
    \b(
        (?:[a-z0-9-]+\.)+
        (?:[a-z]{2,})
        (?:/[^\s<>"']*)?
    )
    \b
    """
)

# Phone number patterns — covers TW/CN/international formats
PHONE_REGEX = re.compile(
    r"""(?x)
    (?:
        # International: +886-2-1234-5678 / +8869xxxxxxxx
        \+\d{1,3}[\s\-]?\(?\d{1,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}
        |
        # TW mobile: 09xx-xxxxxx / 09xxxxxxxx
        0[89]\d{1,2}[\s\-]?\d{3,4}[\s\-]?\d{3,4}
        |
        # TW landline: (02)1234-5678 / 02-1234-5678
        (?:\(0\d\)|0\d)[\s\-]?\d{3,4}[\s\-]?\d{4}
        |
        # Plain long number sequences (8–11 digits, possible scam hotline)
        \b\d{8,11}\b
    )
    """
)


@dataclass
class PreprocessedInput:
    input_type: str  # text | url | mixed | empty
    raw_text: str
    normalized_text: str
    urls: List[str]
    phones: List[str]
    cleaned_text: str
    language_hint: str  # zh | en | mixed | unknown

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Preprocessor:
    def __init__(self) -> None:
        pass

    def process(self, raw_input: str) -> Dict[str, Any]:
        """
        Main entry point.

        Returns:
            dict with normalized text, extracted urls, phones, input type, etc.
        """
        raw_text = raw_input or ""
        normalized_text = self.normalize_text(raw_text)
        urls = self.extract_urls(normalized_text)
        phones = self.extract_phones(normalized_text)
        cleaned_text = self.remove_urls(normalized_text, urls).strip()
        input_type = self.classify_input(normalized_text, urls, cleaned_text)
        language_hint = self.detect_language_hint(cleaned_text or normalized_text)

        result = PreprocessedInput(
            input_type=input_type,
            raw_text=raw_text,
            normalized_text=normalized_text,
            urls=urls,
            phones=phones,
            cleaned_text=cleaned_text,
            language_hint=language_hint,
        )
        return result.to_dict()

    def normalize_text(self, text: str) -> str:
        """
        Basic normalization:
        - strip leading/trailing spaces
        - collapse repeated whitespace
        - normalize some full-width punctuation
        """
        if not text:
            return ""

        replacements = {
            "：": ":",
            "，": ",",
            "。": ".",
            "（": "(",
            "）": ")",
            "　": " ",  # full-width space
        }

        for old, new in replacements.items():
            text = text.replace(old, new)

        text = text.strip()
        text = re.sub(r"\s+", " ", text)
        return text

    def extract_phones(self, text: str) -> List[str]:
        """
        Extract phone numbers from text.
        Returns deduplicated list of matched phone strings.
        """
        if not text:
            return []

        found = []
        seen = set()
        for match in PHONE_REGEX.findall(text):
            normalized = re.sub(r"[\s\-()]", "", match)
            if normalized not in seen:
                seen.add(normalized)
                found.append(match.strip())
        return found

    def extract_urls(self, text: str) -> List[str]:
        """
        Extract URLs from text.
        Supports:
        - full URLs with http/https
        - www.xxx.com
        - bare domains like example.com/login
        """
        if not text:
            return []

        found = []

        # Standard URLs
        for match in URL_REGEX.findall(text):
            found.append(self.normalize_url(match))

        # Bare domains
        for match in BARE_DOMAIN_REGEX.findall(text):
            candidate = match.strip()
            if self.looks_like_domain(candidate):
                normalized = self.normalize_url(candidate)
                if normalized not in found:
                    found.append(normalized)

        return found

    def remove_urls(self, text: str, urls: List[str]) -> str:
        """
        Remove extracted URLs from text to make keyword scanning cleaner.
        """
        cleaned = text
        for url in sorted(urls, key=len, reverse=True):
            original_forms = {url}

            if url.startswith("http://"):
                original_forms.add(url.replace("http://", "", 1))
            if url.startswith("https://"):
                original_forms.add(url.replace("https://", "", 1))

            for form in original_forms:
                cleaned = cleaned.replace(form, " ")

        cleaned = re.sub(r"\s+", " ", cleaned)
        return cleaned.strip()

    def classify_input(self, text: str, urls: List[str], cleaned_text: str) -> str:
        """
        Decide if input is:
        - empty
        - url
        - text
        - mixed
        """
        if not text.strip():
            return "empty"

        only_url = False
        if len(urls) == 1:
            compact = text.strip()
            if compact == urls[0]:
                only_url = True
            elif compact in {
                urls[0].replace("https://", "", 1),
                urls[0].replace("http://", "", 1),
            }:
                only_url = True

        if only_url:
            return "url"

        if urls and cleaned_text:
            return "mixed"

        if urls and not cleaned_text:
            return "url"

        return "text"

    def detect_language_hint(self, text: str) -> str:
        """
        Rough language hint only.
        """
        if not text:
            return "unknown"

        has_zh = bool(re.search(r"[\u4e00-\u9fff]", text))
        has_en = bool(re.search(r"[A-Za-z]", text))

        if has_zh and has_en:
            return "mixed"
        if has_zh:
            return "zh"
        if has_en:
            return "en"
        return "unknown"

    def normalize_url(self, url: str) -> str:
        """
        Normalize URL:
        - prepend https:// if scheme missing
        - lower hostname
        """
        url = url.strip().rstrip(".,!?)];:'\"")

        if not re.match(r"^https?://", url, flags=re.IGNORECASE):
            url = "https://" + url

        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        scheme = parsed.scheme.lower() or "https"
        path = parsed.path or ""
        query = f"?{parsed.query}" if parsed.query else ""
        fragment = f"#{parsed.fragment}" if parsed.fragment else ""

        return f"{scheme}://{netloc}{path}{query}{fragment}"

    def looks_like_domain(self, value: str) -> bool:
        """
        Heuristic check for bare domains.
        """
        if " " in value:
            return False

        # Reject emails
        if "@" in value:
            return False

        # Basic domain structure
        return bool(
            re.match(
                r"(?ix)^(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/.*)?$",
                value.strip(),
            )
        )


if __name__ == "__main__":
    sample = """
    您的帳戶異常，請立即登入驗證：
    https://paypaI-secure-login.com/verify?step=1
    """

    processor = Preprocessor()
    result = processor.process(sample)

    import json

    print(json.dumps(result, ensure_ascii=False, indent=2))
