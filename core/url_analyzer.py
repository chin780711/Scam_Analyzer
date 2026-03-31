"""
url_analyzer.py

Responsibilities:
- Parse and analyze URL risk indicators
- Detect suspicious traits:
  - IP address host
  - non-HTTPS
  - long URL
  - suspicious keywords
  - many subdomains
  - punycode
  - lookalike / brand impersonation heuristics
  - URL shortener usage
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, asdict
from difflib import SequenceMatcher
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs


SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "payment",
    "bank",
    "confirm",
    "password",
    "signin",
    "reset",
    "unlock",
    "suspended",
    "limited",
    "otp",
    "invoice",
    "gift",
    "bonus",
    "prize",
    "claim",
}

DEFAULT_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "rebrand.ly",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "tiny.cc",
    "rb.gy",
}

DEFAULT_BRANDS = {
    "paypal",
    "apple",
    "microsoft",
    "google",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "whatsapp",
    "bank",
    "visa",
    "mastercard",
    "dhl",
    "fedex",
    "ups",
    "post",
}


@dataclass
class URLAnalysisResult:
    url: str
    scheme: str
    domain: str
    subdomain: str
    registered_domain: str
    path: str
    query_params: Dict[str, List[str]]
    flags: List[str]
    reasons: List[str]
    risk_score: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class URLAnalyzer:
    def __init__(
        self,
        suspicious_keywords: set[str] | None = None,
        shorteners: set[str] | None = None,
        known_brands: set[str] | None = None,
    ) -> None:
        self.suspicious_keywords = suspicious_keywords or SUSPICIOUS_KEYWORDS
        self.shorteners = shorteners or DEFAULT_SHORTENERS
        self.known_brands = known_brands or DEFAULT_BRANDS

    def analyze(self, url: str) -> Dict[str, Any]:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        host = parsed.netloc.lower()
        path = parsed.path or ""
        query_params = parse_qs(parsed.query)

        subdomain, registered_domain = self.split_domain(host)

        flags: List[str] = []
        reasons: List[str] = []
        risk_score = 0

        # Non-HTTPS
        if scheme != "https":
            flags.append("non_https")
            reasons.append("網址未使用 HTTPS，加密保護不足。")
            risk_score += 10

        # IP address host
        if self.is_ip_address(host):
            flags.append("ip_host")
            reasons.append("網址直接使用 IP 位址，而不是正常網域，常見於可疑連結。")
            risk_score += 20

        # URL shortener
        if registered_domain in self.shorteners or host in self.shorteners:
            flags.append("shortener")
            reasons.append("此網址使用短網址服務，可能隱藏實際目的地。")
            risk_score += 15

        # Long URL
        if len(url) > 100:
            flags.append("long_url")
            reasons.append("網址長度異常偏長，可能用來隱藏可疑內容。")
            risk_score += 10

        # Too many subdomains
        if subdomain.count(".") >= 2 or (subdomain and len(subdomain.split(".")) >= 3):
            flags.append("many_subdomains")
            reasons.append("網址含有過多子網域，可能用來偽裝官方網站。")
            risk_score += 10

        # Punycode
        if "xn--" in host:
            flags.append("punycode")
            reasons.append("網址含有 punycode，可能涉及相似字元偽裝。")
            risk_score += 20

        # Suspicious keywords
        keyword_hits = self.find_suspicious_keywords(url)
        if keyword_hits:
            flags.append("suspicious_keywords")
            reasons.append(f"網址包含高風險關鍵字：{', '.join(keyword_hits)}。")
            risk_score += min(20, 5 * len(keyword_hits))

        # Brand impersonation
        brand_result = self.detect_brand_impersonation(
            host, registered_domain, subdomain, path
        )
        if brand_result["matched"]:
            flags.extend(brand_result["flags"])
            reasons.extend(brand_result["reasons"])
            risk_score += brand_result["score"]

        risk_score = min(risk_score, 100)

        result = URLAnalysisResult(
            url=url,
            scheme=scheme,
            domain=host,
            subdomain=subdomain,
            registered_domain=registered_domain,
            path=path,
            query_params=query_params,
            flags=list(dict.fromkeys(flags)),
            reasons=reasons,
            risk_score=risk_score,
        )
        return result.to_dict()

    def split_domain(self, host: str) -> tuple[str, str]:
        """
        Simple domain split without external dependencies.

        Example:
            login.verify.paypal.com
            -> subdomain='login.verify', registered_domain='paypal.com'
        """
        parts = host.split(".")
        if len(parts) < 2:
            return "", host

        # Very simple fallback.
        registered_domain = ".".join(parts[-2:])
        subdomain = ".".join(parts[:-2])
        return subdomain, registered_domain

    def is_ip_address(self, host: str) -> bool:
        """
        Check if host is an IP address, allowing optional port stripping.
        """
        host_only = host.split(":")[0]
        try:
            ipaddress.ip_address(host_only)
            return True
        except ValueError:
            return False

    def find_suspicious_keywords(self, url: str) -> List[str]:
        lower_url = url.lower()
        hits = [kw for kw in self.suspicious_keywords if kw in lower_url]
        return sorted(hits)

    def detect_brand_impersonation(
        self,
        host: str,
        registered_domain: str,
        subdomain: str,
        path: str,
    ) -> Dict[str, Any]:
        """
        Heuristics:
        1. Brand name appears in subdomain/path but registered domain is not the brand domain.
        2. Registered domain looks similar to a brand token.
        """
        flags: List[str] = []
        reasons: List[str] = []
        score = 0
        matched = False

        host_lower = host.lower()
        reg_lower = registered_domain.lower()

        for brand in self.known_brands:
            brand_domain = f"{brand}.com"

            # Case 1: brand appears in the host but the registered domain is not the official one.
            # Covers both subdomain spoofing (brand.evil.com) and embedded-brand spoofing
            # (brand-secure-verify.com / verify-brand.com).
            brand_in_host = brand in host_lower
            is_official = reg_lower == brand_domain or reg_lower.startswith(f"{brand}.")

            if brand_in_host and not is_official:
                flags.append("brand_impersonation")
                reasons.append(
                    f"網址中出現品牌字樣「{brand}」，但主網域實際上不是官方常見網域，疑似偽裝。"
                )
                score += 25
                matched = True
                continue

            # Case 2: registered domain visually similar to brand
            root_label = reg_lower.split(".")[0]
            similarity = self.similarity(root_label, brand)

            if root_label != brand and similarity >= 0.80:
                flags.append("lookalike_domain")
                difference_reason = self.explain_lookalike_difference(root_label, brand)
                if difference_reason:
                    reasons.append(difference_reason)
                else:
                    reasons.append(
                        f"主網域「{root_label}」與品牌「{brand}」高度相似，可能是仿冒網址。"
                    )
                score += 30
                matched = True
                continue

            # Case 3: character substitution hint
            if self.has_common_lookalike_pattern(root_label, brand):
                flags.append("lookalike_domain")
                difference_reason = self.explain_lookalike_difference(root_label, brand)
                if difference_reason:
                    reasons.append(difference_reason)
                else:
                    reasons.append(
                        f"主網域「{root_label}」可能使用相似字元偽裝成「{brand}」。"
                    )
                score += 30
                matched = True

        return {
            "matched": matched,
            "flags": list(dict.fromkeys(flags)),
            "reasons": reasons,
            "score": min(score, 40),
        }

    def similarity(self, a: str, b: str) -> float:
        return SequenceMatcher(None, a, b).ratio()

    def has_common_lookalike_pattern(self, candidate: str, brand: str) -> bool:
        """
        Simple character substitution detection.
        Example:
        - paypaI vs paypal
        - micros0ft vs microsoft
        """
        replacements = {
            "0": "o",
            "1": "l",
            "3": "e",
            "5": "s",
            "7": "t",
            "8": "b",
            "9": "g",
            "i": "l",
            "l": "i",
        }

        normalized = "".join(replacements.get(ch, ch) for ch in candidate.lower())
        return normalized == brand.lower()

    def explain_lookalike_difference(self, candidate: str, brand: str) -> str | None:
        if len(candidate) != len(brand):
            return None

        diffs = []
        for i, (c, b) in enumerate(zip(candidate, brand)):
            if c != b:
                diffs.append((c, b, i))

        if len(diffs) != 1:
            return None

        actual, expected, index = diffs[0]

        char_names = {
            "0": "數字 0",
            "1": "數字 1",
            "3": "數字 3",
            "5": "數字 5",
            "i": "小寫字母 i",
            "l": "小寫字母 l",
            "I": "大寫字母 I",
            "o": "小寫字母 o",
        }

        actual_name = char_names.get(actual, f"字元 {actual}")
        expected_name = char_names.get(expected, f"字元 {expected}")

        return (
            f"主網域「{candidate}」疑似模仿「{brand}」，"
            f"其中第 {index + 1} 個字元是 {actual_name}，不是 {expected_name}。"
        )


if __name__ == "__main__":
    analyzer = URLAnalyzer()
    samples = [
        "http://192.168.1.10/login",
        "https://bit.ly/3abcd",
        "https://paypal.verify-login-security.com/login",
        "https://paypaI.com-security-check.net/update",
        "https://xn--pple-43d.com/login",
    ]

    import json

    for s in samples:
        print("=" * 80)
        print(json.dumps(analyzer.analyze(s), ensure_ascii=False, indent=2))
