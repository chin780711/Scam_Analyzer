"""
rule_engine.py

Responsibilities:
- Inspect preprocessed text
- Apply rule-based scam detection
- Aggregate text signals and URL analysis signals
- Produce flags, reasons, and a total risk score
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Dict, Any, List

from core.url_analyzer import URLAnalyzer


DEFAULT_RULES = {
    "urgent_language": {
        "patterns": [
            r"立即",
            r"馬上",
            r"盡快",
            r"緊急",
            r"立即處理",
            r"限時",
            r"24小時內",
            r"帳戶將被停用",
            r"最後通知",
            r"urgent",
            r"immediately",
            r"act now",
            r"final notice",
            r"limited time",
            r"expire(?:d|s)? soon",
            r"suspended",
        ],
        "score": 15,
        "reason": "訊息含有緊急或催促語氣，常見於詐騙或社交工程內容。",
    },
    "credential_request": {
        "patterns": [
            r"密碼",
            r"驗證碼",
            r"OTP",
            r"一次性密碼",
            r"登入驗證",
            r"帳號密碼",
            r"password",
            r"passcode",
            r"verification code",
            r"one-time password",
            r"login credentials",
            r"sign in to verify",
        ],
        "score": 30,
        "reason": "訊息要求提供登入資訊或驗證碼，屬於高風險特徵。",
    },
    "financial_request": {
        "patterns": [
            r"付款",
            r"匯款",
            r"轉帳",
            r"信用卡",
            r"銀行帳號",
            r"退款",
            r"payment",
            r"bank account",
            r"credit card",
            r"wire transfer",
            r"refund",
            r"invoice",
        ],
        "score": 20,
        "reason": "訊息涉及金流、信用卡或銀行資料要求，具有詐騙風險。",
    },
    "link_pressure": {
        "patterns": [
            r"點擊連結",
            r"點此",
            r"立即登入",
            r"立即驗證",
            r"請點擊",
            r"click here",
            r"click the link",
            r"verify now",
            r"log in now",
            r"open the link",
        ],
        "score": 20,
        "reason": "訊息引導使用者立刻點擊連結，屬常見誘導手法。",
    },
    "prize_or_reward": {
        "patterns": [
            r"中獎",
            r"獎勵",
            r"禮物",
            r"免費",
            r"贈品",
            r"bonus",
            r"reward",
            r"gift",
            r"claim now",
            r"winner",
            r"free",
            r"prize",
        ],
        "score": 15,
        "reason": "訊息以獎勵、免費或中獎等誘因吸引點擊，屬常見詐騙特徵。",
    },
    "official_impersonation": {
        "patterns": [
            r"官方通知",
            r"客服中心",
            r"銀行通知",
            r"系統通知",
            r"帳戶異常",
            r"security team",
            r"support team",
            r"official notice",
            r"account issue",
            r"account suspended",
            r"service alert",
        ],
        "score": 15,
        "reason": "訊息可能冒充官方、客服或安全部門，具有社交工程風險。",
    },
    "delivery_scam": {
        "patterns": [
            r"包裹",
            r"配送失敗",
            r"快遞",
            r"物流",
            r"補運費",
            r"parcel",
            r"delivery failed",
            r"courier",
            r"shipment",
            r"reschedule delivery",
        ],
        "score": 15,
        "reason": "訊息疑似利用包裹、物流或配送問題誘導點擊或付款。",
    },
    "job_scam": {
        "patterns": [
            r"高薪",
            r"日結",
            r"在家工作",
            r"兼職",
            r"輕鬆賺",
            r"high salary",
            r"daily pay",
            r"work from home",
            r"part-time",
            r"easy money",
        ],
        "score": 15,
        "reason": "訊息可能利用求職、兼職或快速賺錢作為誘餌。",
    },
}


@dataclass
class RuleEngineResult:
    risk_score: int
    risk_level: str
    flags: List[str]
    reasons: List[str]
    matched_rules: Dict[str, List[str]]
    url_analysis: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RuleEngine:
    def __init__(self, rules: Dict[str, Dict[str, Any]] | None = None) -> None:
        self.rules = rules or DEFAULT_RULES
        self.url_analyzer = URLAnalyzer()

    def analyze(self, preprocessed: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze preprocessed input.

        Expected preprocessed dict:
        {
            "input_type": "mixed",
            "raw_text": "...",
            "normalized_text": "...",
            "urls": [...],
            "cleaned_text": "...",
            "language_hint": "zh"
        }
        """
        text = preprocessed.get("cleaned_text", "") or preprocessed.get(
            "normalized_text", ""
        )
        urls = preprocessed.get("urls", []) or []
        phones = preprocessed.get("phones", []) or []

        flags: List[str] = []
        reasons: List[str] = []
        matched_rules: Dict[str, List[str]] = {}
        score = 0

        # 1. Text-based rules
        for rule_name, rule_data in self.rules.items():
            hits = self.match_patterns(text, rule_data["patterns"])
            if hits:
                flags.append(rule_name)
                reasons.append(rule_data["reason"])
                matched_rules[rule_name] = hits
                score += int(rule_data["score"])

        # 2. URL-based analysis
        url_results: List[Dict[str, Any]] = []
        for url in urls:
            analysis = self.url_analyzer.analyze(url)
            url_results.append(analysis)

            if analysis["flags"]:
                for f in analysis["flags"]:
                    composite_flag = f"url_{f}"
                    if composite_flag not in flags:
                        flags.append(composite_flag)

                reasons.extend(analysis["reasons"])
                score += int(analysis["risk_score"])

        # 3. Extra combined heuristics
        combined_bonus, combined_flags, combined_reasons = (
            self.apply_combined_heuristics(
                text=text,
                urls=urls,
                existing_flags=flags,
            )
        )

        score += combined_bonus
        for f in combined_flags:
            if f not in flags:
                flags.append(f)
        reasons.extend(combined_reasons)

        # 4. Phone number analysis
        if phones:
            phone_bonus, phone_flags, phone_reasons = self.analyze_phones(
                phones=phones,
                existing_flags=flags,
            )
            score += phone_bonus
            for f in phone_flags:
                if f not in flags:
                    flags.append(f)
            reasons.extend(phone_reasons)

        score = min(score, 100)
        risk_level = self.score_to_level(score)

        result = RuleEngineResult(
            risk_score=score,
            risk_level=risk_level,
            flags=flags,
            reasons=self.deduplicate_preserve_order(reasons),
            matched_rules=matched_rules,
            url_analysis=url_results,
        )
        return result.to_dict()

    def match_patterns(self, text: str, patterns: List[str]) -> List[str]:
        hits = []
        for pattern in patterns:
            if re.search(pattern, text, flags=re.IGNORECASE):
                hits.append(pattern)
        return hits

    def apply_combined_heuristics(
        self,
        text: str,
        urls: List[str],
        existing_flags: List[str],
    ) -> tuple[int, List[str], List[str]]:
        """
        Add bonus score when multiple suspicious signals appear together.
        """
        bonus = 0
        flags: List[str] = []
        reasons: List[str] = []

        has_link = len(urls) > 0
        has_urgent = "urgent_language" in existing_flags
        has_credential = "credential_request" in existing_flags
        has_financial = "financial_request" in existing_flags

        if has_link and has_urgent:
            bonus += 10
            flags.append("combined_link_and_urgency")
            reasons.append("訊息同時包含連結與緊急語氣，風險明顯提高。")

        if has_link and has_credential:
            bonus += 15
            flags.append("combined_link_and_credential_request")
            reasons.append("訊息同時要求點擊連結與提供驗證資訊，屬高風險組合。")

        if has_credential and has_financial:
            bonus += 15
            flags.append("combined_credential_and_financial_request")
            reasons.append("訊息同時涉及帳密與金流資訊，屬高風險詐騙特徵。")

        # Simple attachment lure
        if re.search(
            r"\b(?:attachment|invoice|pdf|docx|zip)\b", text, flags=re.IGNORECASE
        ):
            bonus += 10
            flags.append("attachment_lure")
            reasons.append("訊息提及附件或文件下載，可能誘導使用者開啟惡意檔案。")

        return bonus, flags, reasons

    def analyze_phones(
        self,
        phones: List[str],
        existing_flags: List[str],
    ) -> tuple[int, List[str], List[str]]:
        """
        Analyze phone numbers found in the message.
        - Any phone number alone is a mild signal.
        - Phone + urgency/impersonation = higher risk (social engineering pattern).
        """
        bonus = 0
        flags: List[str] = []
        reasons: List[str] = []

        # Base: phone number present
        bonus += 10
        flags.append("phone_number_present")
        reasons.append(
            f"訊息包含 {len(phones)} 個電話號碼，詐騙訊息常以電話引導受害者進一步接觸。"
        )

        # Combined: phone + urgency or impersonation = social engineering
        has_urgent = "urgent_language" in existing_flags
        has_impersonation = "official_impersonation" in existing_flags

        if has_urgent or has_impersonation:
            bonus += 15
            flags.append("phone_with_pressure")
            reasons.append(
                "訊息同時包含電話號碼與催促/冒充語氣，屬常見社交工程手法，請勿主動撥打。"
            )

        return bonus, flags, reasons

    def score_to_level(self, score: int) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 30:
            return "medium"
        return "low"

    def deduplicate_preserve_order(self, items: List[str]) -> List[str]:
        seen = set()
        result = []
        for item in items:
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result


if __name__ == "__main__":
    from core.preprocessor import Preprocessor
    import json

    sample = """
    您的帳戶異常，請立即點擊連結登入驗證，否則 24 小時內將被停用：
    https://paypaI-secure-login.com/verify
    """

    pre = Preprocessor().process(sample)
    result = RuleEngine().analyze(pre)

    print(json.dumps(pre, ensure_ascii=False, indent=2))
    print("=" * 80)
    print(json.dumps(result, ensure_ascii=False, indent=2))
