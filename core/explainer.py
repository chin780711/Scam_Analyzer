"""
explainer.py

Responsibilities:
- Turn raw detection results into human-readable explanations
- Summarize the main risk story
- Produce user-facing explanation output
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, Any, List


@dataclass
class ExplanationResult:
    summary: str
    explanation_points: List[str]
    flagged_items: List[str]
    user_friendly_label: str
    top_reasons: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Explainer:
    """
    Convert machine-oriented detection output into plain-language explanation.
    """

    FLAG_LABELS = {
        "urgent_language": "訊息帶有強烈催促語氣",
        "credential_request": "要求提供帳號、密碼或驗證碼",
        "financial_request": "要求提供付款或銀行相關資訊",
        "link_pressure": "引導你立刻點擊連結",
        "prize_or_reward": "以中獎、獎勵或免費內容吸引你",
        "official_impersonation": "疑似冒充官方、客服或安全單位",
        "delivery_scam": "疑似以包裹或物流問題為由誘導操作",
        "job_scam": "疑似以高薪兼職或在家工作為誘餌",
        "phone_number_present": "訊息包含電話號碼",
        "phone_with_pressure": "電話號碼搭配催促或冒充語氣",
        "combined_link_and_urgency": "同時結合連結與緊急施壓",
        "combined_link_and_credential_request": "同時要求點連結與輸入敏感資料",
        "combined_credential_and_financial_request": "同時涉及帳密與金流資訊",
        "attachment_lure": "可能利用附件或文件下載誘導操作",
        "url_non_https": "網址未使用 HTTPS",
        "url_ip_host": "網址直接使用 IP 位址",
        "url_shortener": "網址使用短網址服務",
        "url_long_url": "網址異常偏長",
        "url_many_subdomains": "網址含有過多子網域",
        "url_punycode": "網址含有 punycode 偽裝風險",
        "url_suspicious_keywords": "網址含有高風險關鍵字",
        "url_brand_impersonation": "網址疑似假冒品牌",
        "url_lookalike_domain": "網址疑似為相似網域偽裝",
    }

    def __init__(self) -> None:
        pass

    def explain(
        self,
        preprocessed: Dict[str, Any],
        rule_result: Dict[str, Any],
        score_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Input:
            preprocessed
            rule_result
            score_result

        Output:
            user-facing explanation
        """
        risk_level = score_result.get("risk_level", "low")
        flags = rule_result.get("flags", [])
        reasons = rule_result.get("reasons", [])
        urls = preprocessed.get("urls", [])

        flagged_items = self.translate_flags(flags)
        scam_pattern = self.detect_scam_pattern(flags)
        explanation_points = self.build_explanation_points(flagged_items, reasons, urls)
        top_reasons = self.build_top_reasons(explanation_points)
        summary = self.build_summary(risk_level, scam_pattern, urls)
        user_friendly_label = self.risk_label_zh(risk_level)

        result = ExplanationResult(
            summary=summary,
            explanation_points=explanation_points,
            flagged_items=flagged_items,
            top_reasons=top_reasons,
            user_friendly_label=user_friendly_label,
        )
        return result.to_dict()

    def translate_flags(self, flags: List[str]) -> List[str]:
        results = []
        for flag in flags:
            results.append(self.FLAG_LABELS.get(flag, flag))

        # deduplicate while preserving order
        seen = set()
        deduped = []
        for item in results:
            if item not in seen:
                seen.add(item)
                deduped.append(item)

        return deduped

    def build_explanation_points(
        self,
        flagged_items: List[str],
        reasons: List[str],
        urls: List[str],
    ) -> List[str]:
        points: List[str] = []

        for item in flagged_items:
            if item not in points:
                points.append(item)

        for reason in reasons:
            short_reason = self.shorten_reason(reason)
            if short_reason not in points:
                points.append(short_reason)

        if urls:
            points.append(f"此內容共包含 {len(urls)} 個網址，已一併納入分析。")

        return points[:6]

    def build_top_reasons(self, explanation_points: List[str]) -> List[str]:
        filtered = []

        skip_keywords = [
            "共包含",
            "已一併納入分析",
            "納入分析",
        ]

        for point in explanation_points:
            if any(keyword in point for keyword in skip_keywords):
                continue
            filtered.append(point)

        return filtered[:3]

    def shorten_reason(self, reason: str) -> str:
        replacements = {
            "訊息含有緊急或催促語氣，常見於詐騙或社交工程內容。": "內容使用催促語氣，試圖讓你急著處理。",
            "訊息要求提供登入資訊或驗證碼，屬於高風險特徵。": "內容要求你提供帳號、密碼或驗證碼。",
            "主網域與品牌名稱高度相似，可能是 lookalike domain。": "網址與常見官方網域非常相似，可能是仿冒網址。",
        }
        return replacements.get(reason, reason)

    def build_summary(
        self,
        risk_level: str,
        scam_pattern: str,
        urls: List[str],
    ) -> str:
        zh_level = self.risk_label_zh(risk_level)

        if risk_level in {"critical", "high"}:
            if urls:
                return f"這則內容屬於{zh_level}，疑似{scam_pattern}，並透過可疑網址誘導你進一步操作。"
            return f"這則內容屬於{zh_level}，疑似{scam_pattern}，請不要直接依照訊息要求操作。"

        if risk_level == "medium":
            return f"這則內容屬於{zh_level}，出現部分{scam_pattern}常見特徵，建議提高警覺。"

        return f"這則內容目前屬於{zh_level}，未發現明顯高風險特徵，但仍建議保持警覺。"

    def join_top_items(self, items: List[str], limit: int = 3) -> str:
        if not items:
            return "無明顯特徵"

        selected = items[:limit]
        return "、".join(selected)

    def risk_label_zh(self, risk_level: str) -> str:
        mapping = {
            "low": "低風險",
            "medium": "中風險",
            "high": "高風險",
            "critical": "極高風險",
        }
        return mapping.get(risk_level, "未知風險")

    def detect_scam_pattern(self, flags: List[str]) -> str:
        flag_set = set(flags)

        if "delivery_scam" in flag_set:
            return "假冒物流通知"
        if "job_scam" in flag_set:
            return "高薪兼職詐騙"
        if "official_impersonation" in flag_set and "credential_request" in flag_set:
            return "假冒官方登入驗證"
        if "financial_request" in flag_set:
            return "金流或付款誘導"
        if "prize_or_reward" in flag_set:
            return "中獎或獎勵誘導"
        return "可疑詐騙訊息"


if __name__ == "__main__":
    import json

    preprocessed = {
        "input_type": "mixed",
        "raw_text": "請立即驗證帳戶 https://paypaI-security-login.com",
        "normalized_text": "請立即驗證帳戶 https://paypaI-security-login.com",
        "urls": ["https://paypaI-security-login.com"],
        "cleaned_text": "請立即驗證帳戶",
        "language_hint": "zh",
    }

    rule_result = {
        "risk_score": 88,
        "risk_level": "high",
        "flags": [
            "urgent_language",
            "credential_request",
            "url_lookalike_domain",
            "combined_link_and_credential_request",
        ],
        "reasons": [
            "訊息含有緊急或催促語氣，常見於詐騙或社交工程內容。",
            "訊息要求提供登入資訊或驗證碼，屬於高風險特徵。",
            "主網域與品牌名稱高度相似，可能是 lookalike domain。",
        ],
        "matched_rules": {},
        "url_analysis": [],
    }

    score_result = {
        "risk_score": 88,
        "risk_level": "high",
        "score_breakdown": {},
    }

    explainer = Explainer()
    result = explainer.explain(preprocessed, rule_result, score_result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
