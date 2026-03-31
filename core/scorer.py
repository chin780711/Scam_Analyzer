"""
scorer.py

Responsibilities:
- Normalize and finalize scam risk score
- Convert score into risk level
- Provide score summary for downstream modules
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, Any, List


@dataclass
class ScoreResult:
    risk_score: int
    risk_level: str
    score_breakdown: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Scorer:
    """
    Final scoring layer.

    In the current MVP:
    - rule_engine already computes most of the score
    - scorer is responsible for:
        1. clamping / normalizing score
        2. converting to risk level
        3. producing a structured score breakdown

    Later you can expand this class to:
    - add model-based score
    - adjust weighting
    - support confidence score
    """

    def __init__(self) -> None:
        pass

    def score(self, rule_result: Dict[str, Any]) -> Dict[str, Any]:
        flags: List[str] = rule_result.get("flags", [])
        reasons: List[str] = rule_result.get("reasons", [])
        url_analysis: List[Dict[str, Any]] = rule_result.get("url_analysis", [])

        raw_score = int(rule_result.get("risk_score", 0))

        adjustment_result = self.calculate_adjustments(flags, url_analysis)
        adjustment_score = adjustment_result["adjustment_score"]

        final_score = self.normalize_score(raw_score + adjustment_score)
        risk_level = self.score_to_level(final_score)
        risk_level = self.enforce_minimum_risk_level(flags, risk_level)

        high_impact_flags = self.extract_high_impact_flags(flags)

        score_breakdown = {
            "raw_score": raw_score,
            "adjustment_score": adjustment_score,
            "final_score": final_score,
            "risk_level": risk_level,
            "flag_count": len(flags),
            "reason_count": len(reasons),
            "url_count": len(url_analysis),
            "high_impact_flags": high_impact_flags,
            "high_impact_flag_count": len(high_impact_flags),
            "max_url_risk_score": max(
                (u.get("risk_score", 0) for u in url_analysis), default=0
            ),
            "adjustment_reasons": adjustment_result["adjustment_reasons"],
        }

        result = ScoreResult(
            risk_score=final_score,
            risk_level=risk_level,
            score_breakdown=score_breakdown,
        )
        return result.to_dict()

    def enforce_minimum_risk_level(self, flags: List[str], current_level: str) -> str:
        flag_set = set(flags)

        if "combined_credential_and_financial_request" in flag_set:
            return "critical"

        if "combined_link_and_credential_request" in flag_set:
            return "high"

        if "credential_request" in flag_set and (
            "lookalike_domain" in flag_set or "url_lookalike_domain" in flag_set
        ):
            return "high"

        if "financial_request" in flag_set and (
            "brand_impersonation" in flag_set or "url_brand_impersonation" in flag_set
        ):
            return "high"

        if "job_scam" in flag_set and "urgent_language" in flag_set:
            return "high"

        if "job_scam" in flag_set:
            return "medium"

        return current_level

    def normalize_score(self, score: int) -> int:
        """
        Clamp score into 0~100.
        """
        if score < 0:
            return 0
        if score > 100:
            return 100
        return score

    def score_to_level(self, score: int) -> str:
        """
        Risk level mapping.
        """
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 30:
            return "medium"
        return "low"

    def calculate_adjustments(
        self,
        flags: List[str],
        url_analysis: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        adjustment = 0
        reasons = []

        high_risk_flags = {
            "job_scam": 12,
            "credential_request": 15,
            "financial_request": 15,
            "brand_impersonation": 12,
            "url_brand_impersonation": 12,
            "lookalike_domain": 12,
            "url_lookalike_domain": 12,
            "ip_host": 10,
            "url_ip_host": 10,
            "shortener": 8,
            "url_shortener": 8,
            "combined_link_and_credential_request": 15,
            "combined_credential_and_financial_request": 20,
        }

        for flag in flags:
            if flag in high_risk_flags:
                adjustment += high_risk_flags[flag]
                reasons.append(f"{flag} +{high_risk_flags[flag]}")

        if url_analysis:
            max_url_score = max(
                (u.get("risk_score", 0) for u in url_analysis), default=0
            )
            if max_url_score >= 70:
                adjustment += 10
                reasons.append("high_risk_url +10")
            elif max_url_score >= 40:
                adjustment += 5
                reasons.append("medium_risk_url +5")

        return {
            "adjustment_score": adjustment,
            "adjustment_reasons": reasons,
        }

    def extract_high_impact_flags(self, flags: List[str]) -> List[str]:
        """
        Extract especially dangerous flags for UI emphasis.
        """
        priority_keywords = [
            "job_scam",
            "credential",
            "financial",
            "brand_impersonation",
            "lookalike",
            "ip_host",
            "shortener",
            "combined_link_and_credential_request",
            "combined_credential_and_financial_request",
        ]

        results = []
        for flag in flags:
            if any(keyword in flag for keyword in priority_keywords):
                results.append(flag)

        # preserve order + deduplicate
        seen = set()
        deduped = []
        for item in results:
            if item not in seen:
                seen.add(item)
                deduped.append(item)

        return deduped


if __name__ == "__main__":
    import json

    sample_rule_result = {
        "risk_score": 92,
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
        ],
        "matched_rules": {},
        "url_analysis": [{"url": "https://paypaI-verify.com", "risk_score": 35}],
    }

    scorer = Scorer()
    result = scorer.score(sample_rule_result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
