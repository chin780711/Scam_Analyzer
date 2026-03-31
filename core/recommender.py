"""
recommender.py

Responsibilities:
- Generate actionable safety recommendations
- Tailor next steps based on flags and risk level
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, Any, List


@dataclass
class RecommendationResult:
    recommendations: List[str]
    immediate_actions: List[str]
    do_not_actions: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Recommender:
    """
    Turn analysis output into practical user actions.
    """

    def __init__(self) -> None:
        pass

    def recommend(
        self,
        preprocessed: Dict[str, Any],
        rule_result: Dict[str, Any],
        score_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        risk_level = score_result.get("risk_level", "low")
        flags = rule_result.get("flags", [])
        urls = preprocessed.get("urls", [])

        recommendations: List[str] = []
        immediate_actions: List[str] = []
        do_not_actions: List[str] = []

        # Base recommendations by risk
        if risk_level in {"critical", "high"}:
            recommendations.extend(
                [
                    "此內容風險偏高，請不要依照訊息指示操作。",
                    "請改用官方 App、官方網站或官方客服重新確認資訊。",
                ]
            )
            immediate_actions.extend(
                [
                    "停止與該訊息互動。",
                    "若已點開連結，請確認是否輸入過帳號、密碼、驗證碼或付款資料。",
                ]
            )
            do_not_actions.extend(
                [
                    "不要點擊訊息中的連結。",
                    "不要輸入帳號、密碼、驗證碼或信用卡資料。",
                ]
            )

        elif risk_level == "medium":
            recommendations.extend(
                [
                    "此內容出現可疑跡象，建議先查證來源，不要直接依訊息操作。",
                    "若涉及登入、驗證或付款，請改走官方網站或官方 App。",
                ]
            )
            immediate_actions.extend(
                [
                    "先檢查寄件者、主網域與訊息內容是否一致。",
                    "必要時自行搜尋官方客服確認。",
                ]
            )
            do_not_actions.extend(
                [
                    "不要在未確認前提供個人資料。",
                    "不要直接點開訊息中的連結。",
                ]
            )

        else:
            recommendations.extend(
                [
                    "目前未發現明顯高風險特徵，但仍建議自行核對來源與主網域。",
                ]
            )
            immediate_actions.extend(
                [
                    "可再確認寄件者、網址與內容是否合理。",
                ]
            )
            do_not_actions.extend(
                [
                    "不要因對方催促就立即操作。",
                ]
            )

        # Flag-based recommendations
        if "credential_request" in flags:
            recommendations.append(
                "任何要求你提供密碼、OTP 或驗證碼的訊息都應特別小心。"
            )
            do_not_actions.append("不要提供密碼、OTP、驗證碼或登入憑證。")

        if "financial_request" in flags:
            recommendations.append(
                "若涉及付款、匯款或信用卡資料，請務必透過官方管道再次核實。"
            )
            do_not_actions.append("不要直接匯款，也不要提供信用卡或銀行帳戶資訊。")

        if "official_impersonation" in flags:
            recommendations.append(
                "疑似冒充官方單位時，請自行搜尋官方客服，不要直接使用訊息提供的聯絡方式。"
            )

        if "link_pressure" in flags or urls:
            recommendations.append(
                "如需查證，請手動輸入官方網址，不要直接點擊訊息中的連結。"
            )
            do_not_actions.append("不要因為對方催促就立即開啟連結。")

        if "url_shortener" in flags or "shortener" in flags:
            recommendations.append(
                "短網址可能隱藏真實目的地，應先展開或改從官方來源進入。"
            )

        if (
            "url_lookalike_domain" in flags
            or "lookalike_domain" in flags
            or "url_brand_impersonation" in flags
            or "brand_impersonation" in flags
        ):
            recommendations.append("請仔細檢查主網域拼字，避免誤入假冒官方網站。")

        if "attachment_lure" in flags:
            recommendations.append("若訊息要求下載附件，請先確認檔案來源與必要性。")
            do_not_actions.append("不要隨意開啟不明 PDF、ZIP、DOCX 或發票附件。")

        if "delivery_scam" in flags:
            recommendations.append(
                "快遞或包裹通知請直接到官方物流網站查詢單號，不要點訊息中的連結。"
            )
            immediate_actions.append("自行前往官方物流網站輸入包裹單號查詢狀態。")
            do_not_actions.append("不要透過訊息連結支付任何補運費或關稅。")

        if "job_scam" in flags:
            recommendations.append(
                "高薪兼職或在家工作機會多為詐騙誘餌，請透過正規求職平台查證。"
            )
            immediate_actions.append("搜尋該公司名稱加上「詐騙」確認是否有相關警示。")
            do_not_actions.append(
                "不要預先支付任何費用或提供銀行帳戶作為「收款帳戶」。"
            )

        if "phone_number_present" in flags:
            recommendations.append(
                "訊息中出現電話號碼，請勿主動撥打，應自行上網查詢官方客服電話再聯繫。"
            )

        if "phone_with_pressure" in flags:
            immediate_actions.append(
                "不要撥打訊息提供的電話，詐騙集團常以此直接與受害者接觸。"
            )
            do_not_actions.append("不要因對方催促或自稱官方就撥打訊息中的電話號碼。")

        if risk_level in {"high", "critical"} and (
            "credential_request" in flags or "financial_request" in flags
        ):
            immediate_actions.append(
                "若你已輸入帳號、密碼、驗證碼或付款資料，請立即修改密碼或聯絡銀行。"
            )

        # Additional advice if user already received URL
        if urls:
            immediate_actions.append("可先把網址複製下來檢查主網域，而不是直接打開。")

        result = RecommendationResult(
            recommendations=self.deduplicate_preserve_order(recommendations),
            immediate_actions=self.deduplicate_preserve_order(immediate_actions),
            do_not_actions=self.deduplicate_preserve_order(do_not_actions),
        )
        return result.to_dict()

    def deduplicate_preserve_order(self, items: List[str]) -> List[str]:
        seen = set()
        result = []
        for item in items:
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result


if __name__ == "__main__":
    import json

    preprocessed = {"urls": ["https://paypaI-security-login.com"]}

    rule_result = {
        "flags": [
            "credential_request",
            "link_pressure",
            "url_lookalike_domain",
            "official_impersonation",
        ]
    }

    score_result = {"risk_level": "high"}

    recommender = Recommender()
    result = recommender.recommend(preprocessed, rule_result, score_result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
