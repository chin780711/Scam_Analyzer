"""
components.py

Responsibilities:
- Shared Streamlit UI rendering helpers
"""

from __future__ import annotations

import json
import streamlit as st


URL_FLAG_LABELS = {
    "non_https": "未使用 HTTPS",
    "ip_host": "直接使用 IP 位址",
    "shortener": "短網址",
    "long_url": "網址過長",
    "many_subdomains": "過多子網域",
    "punycode": "Punycode 偽裝風險",
    "suspicious_keywords": "含高風險關鍵字",
    "brand_impersonation": "疑似假冒品牌",
    "lookalike_domain": "相似網域偽裝",
}


def url_flag_label_zh(flag: str) -> str:
    return URL_FLAG_LABELS.get(flag, flag)


def risk_color(level: str) -> str:
    mapping = {
        "low": "🟢",
        "medium": "🟠",
        "high": "🔴",
        "critical": "🚨",
    }
    return mapping.get(level, "⚪")


def risk_label_zh(level: str) -> str:
    mapping = {
        "low": "低風險",
        "medium": "中風險",
        "high": "高風險",
        "critical": "極高風險",
    }
    return mapping.get(level, "未知")


def render_top_metrics(
    score_result: dict, rule_result: dict, preprocessed: dict
) -> None:
    risk_score = score_result.get("risk_score", 0)
    risk_level = score_result.get("risk_level", "low")
    risk_icon = risk_color(risk_level)
    risk_label = risk_label_zh(risk_level)
    score_breakdown = score_result.get("score_breakdown", {})
    high_impact_count = score_breakdown.get("high_impact_flag_count", 0)

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("風險等級", f"{risk_icon} {risk_label}")

    with col2:
        st.metric("可疑旗標數量", len(rule_result.get("flags", [])))

    with col3:
        st.metric("網址數量", len(preprocessed.get("urls", [])))

    with col4:
        st.metric("高風險信號", high_impact_count)


def render_summary_box(explanation_result: dict, score_result: dict) -> None:
    summary = explanation_result.get("summary", "")
    risk_level = score_result.get("risk_level", "low")

    if risk_level in {"critical", "high"}:
        st.error(summary)
    elif risk_level == "medium":
        st.warning(summary)
    else:
        st.success(summary)


def render_explanation_tab(explanation_result: dict) -> None:

    top_reasons = explanation_result.get("top_reasons", [])
    explanation_points = explanation_result.get("explanation_points", [])

    st.markdown("### 你要注意的 3 個重點")
    if top_reasons:
        for item in top_reasons:
            st.markdown(f"- {item}")
    else:
        st.write("目前沒有明確重點。")

    detail_points = explanation_points[len(top_reasons) :]

    st.markdown("### 詳細說明")
    if detail_points:
        for point in detail_points:
            st.markdown(f"- {point}")
    else:
        st.write("目前沒有更多補充說明。")


def render_recommendation_tab(recommendation_result: dict) -> None:
    st.markdown("### 建議做法")
    for item in recommendation_result.get("recommendations", []):
        st.markdown(f"- {item}")

    st.markdown("### 立即行動")
    for item in recommendation_result.get("immediate_actions", []):
        st.markdown(f"- {item}")

    st.markdown("### 不要做的事")
    for item in recommendation_result.get("do_not_actions", []):
        st.markdown(f"- {item}")


def url_risk_label(score: int) -> str:
    if score >= 70:
        return "高風險"
    if score >= 40:
        return "中風險"
    return "低風險"


def render_url_analysis_tab(rule_result: dict) -> None:
    url_analysis = rule_result.get("url_analysis", [])

    if not url_analysis:
        st.info("此輸入未包含網址。")
        return

    for idx, url_result in enumerate(url_analysis, start=1):
        st.markdown(f"### 網址 {idx}")
        st.code(url_result.get("url", ""), language=None)

        c1, c2 = st.columns(2)
        with c1:
            st.write(f"**主網域：** {url_result.get('registered_domain', '-')}")
        score = url_result.get("risk_score", 0)
        label = url_risk_label(score)

        with c2:
            st.write(f"**URL 風險：** {label}（{score}/100）")

        reasons = url_result.get("reasons", [])
        flags = url_result.get("flags", [])

        st.markdown("**這個網址可疑的地方**")
        if reasons:
            for reason in reasons[:3]:
                st.markdown(f"- {reason}")
        else:
            st.write("目前未發現明確可疑原因。")

        st.markdown("**偵測到的特徵**")
        if flags:
            for f in flags:
                st.markdown(f"- {url_flag_label_zh(f)}")
        else:
            st.write("無")

        st.markdown("---")


def render_technical_tab(
    preprocessed: dict, rule_result: dict, score_result: dict
) -> None:
    st.markdown("### 前處理結果")
    st.write(f"**輸入類型：** {preprocessed.get('input_type', '-')}")
    st.write(f"**語言提示：** {preprocessed.get('language_hint', '-')}")
    st.write(f"**萃取網址：** {preprocessed.get('urls', [])}")
    st.write(f"**清理後文字：** {preprocessed.get('cleaned_text', '')}")

    st.markdown("### 規則引擎結果")
    st.write(f"**Flags：** {rule_result.get('flags', [])}")
    st.json(rule_result.get("matched_rules", {}))

    st.markdown("### 分數細節")
    st.json(score_result.get("score_breakdown", {}))


def render_json_tab(result: dict) -> None:
    json_text = json.dumps(result, ensure_ascii=False, indent=2)
    st.code(json_text, language="json")

    st.download_button(
        label="下載 JSON 結果",
        data=json_text,
        file_name="scam_analysis_result.json",
        mime="application/json",
    )
