from __future__ import annotations

from datetime import datetime

import streamlit as st

# -----------------------------
# Page config
# -----------------------------
st.set_page_config(
    page_title="AI Scam Analyzer",
    page_icon="🛡️",
    layout="wide",
)

from core.preprocessor import Preprocessor
from core.rule_engine import RuleEngine
from core.scorer import Scorer
from core.explainer import Explainer
from core.recommender import Recommender
from db.history_store import save_analysis, get_recent_history, save_feedback
from db.init_db import init_db
from ui.components import (
    risk_color,
    risk_label_zh,
    render_top_metrics,
    render_summary_box,
    render_explanation_tab,
    render_recommendation_tab,
    render_url_analysis_tab,
    render_technical_tab,
    render_json_tab,
)

init_db()

from pathlib import Path


def load_css(file_path: str) -> None:
    css_path = Path(file_path)
    with css_path.open("r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


load_css("ui/styles.css")


# -----------------------------
# Core instances
# -----------------------------
preprocessor = Preprocessor()
rule_engine = RuleEngine()
scorer = Scorer()
explainer = Explainer()
recommender = Recommender()


# -----------------------------
# Helpers
# -----------------------------


def clear_input():
    st.session_state["user_input"] = ""
    st.session_state["analysis_result"] = None
    st.session_state["last_analysis_id"] = None
    st.session_state["feedback_submitted"] = None


def analyze_input(user_input: str) -> dict:
    """
    Full pipeline:
    1. preprocess
    2. rule analyze
    3. score
    4. explain
    5. recommend
    6. save to history
    """
    pre = preprocessor.process(user_input)
    rule_result = rule_engine.analyze(pre)
    score_result = scorer.score(rule_result)
    explanation_result = explainer.explain(pre, rule_result, score_result)
    recommendation_result = recommender.recommend(pre, rule_result, score_result)

    result = {
        "preprocessed": pre,
        "rule_result": rule_result,
        "score_result": score_result,
        "explanation_result": explanation_result,
        "recommendation_result": recommendation_result,
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    try:
        record_id = save_analysis(result)
        st.session_state["last_analysis_id"] = record_id
    except Exception as e:
        st.warning(f"⚠️ 歷史記錄儲存失敗：{e}")
        st.session_state["last_analysis_id"] = None

    return result


def render_risk_badge(label: str) -> None:
    color_map = {
        "低風險": "#16a34a",
        "中風險": "#f59e0b",
        "高風險": "#ef4444",
        "極高風險": "#b91c1c",
    }

    color = color_map.get(label, "#6b7280")

    st.markdown(
        f"""
        <div style="margin: 8px 0 18px 0;">
            <span style="font-size: 16px; font-weight: 700; color: white; margin-right: 10px;">
                風險等級
            </span>
            <span style="
                display: inline-block;
                padding: 6px 14px;
                border-radius: 999px;
                background-color: {color};
                color: white;
                font-size: 14px;
                font-weight: 700;
                line-height: 1.2;
            ">
                {label}
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_risk_summary(label: str) -> None:
    summary_map = {
        "低風險": "目前未發現明顯風險。",
        "中風險": "發現部分可疑特徵，建議提高警覺。",
        "高風險": "偵測到多項可疑特徵，請勿直接點擊、回覆或提供資料。",
        "極高風險": "高度疑似詐騙或惡意內容，請立即停止互動。",
    }

    st.markdown(f"**判定結果：** {summary_map.get(label, '已完成風險分析。')}")


# -----------------------------
# Sidebar - 歷史紀錄
# -----------------------------
RISK_ICON = {"low": "🟢", "medium": "🟠", "high": "🔴", "critical": "🚨"}
RISK_LABEL = {
    "low": "低風險",
    "medium": "中風險",
    "high": "高風險",
    "critical": "極高風險",
}

with st.sidebar:
    st.title("🛡️ Scam Analyzer")
    st.markdown("---")
    st.markdown("### 📋 最近分析紀錄")

    try:
        history = get_recent_history(limit=10)
    except Exception:
        history = []

    if not history:
        st.caption("尚無分析紀錄。")
    else:
        for record in history:
            level = record.get("risk_level", "low")
            icon = risk_color(level)
            label = risk_label_zh(level)
            raw = record.get("raw_input", "")
            preview = raw[:40] + "…" if len(raw) > 40 else raw
            analyzed_at = record.get("analyzed_at", "")[:16]

            with st.expander(f"{icon} {preview}", expanded=False):
                st.caption(f"🕐 {analyzed_at}")
                st.caption(
                    f"風險等級：**{label}**　分數：**{record.get('risk_score', 0)}/100**"
                )
                summary = record.get("summary", "")
                if summary:
                    st.markdown(f"> {summary}")

# -----------------------------
# Main UI
# -----------------------------
st.title("Scam Analyzer")
st.write("貼上可疑訊息、Email 內容或網址，系統會分析風險並解釋原因。")

SAMPLE_INPUTS = {
    "🎣 釣魚簡訊": "您的帳戶異常，請立即點擊連結登入驗證，否則 24 小時內將被停用：\nhttps://paypaI-secure-login.com/verify",
    "📦 假冒快遞": "您有一件包裹因地址不符導致配送失敗，請點擊以下連結補填資料並支付補運費：\nhttps://dhl-delivery-tw.com/reschedule",
    "💼 求職詐騙": "【高薪兼職】在家工作，日結 3000 元，輕鬆賺！只需動動手指按讚留言，無經驗可，立即加 Line 了解詳情。",
}


def set_sample(text: str) -> None:
    st.session_state["user_input"] = text


if "user_input" not in st.session_state:
    st.session_state["user_input"] = ""

if "analysis_result" not in st.session_state:
    st.session_state["analysis_result"] = None

if "last_analysis_id" not in st.session_state:
    st.session_state["last_analysis_id"] = None

if "feedback_submitted" not in st.session_state:
    st.session_state["feedback_submitted"] = None


st.text_area("請輸入可疑內容", height=220, key="user_input")

btn_left, btn_mid1, btn_mid2, btn_right = st.columns([2, 1, 1, 2])

analyze_btn = False

with btn_mid1:
    analyze_btn = st.button("開始分析", use_container_width=True, type="primary")

with btn_mid2:
    st.button("清空內容", use_container_width=True, on_click=clear_input)

st.caption("試試範例：")
sample_cols = st.columns(len(SAMPLE_INPUTS))
for col, (label, text) in zip(sample_cols, SAMPLE_INPUTS.items()):
    with col:
        st.button(label, on_click=set_sample, args=(text,), use_container_width=True)

if analyze_btn:
    user_input = st.session_state.get("user_input", "")
    if not user_input.strip():
        st.warning("請先輸入要分析的內容。")
    else:
        st.session_state["analysis_result"] = analyze_input(user_input)

result = st.session_state.get("analysis_result")

if result:
    pre = result.get("preprocessed", {})
    rule_result = result.get("rule_result", {})
    score_result = result.get("score_result", {})
    explanation_result = result.get("explanation_result", {})
    recommendation_result = result.get("recommendation_result", {})

    # -----------------------------
    # Top summary
    # -----------------------------
    st.markdown("---")
    st.subheader("分析結果總覽")

    render_top_metrics(score_result, rule_result, pre)
    render_summary_box(explanation_result, score_result)

    phones = pre.get("phones", [])
    if phones:
        st.warning(
            f"⚠️ 偵測到電話號碼：{', '.join(phones)}　請勿主動撥打，應自行查詢官方客服電話。"
        )

    show_debug = st.checkbox(
        "顯示技術細節（開發者模式）",
        value=False,
        key="show_debug",
    )
    tab_list = ["重點說明", "建議動作", "網址分析"]

    if show_debug:
        tab_list += ["技術細節", "JSON 結果"]

    tabs = st.tabs(tab_list)

    with tabs[0]:
        st.markdown("### 分析摘要")
        label = explanation_result.get("user_friendly_label", "中風險")
        render_risk_badge(label)
        render_risk_summary(label)
        render_explanation_tab(explanation_result)

    with tabs[1]:
        render_recommendation_tab(recommendation_result)

    with tabs[2]:
        render_url_analysis_tab(rule_result)

    if show_debug:
        with tabs[3]:
            render_technical_tab(pre, rule_result, score_result)

        with tabs[4]:
            render_json_tab(result)

    st.caption(f"分析時間：{result.get('analyzed_at', '-')}")

    st.markdown("---")
    st.markdown("##### 這次分析結果準確嗎？")

    analysis_id = st.session_state.get("last_analysis_id")

    col_f1, col_f2, col_f3, _ = st.columns([1, 1, 1, 3])

    def submit_feedback(fb: str) -> None:
        if analysis_id:
            try:
                save_feedback(analysis_id, fb)
                st.session_state["feedback_submitted"] = fb
            except Exception:
                pass

    with col_f1:
        st.button(
            "✅ 判斷正確",
            use_container_width=True,
            on_click=submit_feedback,
            args=("correct",),
        )
    with col_f2:
        st.button(
            "⬆️ 風險偏低",
            use_container_width=True,
            on_click=submit_feedback,
            args=("wrong_too_low",),
        )
    with col_f3:
        st.button(
            "⬇️ 風險偏高",
            use_container_width=True,
            on_click=submit_feedback,
            args=("wrong_too_high",),
        )

    if st.session_state.get("feedback_submitted"):
        fb = st.session_state["feedback_submitted"]
        msg = {
            "correct": "感謝回饋！",
            "wrong_too_low": "感謝回饋，我們會持續改善偵測能力。",
            "wrong_too_high": "感謝回饋，我們會調整判斷標準。",
        }.get(fb, "感謝回饋！")
        st.success(msg)
        st.session_state.pop("feedback_submitted")


# -----------------------------
# Footer
# -----------------------------
st.markdown("---")
st.caption("Scam Analyzer MVP • Rule-based detection + URL analysis + explanation")
