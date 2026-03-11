"""
Streamlit-дашборд: статистика и результаты пайплайна мониторинга угроз.
Позволяет просматривать отчёт, график, блокировки и лог, а также запускать анализ с пошаговой анимацией.
"""

from __future__ import annotations

import time
from pathlib import Path

import pandas as pd
import streamlit as st

# Импорт констант и функций пайплайна (без выполнения main)
from dotenv import load_dotenv

load_dotenv()

# Импорт после load_dotenv, чтобы os.getenv в main работал
import main as pipeline

# Пути из main
REPORT_JSON = pipeline.REPORT_JSON
REPORT_CSV = pipeline.REPORT_CSV
PLOT_FILE = pipeline.PLOT_FILE
BLOCKED_IPS_FILE = pipeline.BLOCKED_IPS_FILE
APP_LOG_FILE = pipeline.APP_LOG_FILE
OUTPUT_DIR = pipeline.OUTPUT_DIR


@st.cache_data(ttl=60)
def load_report_data() -> tuple[dict | None, pd.DataFrame | None]:
    """Загружает метаданные и записи из threat_report.json. Возвращает (metadata, df) или (None, None)."""
    if not REPORT_JSON.exists():
        return None, None
    try:
        import json
        with REPORT_JSON.open("r", encoding="utf-8") as f:
            data = json.load(f)
        meta = data.get("metadata", {})
        records = data.get("records", [])
        if not records:
            return meta, None
        df = pd.DataFrame(records)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return meta, df
    except Exception:
        return None, None


def load_blocked_ips() -> str:
    """Читает список заблокированных IP."""
    if not BLOCKED_IPS_FILE.exists():
        return ""
    return BLOCKED_IPS_FILE.read_text(encoding="utf-8")


def load_log_tail(lines: int = 80) -> str:
    """Читает последние N строк лога."""
    if not APP_LOG_FILE.exists():
        return ""
    try:
        text = APP_LOG_FILE.read_text(encoding="utf-8")
        all_lines = text.splitlines()
        return "\n".join(all_lines[-lines:])
    except Exception:
        return ""


def inject_custom_css():
    """Тёмно-синяя тема в стиле Platform V SOWA + скрытие подсказки keyboard у сайдбара."""
    st.markdown(
        """
        <link href="https://fonts.googleapis.com/css2?family=PT+Sans:wght@400;500;600;700&family=PT+Mono&display=swap" rel="stylesheet">
        <style>
            :root {
                --electric-blue: #38bdf8;
                --electric-blue-dim: #0ea5e9;
                --bg-dark: #0f172a;
                --bg-card: #1e293b;
                --bg-card-hover: #334155;
                --text-primary: #f1f5f9;
                --text-secondary: #94a3b8;
                --border: #334155;
                --card-radius: 8px;
                --transition: 0.2s ease;
            }
            .stApp {
                background: var(--bg-dark);
                font-family: 'PT Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            }
            .stApp p, .stApp span, .stApp label, .stApp div {
                color: var(--text-primary);
            }
            /* Убираем подсказку "keyboard" при наведении на кнопку сворачивания сайдбара */
            [data-testid="stSidebar"] [title*="keyboard"],
            [data-testid="stSidebar"] button[title*="keyboard"] {
                font-size: 0 !important;
                line-height: 0 !important;
            }
            /* Хедер в стиле Platform V: тёмно-синий с акцентом */
            .hero-header {
                font-family: 'PT Sans', sans-serif;
                background: linear-gradient(135deg, #1e3a5f 0%, #1e293b 100%);
                border: 1px solid var(--border);
                padding: 1.25rem 1.5rem;
                border-radius: var(--card-radius);
                margin-bottom: 1.5rem;
                color: #ffffff;
                box-shadow: 0 0 0 1px rgba(56, 189, 248, 0.15);
            }
            .hero-header h1 {
                font-weight: 700;
                font-size: 1.5rem;
                margin: 0;
                color: var(--text-primary);
            }
            .hero-header p {
                margin: 0.5rem 0 0 0;
                font-size: 0.9375rem;
                color: var(--text-secondary);
            }
            .metric-card {
                font-family: 'PT Sans', sans-serif;
                background: var(--bg-card);
                border-radius: var(--card-radius);
                padding: 1rem 1.25rem;
                border: 1px solid var(--border);
                transition: border-color var(--transition), box-shadow var(--transition);
                animation: cardFadeIn 0.4s ease-out backwards;
            }
            .metric-card:hover {
                border-color: var(--electric-blue);
                box-shadow: 0 0 20px rgba(56, 189, 248, 0.12);
            }
            .metric-card .label {
                font-size: 0.8125rem;
                color: var(--text-secondary);
                font-weight: 500;
            }
            .metric-card .value {
                font-size: 1.375rem;
                font-weight: 700;
                color: var(--text-primary);
                margin-top: 0.35rem;
            }
            @keyframes cardFadeIn {
                from { opacity: 0; transform: translateY(6px); }
                to { opacity: 1; transform: translateY(0); }
            }
            .metric-card:nth-child(1) { animation-delay: 0.03s; }
            .metric-card:nth-child(2) { animation-delay: 0.06s; }
            .metric-card:nth-child(3) { animation-delay: 0.09s; }
            .metric-card:nth-child(4) { animation-delay: 0.12s; }
            .section-fade { animation: sectionFade 0.4s ease-out; }
            @keyframes sectionFade {
                from { opacity: 0; }
                to { opacity: 1; }
            }
            /* Сайдбар: тёмно-синий, как на Platform V */
            [data-testid="stSidebar"] {
                background: #0c1222;
                border-right: 1px solid var(--border);
            }
            [data-testid="stSidebar"] .stRadio label,
            [data-testid="stSidebar"] p, [data-testid="stSidebar"] span {
                color: var(--text-primary) !important;
                font-family: 'PT Sans', sans-serif;
            }
            [data-testid="stSidebar"] .stRadio label { font-size: 0.9375rem; }
            /* Скрываем текст/подсказку keyboard в сайдбаре (иконка стрелки остаётся) */
            [data-testid="stSidebar"] > div:first-child {
                overflow: hidden;
            }
            [data-testid="stSidebar"] [class*="collapsible"] button[title] {
                position: relative;
            }
            /* Кнопка — электрический синий акцент */
            .stButton > button[kind="primary"] {
                font-family: 'PT Sans', sans-serif;
                font-weight: 600;
                font-size: 0.9375rem;
                border-radius: 8px;
                padding: 0.5rem 1.25rem;
                background: var(--electric-blue);
                color: #0f172a;
                border: none;
                transition: background var(--transition), box-shadow var(--transition);
            }
            .stButton > button[kind="primary"]:hover {
                background: var(--electric-blue-dim);
                box-shadow: 0 0 16px rgba(56, 189, 248, 0.4);
            }
            .stTabs [data-baseweb="tab"] {
                font-family: 'PT Sans', sans-serif;
                font-weight: 500;
                font-size: 0.9375rem;
            }
            .chart-container {
                background: var(--bg-card);
                border-radius: var(--card-radius);
                padding: 1.25rem;
                border: 1px solid var(--border);
                animation: cardFadeIn 0.4s ease-out;
            }
            [data-testid="stStatus"] {
                border-radius: 8px;
                border: 1px solid var(--border);
            }
            .stMarkdown h2, .stMarkdown h3 {
                color: var(--text-primary) !important;
                font-family: 'PT Sans', sans-serif;
                font-weight: 600;
            }
            [data-testid="stDataFrame"], .stCodeBlock, .stTextArea textarea {
                font-family: 'PT Mono', 'Consolas', monospace !important;
                font-size: 0.875rem;
            }
        </style>
        <script>
            (function() {
                function removeKeyboardTitle() {
                    document.querySelectorAll('[title*="keyboard"], [title*="Keyboard"]').forEach(function(el) {
                        el.removeAttribute('title');
                    });
                }
                removeKeyboardTitle();
                if (document.readyState === 'loading') {
                    document.addEventListener('DOMContentLoaded', removeKeyboardTitle);
                }
                var observer = new MutationObserver(function() { removeKeyboardTitle(); });
                observer.observe(document.body, { childList: true, subtree: true });
            })();
        </script>
        """,
        unsafe_allow_html=True,
    )


def render_hero():
    """Главный баннер с градиентом и анимацией."""
    st.markdown(
        """
        <div class="hero-header">
            <h1>🛡️ Мониторинг угроз</h1>
            <p>Сбор данных из логов и VirusTotal → анализ → реагирование → отчёт и визуализация</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_metric_card(label: str, value: str, delay_class: str = ""):
    """Отрисовка одной метрики в стилизованной карточке."""
    st.markdown(
        f'<div class="metric-card {delay_class}"><div class="label">{label}</div><div class="value">{value}</div></div>',
        unsafe_allow_html=True,
    )


def render_view_results():
    """Вкладки: Сводка, Таблица, График, Блокировки, Лог."""
    meta, df = load_report_data()

    if meta is None and (df is None or df.empty):
        st.markdown(
            '<div class="section-fade">',
            unsafe_allow_html=True,
        )
        st.info("📊 Отчёт не найден. Запустите анализ с помощью кнопки **«Запустить анализ»** в боковой панели.")
        st.markdown("</div>", unsafe_allow_html=True)
        return

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📈 Сводка",
        "📋 Таблица отчёта",
        "📊 График",
        "🚫 Заблокированные IP",
        "📜 Лог",
    ])

    with tab1:
        st.markdown('<div class="section-fade">', unsafe_allow_html=True)
        st.subheader("Метаданные отчёта")
        if meta:
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                render_metric_card("Всего событий", str(meta.get("total_events", "—")))
            with col2:
                render_metric_card("Угроз обнаружено", str(meta.get("threat_count", "—")))
            with col3:
                render_metric_card("Заблокировано IP", str(meta.get("blocked_ips_count", "—")))
            with col4:
                gen_at = meta.get("generated_at") or "—"
                if isinstance(gen_at, str) and len(gen_at) > 19:
                    gen_at = gen_at[:19]
                render_metric_card("Дата генерации", str(gen_at))
            with st.expander("Полные метаданные (JSON)"):
                st.json(meta)
        else:
            st.write("Метаданные недоступны.")
        st.markdown("</div>", unsafe_allow_html=True)

    with tab2:
        st.markdown('<div class="section-fade">', unsafe_allow_html=True)
        if df is not None and not df.empty:
            only_threats = st.checkbox("Только строки с угрозами", value=False)
            if only_threats:
                df_filtered = df[df.get("is_threat", False) == True]  # noqa: E712
            else:
                df_filtered = df
            st.dataframe(df_filtered, use_container_width=True)
        else:
            st.write("Нет записей в отчёте.")
        st.markdown("</div>", unsafe_allow_html=True)

    with tab3:
        st.markdown('<div class="section-fade">', unsafe_allow_html=True)
        if PLOT_FILE.exists():
            st.markdown('<div class="chart-container">', unsafe_allow_html=True)
            st.image(str(PLOT_FILE), use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.warning("График не найден. Запустите анализ.")
        st.markdown("</div>", unsafe_allow_html=True)

    with tab4:
        st.markdown('<div class="section-fade">', unsafe_allow_html=True)
        blocked = load_blocked_ips()
        if blocked.strip():
            st.code(blocked, language="text")
        else:
            st.write("Список заблокированных IP пуст.")
        st.markdown("</div>", unsafe_allow_html=True)

    with tab5:
        st.markdown('<div class="section-fade">', unsafe_allow_html=True)
        log_tail = load_log_tail()
        if log_tail:
            st.text_area("Последние строки лога", value=log_tail, height=300)
        else:
            st.write("Лог пуст или отсутствует.")
        st.markdown("</div>", unsafe_allow_html=True)


def run_analysis_with_animation():
    """Запуск пайплайна с пошаговой анимацией (st.status на каждый этап)."""
    st.subheader("Запуск анализа")
    st.caption("Нажмите кнопку ниже, чтобы выполнить полный цикл: сбор логов → обогащение VirusTotal → детекция → реагирование → отчёт и график.")
    if st.button("▶ Запустить анализ", type="primary"):
        pipeline.setup_logging(APP_LOG_FILE)
        steps = pipeline.get_pipeline_steps()
        result = None
        progress_bar = st.progress(0.0)
        status_placeholder = st.empty()

        for i, (step_name, step_fn) in enumerate(steps):
            with status_placeholder.container():
                with st.status(f"Этап {i + 1}/6: {step_name}", state="running") as status:
                    st.spinner("Выполняется...")
                    try:
                        result = step_fn(result)
                        time.sleep(0.35)
                    except Exception as e:
                        st.error(str(e))
                        status.update(state="error", label=f"Этап {i + 1}: ошибка")
                        raise
                    status.update(state="complete", label=f"Этап {i + 1}/6: {step_name} — готово")
            progress_bar.progress((i + 1) / 6)

        progress_bar.progress(1.0)
        st.success("✅ Анализ завершён. Данные обновлены.")
        st.balloons()
        load_report_data.clear()
        status_placeholder.empty()
        progress_bar.empty()
        st.rerun()


def main():
    st.set_page_config(
        page_title="Мониторинг угроз",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    inject_custom_css()
    render_hero()

    mode = st.sidebar.radio(
        "Режим",
        ["Просмотр результатов", "Запустить анализ"],
        index=0,
    )

    if mode == "Запустить анализ":
        run_analysis_with_animation()
        st.divider()
        st.subheader("Результаты после запуска")
    render_view_results()


if __name__ == "__main__":
    main()
