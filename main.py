"""
Автоматизированный мониторинг и реагирование на угрозы.

Скрипт выполняет четыре этапа задания:
  1. Сбор данных — загрузка логов Suricata (CSV/JSON) и обогащение через VirusTotal API (или имитация).
  2. Анализ данных — выявление угроз по частоте запросов и по результатам VirusTotal (malicious > 0).
  3. Реагирование — вывод [ALERT] в лог и имитация блокировки (запись IP в blocked_ips.txt).
  4. Формирование отчёта и визуализация — сохранение отчёта в CSV и JSON, построение графика (PNG).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional, Set

import matplotlib.pyplot as plt
from matplotlib.patches import Patch
import pandas as pd
import requests
import seaborn as sns
from dotenv import load_dotenv


# -----------------------------
# Конфигурация проекта
# -----------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOGS_FILE = DATA_DIR / "suricata_logs.csv"
MOCK_DIR = DATA_DIR / "mock_api"
OUTPUT_DIR = BASE_DIR / "output"

BLOCKED_IPS_FILE = OUTPUT_DIR / "blocked_ips.txt"
REPORT_CSV = OUTPUT_DIR / "threat_report.csv"
REPORT_JSON = OUTPUT_DIR / "threat_report.json"
PLOT_FILE = OUTPUT_DIR / "threat_plot.png"
APP_LOG_FILE = OUTPUT_DIR / "app.log"

VT_ENDPOINT_TEMPLATE = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
FREQUENCY_THRESHOLD_PER_MIN = 100


def setup_logging(log_file: Path) -> None:
    """Настраивает логирование в консоль и файл."""
    log_file.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.handlers.clear()

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    root_logger.addHandler(stream_handler)


def generate_synthetic_logs(path: Path, rows: int = 700) -> pd.DataFrame:
    """
    Генерирует синтетические сетевые события.
    Включает один «шумный» IP для срабатывания порога частоты.
    """
    logging.info("Файл логов не найден. Генерирую синтетические данные: %s", path)
    path.parent.mkdir(parents=True, exist_ok=True)

    base_time = pd.Timestamp.utcnow().floor("min")
    normal_src_ips = [
        "192.168.1.10",
        "10.0.0.20",
        "172.16.0.15",
        "203.0.113.77",
        "198.51.100.23",
    ]
    burst_ip = "185.220.101.42"
    dest_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8", "1.1.1.1"]
    event_types = ["http", "dns", "ssh", "tls", "icmp"]
    severities = ["low", "medium", "high"]

    records: list[dict[str, Any]] = []

    for i in range(rows - 200):
        records.append(
            {
                "timestamp": (base_time - pd.Timedelta(minutes=i % 12, seconds=i % 59)).isoformat(),
                "src_ip": normal_src_ips[i % len(normal_src_ips)],
                "dest_ip": dest_ips[i % len(dest_ips)],
                "event_type": event_types[i % len(event_types)],
                "severity": severities[i % len(severities)],
            }
        )

    for i in range(200):
        records.append(
            {
                "timestamp": (base_time - pd.Timedelta(seconds=i % 60)).isoformat(),
                "src_ip": burst_ip,
                "dest_ip": dest_ips[i % len(dest_ips)],
                "event_type": "port_scan",
                "severity": "high",
            }
        )

    df = pd.DataFrame(records)
    df.to_csv(path, index=False)
    logging.info("Синтетические логи сохранены: %s (%d строк)", path, len(df))
    return df


def load_logs(path: Path) -> pd.DataFrame:
    """
    Загружает логи из CSV/JSON.
    Если файл отсутствует — генерирует тестовые данные.
    """
    try:
        if not path.exists():
            return generate_synthetic_logs(path)

        logging.info("Загружаю логи: %s", path)
        if path.suffix.lower() == ".json":
            df = pd.read_json(path)
        else:
            df = pd.read_csv(path)

        required_columns = {"timestamp", "src_ip", "dest_ip", "event_type"}
        missing = required_columns - set(df.columns)
        if missing:
            raise ValueError(f"В логах отсутствуют обязательные поля: {sorted(missing)}")

        if "severity" not in df.columns:
            df["severity"] = "unknown"

        return df

    except Exception as exc:
        logging.exception("Ошибка при загрузке логов: %s", exc)
        raise


def _mock_file_for_ip(mock_dir: Path, ip: str) -> Path:
    safe_ip = ip.replace(":", "_")
    return mock_dir / f"{safe_ip}.json"


def _deterministic_malicious_score(ip: str) -> int:
    """Детерминированный score для имитации API (иногда > 0)."""
    digest = hashlib.sha256(ip.encode("utf-8")).hexdigest()
    value = int(digest[:2], 16)
    if value % 5 == 0:
        return 2
    if value % 7 == 0:
        return 1
    return 0


def _create_mock_vt_response(ip: str) -> Dict[str, Any]:
    malicious = _deterministic_malicious_score(ip)
    return {
        "data": {
            "id": ip,
            "type": "ip_address",
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 68,
                    "undetected": 14,
                    "suspicious": 0,
                    "malicious": malicious,
                    "timeout": 0,
                }
            },
        }
    }


def _load_or_generate_mock_response(mock_dir: Path, ip: str) -> Dict[str, Any]:
    mock_dir.mkdir(parents=True, exist_ok=True)
    mock_path = _mock_file_for_ip(mock_dir, ip)

    if mock_path.exists():
        with mock_path.open("r", encoding="utf-8") as f:
            return json.load(f)

    payload = _create_mock_vt_response(ip)
    with mock_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return payload


def _extract_malicious_count(vt_payload: Dict[str, Any]) -> int:
    """Извлекает количество malicious из ответа VirusTotal (v3 или старый формат)."""
    try:
        attrs = vt_payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        if "malicious" in stats:
            return int(stats["malicious"])
        if "positives" in vt_payload:
            return int(vt_payload["positives"])
    except Exception:
        pass
    return 0


def _query_virustotal_ip(ip: str, api_key: str, timeout: int = 12) -> Optional[Dict[str, Any]]:
    headers = {"x-apikey": api_key}
    url = VT_ENDPOINT_TEMPLATE.format(ip=ip)
    response = requests.get(url, headers=headers, timeout=timeout)

    if response.status_code >= 500 or response.status_code == 429:
        raise requests.RequestException(
            f"VirusTotal недоступен (HTTP {response.status_code})"
        )

    response.raise_for_status()
    return response.json()


def enrich_with_api(df: pd.DataFrame, api_key: Optional[str], mock_dir: Path) -> pd.DataFrame:
    """
    Обогащает DataFrame данными VirusTotal.
    Режимы: реальный (при наличии API-ключа) или имитация (локальные JSON).
    """
    unique_ips = sorted(df["src_ip"].dropna().astype(str).unique())
    logging.info("Обогащение IP через VirusTotal. Уникальных src_ip: %d", len(unique_ips))

    enrichment_records: list[dict[str, Any]] = []
    global_simulation_mode = not bool(api_key)

    if global_simulation_mode:
        logging.warning("VIRUSTOTAL_API_KEY не задан. Работаю в режиме имитации.")

    for ip in unique_ips:
        source = "mock"
        payload: Dict[str, Any]

        if not global_simulation_mode and api_key:
            try:
                payload = _query_virustotal_ip(ip=ip, api_key=api_key)
                source = "api"
            except Exception as exc:
                logging.warning(
                    "Ошибка API для IP %s: %s. Переключаюсь на локальную имитацию.",
                    ip,
                    exc,
                )
                payload = _load_or_generate_mock_response(mock_dir, ip)
                source = "mock_fallback"
        else:
            payload = _load_or_generate_mock_response(mock_dir, ip)

        malicious = _extract_malicious_count(payload)
        enrichment_records.append(
            {
                "src_ip": ip,
                "vt_malicious": malicious,
                "vt_source": source,
            }
        )

    enrichment_df = pd.DataFrame(enrichment_records)
    merged = df.merge(enrichment_df, on="src_ip", how="left")
    merged["vt_malicious"] = merged["vt_malicious"].fillna(0).astype(int)
    merged["vt_source"] = merged["vt_source"].fillna("unknown")
    return merged


def detect_threats(df: pd.DataFrame, freq_threshold: int = FREQUENCY_THRESHOLD_PER_MIN) -> pd.DataFrame:
    """
    Выявляет угрозы: высокая частота событий от src_ip в минуту и/или VT malicious > 0.
    """
    result = df.copy()
    result["timestamp"] = pd.to_datetime(result["timestamp"], errors="coerce", utc=True)
    result["minute_bucket"] = result["timestamp"].dt.floor("min")

    result["requests_per_min"] = (
        result.groupby(["src_ip", "minute_bucket"])["src_ip"].transform("count").fillna(0).astype(int)
    )

    result["is_scan_suspected"] = result["requests_per_min"] > freq_threshold
    result["is_api_threat"] = result["vt_malicious"] > 0
    result["is_threat"] = result["is_scan_suspected"] | result["is_api_threat"]

    reasons: list[str] = []
    for _, row in result.iterrows():
        row_reasons = []
        if bool(row["is_scan_suspected"]):
            row_reasons.append("high_frequency")
        if bool(row["is_api_threat"]):
            row_reasons.append("virustotal_malicious")
        reasons.append(",".join(row_reasons) if row_reasons else "none")

    result["threat_reason"] = reasons
    return result


def respond(df: pd.DataFrame, blocked_ips_file: Path) -> Set[str]:
    """Имитирует реагирование: [ALERT] в лог и запись IP в blocked_ips.txt."""
    blocked_ips_file.parent.mkdir(parents=True, exist_ok=True)

    blocked_ips: Set[str] = set()
    if blocked_ips_file.exists():
        existing = blocked_ips_file.read_text(encoding="utf-8").splitlines()
        blocked_ips.update(ip.strip() for ip in existing if ip.strip())

    threat_rows = df[df["is_threat"] == True]  # noqa: E712
    for row in threat_rows.itertuples(index=False):
        ip = str(row.src_ip)
        event_type = str(row.event_type)
        logging.warning("[ALERT] Обнаружена угроза: IP %s, источник: %s", ip, event_type)
        blocked_ips.add(ip)

    blocked_ips_file.write_text("\n".join(sorted(blocked_ips)), encoding="utf-8")
    logging.info("Список заблокированных IP сохранён: %s (всего %d)", blocked_ips_file, len(blocked_ips))
    return blocked_ips


def _report_columns() -> list[str]:
    """Список колонок для отчёта."""
    return [
        "timestamp",
        "src_ip",
        "dest_ip",
        "event_type",
        "severity",
        "requests_per_min",
        "vt_malicious",
        "vt_source",
        "is_scan_suspected",
        "is_api_threat",
        "is_threat",
        "threat_reason",
    ]


def save_report(df: pd.DataFrame, report_csv_path: Path, report_json_path: Path) -> None:
    """
    Сохраняет итоговый отчёт в CSV и JSON.
    В JSON добавляются метаданные (дата запуска, счётчики) через модуль json.
    """
    report_csv_path.parent.mkdir(parents=True, exist_ok=True)
    columns_order = _report_columns()

    for col in columns_order:
        if col not in df.columns:
            df[col] = None

    output_df = df[columns_order].copy()
    output_df.to_csv(report_csv_path, index=False)
    logging.info("Отчёт CSV сохранён: %s (строк: %d)", report_csv_path, len(output_df))

    # Сериализация в JSON с метаданными (явное использование модуля json)
    records = output_df.to_dict(orient="records")
    for r in records:
        if "timestamp" in r and hasattr(r["timestamp"], "isoformat"):
            r["timestamp"] = r["timestamp"].isoformat()

    meta = {
        "generated_at": pd.Timestamp.utcnow().isoformat(),
        "total_events": len(output_df),
        "threat_count": int(output_df["is_threat"].sum()),
        "blocked_ips_count": int(output_df.loc[output_df["is_threat"].astype(bool), "src_ip"].nunique()),
    }
    report_payload = {"metadata": meta, "records": records}
    with report_json_path.open("w", encoding="utf-8") as f:
        json.dump(report_payload, f, ensure_ascii=False, indent=2)
    logging.info("Отчёт JSON сохранён: %s", report_json_path)


def plot_results(df: pd.DataFrame, plot_file: Path) -> None:
    """Строит график Top-5 самых активных IP с раскраской по признаку угрозы в стиле Platform V."""
    plot_file.parent.mkdir(parents=True, exist_ok=True)

    activity = df.groupby("src_ip").size().sort_values(ascending=False).head(5)
    if activity.empty:
        logging.warning("Нет данных для построения графика.")
        return

    threat_by_ip = df.groupby("src_ip")["is_threat"].max()
    plot_df = activity.reset_index(name="count")
    plot_df["is_threat"] = plot_df["src_ip"].map(threat_by_ip).fillna(False)

    # Палитра в стиле Platform V: тёмный фон, голубой акцент, красный для угроз
    BG_DARK = "#1e293b"
    BG_FIGURE = "#0f172a"
    TEXT_PRIMARY = "#f1f5f9"
    TEXT_SECONDARY = "#94a3b8"
    GRID_COLOR = "#334155"
    ACCENT_BLUE = "#38bdf8"
    THREAT_RED = "#f87171"

    fig, ax = plt.subplots(figsize=(10, 6), facecolor=BG_FIGURE)
    ax.set_facecolor(BG_DARK)

    colors = [THREAT_RED if is_threat else ACCENT_BLUE for is_threat in plot_df["is_threat"]]
    bars = ax.bar(plot_df["src_ip"], plot_df["count"], color=colors, edgecolor=GRID_COLOR, linewidth=0.6)

    ax.set_title("Top-5 самых активных IP", fontsize=14, fontweight=600, color=TEXT_PRIMARY, pad=12)
    ax.set_xlabel("IP-адрес источника", fontsize=11, color=TEXT_SECONDARY)
    ax.set_ylabel("Количество событий", fontsize=11, color=TEXT_SECONDARY)
    ax.tick_params(axis="both", colors=TEXT_SECONDARY, labelsize=10)
    ax.set_xticklabels(plot_df["src_ip"], rotation=25, ha="right")

    for spine in ax.spines.values():
        spine.set_color(GRID_COLOR)
    ax.grid(True, axis="y", color=GRID_COLOR, alpha=0.4, linestyle="--")
    ax.set_axisbelow(True)

    for bar in bars:
        height = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            height + (ax.get_ylim()[1] - ax.get_ylim()[0]) * 0.02,
            f"{int(height)}",
            ha="center",
            va="bottom",
            fontsize=10,
            fontweight=500,
            color=TEXT_PRIMARY,
        )

    # Легенда: угроза / норма
    legend_elements = [
        Patch(facecolor=ACCENT_BLUE, edgecolor=GRID_COLOR, label="Норма"),
        Patch(facecolor=THREAT_RED, edgecolor=GRID_COLOR, label="Угроза"),
    ]
    ax.legend(handles=legend_elements, loc="upper right", frameon=True, facecolor=BG_DARK,
              edgecolor=GRID_COLOR, labelcolor=TEXT_PRIMARY, fontsize=9)

    plt.tight_layout()
    fig.savefig(
        plot_file,
        dpi=150,
        facecolor=BG_FIGURE,
        edgecolor="none",
        bbox_inches="tight",
    )
    plt.close(fig)
    logging.info("График сохранён: %s", plot_file)


def get_pipeline_steps() -> list[tuple[str, Any]]:
    """
    Возвращает список шагов пайплайна для пошагового запуска (например, из Streamlit).
    Каждый элемент — (название_этапа, callable). Callable принимает результат предыдущего шага
    (None для первого) и возвращает результат для следующего.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    def step1(_: Any) -> pd.DataFrame:
        return load_logs(LOGS_FILE)

    def step2(prev: pd.DataFrame) -> pd.DataFrame:
        return enrich_with_api(prev, api_key, MOCK_DIR)

    def step3(prev: pd.DataFrame) -> pd.DataFrame:
        return detect_threats(prev, freq_threshold=FREQUENCY_THRESHOLD_PER_MIN)

    def step4(prev: pd.DataFrame) -> pd.DataFrame:
        respond(prev, BLOCKED_IPS_FILE)
        return prev

    def step5(prev: pd.DataFrame) -> pd.DataFrame:
        save_report(prev, REPORT_CSV, REPORT_JSON)
        return prev

    def step6(prev: pd.DataFrame) -> pd.DataFrame:
        plot_results(prev, PLOT_FILE)
        return prev

    return [
        ("Сбор данных (логи Suricata)", step1),
        ("Обогащение (VirusTotal API)", step2),
        ("Детекция угроз", step3),
        ("Реагирование (блокировка)", step4),
        ("Сохранение отчёта", step5),
        ("Построение графика", step6),
    ]


def main() -> None:
    """Последовательное выполнение всех этапов: сбор данных, анализ, реагирование, отчёт и график."""
    load_dotenv()
    setup_logging(APP_LOG_FILE)

    logging.info("Запуск системы мониторинга угроз.")
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    try:
        logs_df = load_logs(LOGS_FILE)
        enriched_df = enrich_with_api(logs_df, api_key=api_key, mock_dir=MOCK_DIR)
        threats_df = detect_threats(enriched_df, freq_threshold=FREQUENCY_THRESHOLD_PER_MIN)
        respond(threats_df, BLOCKED_IPS_FILE)
        save_report(threats_df, REPORT_CSV, REPORT_JSON)
        plot_results(threats_df, PLOT_FILE)

        total = len(threats_df)
        threats = int(threats_df["is_threat"].sum())
        logging.info("Готово. Проанализировано событий: %d, угроз обнаружено: %d", total, threats)

    except Exception as exc:
        logging.exception("Критическая ошибка выполнения: %s", exc)
        raise


if __name__ == "__main__":
    main()
