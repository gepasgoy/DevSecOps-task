#!/usr/bin/env python3
"""
Скрипт для парсинга и структурирования JSON-отчета Semgrep.
Использование: python3 parse_semgrep.py semgrep-report.json [--save-log]
"""

import json
import sys
import os
from collections import defaultdict
from datetime import datetime


def load_report(filepath):
    """Загружает JSON-отчет"""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_errors(errors):
    """Парсит ошибки парсинга/сканирования"""
    if not errors:
        return None

    parsed = defaultdict(list)
    for err in errors:
        filepath = err.get("path", "unknown")
        err_type = err.get("type", "unknown")

        if isinstance(err_type, list):
            err_type = err_type[0]

        parsed[err_type].append({
            "file": filepath,
            "line": err.get("spans", [{}])[0].get("start", {}).get("line", "N/A") if err.get("spans") else "N/A",
            "message": err.get("message", "")
        })

    return dict(parsed)


def parse_results(results):
    """Парсит найденные уязвимости"""
    if not results:
        return None

    by_severity = defaultdict(list)
    by_file = defaultdict(list)

    for finding in results:
        check_id = finding.get("check_id", "unknown")
        severity = finding.get("extra", {}).get("severity", "UNKNOWN")
        message = finding.get("extra", {}).get("message", "").split(".")[0]

        filepath = finding.get("path", "unknown")
        line = finding.get("start", {}).get("line", "N/A")

        finding_info = {
            "rule": check_id,
            "file": filepath,
            "line": line,
            "message": message,
            "severity": severity,
        }

        by_severity[severity].append(finding_info)
        by_file[filepath].append(finding_info)

    return {
        "by_severity": dict(by_severity),
        "by_file": dict(by_file),
    }


class LogWriter:
    """Записывает вывод в файл лога и дублирует в консоль"""
    
    def __init__(self, tool_name, save_log=False):
        self.save_log = save_log
        self.log_lines = []
        
        if save_log:
            # Создаем папку logs если её нет
            os.makedirs("logs", exist_ok=True)
            
            # Формируем имя файла: logs/2026-05-10_18-30-00_semgrep.log
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            self.log_path = f"logs/{timestamp}_{tool_name}.log"
    
    def write(self, text=""):
        """Пишет текст в консоль и сохраняет для лога"""
        print(text)
        if self.save_log:
            self.log_lines.append(text)
    
    def save(self):
        """Сохраняет накопленный вывод в файл"""
        if self.save_log and self.log_lines:
            with open(self.log_path, "w", encoding="utf-8") as f:
                f.write("\n".join(self.log_lines))
            print(f"\n📄 Лог сохранен: {self.log_path}")


def print_separator(log, title):
    """Выводит разделитель с заголовком"""
    log.write(f"\n{'=' * 70}")
    log.write(f"  {title}")
    log.write(f"{'=' * 70}")


def print_errors(log, errors):
    """Выводит ошибки парсинга"""
    if not errors:
        log.write("✅ Ошибок парсинга не обнаружено")
        return

    log.write(f"⚠️  Найдено ошибок: {sum(len(v) for v in errors.values())}")
    for err_type, err_list in errors.items():
        log.write(f"\n  📄 Тип: {err_type}")
        for err in err_list:
            log.write(f"     • {err['file']} (строка {err['line']}): {err['message'][:150]}")
            if len(err['message']) > 150:
                log.write(f"       ...")


def print_results(log, results):
    """Выводит найденные уязвимости"""
    if not results:
        log.write("\n✅ Уязвимостей не найдено")
        return

    # По severity
    print_separator(log, "УЯЗВИМОСТИ ПО КРИТИЧНОСТИ")
    severity_order = ["ERROR", "WARNING", "INFO"]
    for sev in severity_order:
        findings = results["by_severity"].get(sev, [])
        if findings:
            icon = {"ERROR": "🔴", "WARNING": "🟡", "INFO": "🔵"}.get(sev, "⚪")
            log.write(f"\n{icon} {sev}: {len(findings)} шт.")
            for f in findings:
                log.write(f"   • {f['file']}:{f['line']} — {f['rule'].split('.')[-1]}")
                log.write(f"     {f['message']}")

    # По файлам
    print_separator(log, "ФАЙЛЫ С УЯЗВИМОСТЯМИ")
    for filepath, findings in results["by_file"].items():
        log.write(f"\n📁 {filepath}: {len(findings)} шт.")
        for f in findings:
            log.write(f"   • Строка {f['line']}: [{f['severity']}] {f['message']}")


def print_summary(log, report):
    """Выводит общую сводку"""
    print_separator(log, "СВОДКА СКАНИРОВАНИЯ")
    
    # Пробуем взять время из отчета, иначе — неизвестно
    scan_time = report.get("scan_metadata", {}).get("started_at") or report.get("started_at")
    if scan_time:
        scan_time = scan_time[:19].replace("T", " ")
        log.write(f"🕐 Время сканирования: {scan_time}")
    else:
        log.write(f"🕐 Время сканирования: неизвестно (в отчете нет метаданных)")
    
    log.write(f"📊 Версия Semgrep: {report.get('version', 'unknown')}")
    log.write(f"📂 Просканировано файлов: {len(report.get('paths', {}).get('scanned', []))}")

    results = report.get("results", [])
    if results:
        sev_count = defaultdict(int)
        for r in results:
            sev_count[r.get("extra", {}).get("severity", "UNKNOWN")] += 1

        log.write(f"\n🔍 Найдено уязвимостей: {len(results)}")
        for sev in ["ERROR", "WARNING", "INFO"]:
            if sev in sev_count:
                log.write(f"   {sev}: {sev_count[sev]} шт.")

    # Топ правил
    if results:
        rule_count = defaultdict(int)
        for r in results:
            rule_count[r["check_id"]] += 1
        log.write(f"\n📏 Уникальных правил: {len(rule_count)}")
        log.write("   Топ срабатываний:")
        for rule, count in sorted(rule_count.items(), key=lambda x: x[1], reverse=True)[:5]:
            log.write(f"   • {rule}: {count} раз(а)")

    errors = report.get("errors", [])
    if errors:
        log.write(f"\n⚠️  Ошибок парсинга: {len(errors)}")


def main():
    if len(sys.argv) < 2:
        print("Использование: python3 parse_semgrep.py <путь-к-json-отчету> [--save-log]")
        sys.exit(1)

    filepath = sys.argv[1]
    save_log = "--save-log" in sys.argv
    
    log = LogWriter("semgrep", save_log)

    try:
        report = load_report(filepath)
    except FileNotFoundError:
        log.write(f"❌ Файл не найден: {filepath}")
        log.save()
        sys.exit(1)
    except json.JSONDecodeError as e:
        log.write(f"❌ Ошибка парсинга JSON: {e}")
        log.save()
        sys.exit(1)

    print_summary(log, report)

    errors = parse_errors(report.get("errors", []))
    if errors:
        print_separator(log, "ОШИБКИ ПАРСИНГА")
        print_errors(log, errors)

    results = parse_results(report.get("results", []))
    if results:
        print_results(log, results)

    log.write(f"\n{'=' * 70}")
    log.write("✅ Анализ завершен")
    
    log.save()


if __name__ == "__main__":
    main()
