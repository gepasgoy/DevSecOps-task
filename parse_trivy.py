#!/usr/bin/env python3
"""
Скрипт для парсинга и структурирования JSON-отчета Trivy (SCA).
Использование: python3 parse_trivy.py test_tryvi.json [--save-log]
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


def parse_vulnerabilities(results):
    """Парсит все уязвимости из результатов сканирования"""
    all_vulns = []
    
    for result in results:
        target = result.get("Target", "unknown")
        target_class = result.get("Class", "unknown")
        target_type = result.get("Type", "unknown")
        
        vulns = result.get("Vulnerabilities", [])
        
        for vuln in vulns:
            pkg_name = vuln.get("PkgName", "unknown")
            installed = vuln.get("InstalledVersion", "unknown")
            fixed = vuln.get("FixedVersion", "unknown")
            
            vuln_info = {
                "id": vuln.get("VulnerabilityID", "unknown"),
                "severity": vuln.get("Severity", "UNKNOWN"),
                "title": vuln.get("Title", ""),
                "description": vuln.get("Description", ""),
                "package": pkg_name,
                "installed_version": installed,
                "fixed_version": fixed,
                "target": target,
                "class": target_class,
                "type": target_type,
                "status": vuln.get("Status", "unknown"),
                "cvss": extract_cvss(vuln),
                "cwe": vuln.get("CweIDs", []),
                "published": vuln.get("PublishedDate", ""),
            }
            all_vulns.append(vuln_info)
    
    return all_vulns


def extract_cvss(vuln):
    """Извлекает CVSS оценки"""
    cvss = vuln.get("CVSS", {})
    result = {}
    
    for source, data in cvss.items():
        if isinstance(data, dict):
            score = data.get("V3Score", data.get("V40Score"))
            vector = data.get("V3Vector", data.get("V40Vector", ""))
            if score:
                result[source] = {"score": score, "vector": vector}
    
    return result


def group_findings(vulns):
    """Группирует уязвимости по разным критериям"""
    by_severity = defaultdict(list)
    by_package = defaultdict(list)
    by_target = defaultdict(list)
    
    for vuln in vulns:
        by_severity[vuln["severity"]].append(vuln)
        by_package[vuln["package"]].append(vuln)
        by_target[vuln["target"]].append(vuln)
    
    return {
        "by_severity": dict(by_severity),
        "by_package": dict(by_package),
        "by_target": dict(by_target),
    }


class LogWriter:
    """Записывает вывод в файл лога и дублирует в консоль"""
    
    def __init__(self, tool_name, save_log=False):
        self.save_log = save_log
        self.log_lines = []
        
        if save_log:
            # Создаем папку logs если её нет
            os.makedirs("logs", exist_ok=True)
            
            # Формируем имя файла: logs/2026-05-10_18-30-00_trivy.log
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
    log.write(f"\n{'=' * 80}")
    log.write(f"  {title}")
    log.write(f"{'=' * 80}")


def print_summary(log, report, vulns):
    """Выводит общую сводку"""
    metadata = report.get("Metadata", {})
    artifact = report.get("ArtifactName", "unknown")
    artifact_type = report.get("ArtifactType", "unknown")
    
    # Время сканирования из отчета
    created = report.get("CreatedAt", "")
    if created:
        created = created[:19].replace("T", " ")
    
    print_separator(log, "СВОДКА СКАНИРОВАНИЯ")
    log.write(f"🔧 Trivy версия: {report.get('Trivy', {}).get('Version', 'unknown')}")
    log.write(f"🕐 Время сканирования: {created}")
    log.write(f"📦 Артефакт: {artifact}")
    log.write(f"📋 Тип артефакта: {artifact_type}")
    
    if metadata.get("OS"):
        os_info = metadata["OS"]
        log.write(f"💻 ОС: {os_info.get('Family', '')} {os_info.get('Name', '')}")
    
    if metadata.get("Size"):
        size_mb = metadata["Size"] / (1024 * 1024)
        log.write(f"📏 Размер образа: {size_mb:.1f} MB")
    
    # Статистика по severity
    sev_count = defaultdict(int)
    for vuln in vulns:
        sev_count[vuln["severity"]] += 1
    
    total = len(vulns)
    log.write(f"\n🔍 Всего уязвимостей: {total}")
    
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    icons = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵",
        "UNKNOWN": "⚪"
    }
    
    for sev in severity_order:
        if sev in sev_count:
            icon = icons.get(sev, "⚪")
            bar = "█" * (sev_count[sev] // 2) if sev_count[sev] > 0 else ""
            log.write(f"   {icon} {sev:8s}: {sev_count[sev]:3d}  {bar}")
    
    # Статистика по типам целей
    target_count = defaultdict(int)
    for vuln in vulns:
        target_count[vuln["class"]] += 1
    
    log.write(f"\n📊 По типам пакетов:")
    for cls, count in target_count.items():
        log.write(f"   • {cls}: {count}")


def print_top_findings(log, vulns, n=10):
    """Выводит топ уязвимостей по критичности"""
    print_separator(log, "ТОП УЯЗВИМОСТЕЙ")
    
    severity_weight = {
        "CRITICAL": 0,
        "HIGH": 1000,
        "MEDIUM": 2000,
        "LOW": 3000,
        "UNKNOWN": 4000
    }
    
    sorted_vulns = sorted(vulns, key=lambda v: (
        severity_weight.get(v["severity"], 5000),
        -max([c["score"] for c in v["cvss"].values()]) if v["cvss"] else 0
    ))
    
    shown = 0
    for vuln in sorted_vulns[:n]:
        shown += 1
        sev = vuln["severity"]
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "⚪")
        
        # Максимальный CVSS
        max_cvss = ""
        if vuln["cvss"]:
            best = max(vuln["cvss"].items(), key=lambda x: x[1]["score"])
            max_cvss = f"CVSS {best[1]['score']} ({best[0]})"
        
        log.write(f"\n{shown:2d}. {icon} [{sev}] {vuln['id']} {max_cvss}")
        log.write(f"    📦 Пакет: {vuln['package']}")
        log.write(f"    📂 Версия: {vuln['installed_version']} → {vuln['fixed_version']}")
        log.write(f"    🎯 Цель: {vuln['target'][:70]}")
        
        if vuln["title"]:
            title = vuln["title"]
            if len(title) > 100:
                title = title[:97] + "..."
            log.write(f"    📝 {title}")
    
    if len(sorted_vulns) > n:
        log.write(f"\n    ... и еще {len(sorted_vulns) - n} уязвимостей")


def print_package_summary(log, vulns):
    """Выводит сводку по пакетам"""
    print_separator(log, "ПАКЕТЫ С НАИБОЛЬШИМ КОЛИЧЕСТВОМ УЯЗВИМОСТЕЙ")
    
    pkg_count = defaultdict(int)
    pkg_max_sev = defaultdict(lambda: "LOW")
    
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    
    for vuln in vulns:
        pkg_count[vuln["package"]] += 1
        if sev_rank.get(vuln["severity"], 0) > sev_rank.get(pkg_max_sev[vuln["package"]], 0):
            pkg_max_sev[vuln["package"]] = vuln["severity"]
    
    sorted_pkgs = sorted(pkg_count.items(), key=lambda x: x[1], reverse=True)[:10]
    
    for pkg, count in sorted_pkgs:
        sev = pkg_max_sev[pkg]
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "⚪")
        log.write(f"  {icon} {pkg}: {count} уязвимостей (макс: {sev})")


def print_cvss_distribution(log, vulns):
    """Выводит распределение CVSS оценок"""
    print_separator(log, "РАСПРЕДЕЛЕНИЕ CVSS")
    
    ranges = {
        "9.0-10.0 (Critical)": [],
        "7.0-8.9 (High)": [],
        "4.0-6.9 (Medium)": [],
        "0.1-3.9 (Low)": [],
        "Без оценки": []
    }
    
    for vuln in vulns:
        if vuln["cvss"]:
            best = max(vuln["cvss"].items(), key=lambda x: x[1]["score"])
            score = best[1]["score"]
            
            if score >= 9.0:
                ranges["9.0-10.0 (Critical)"].append(vuln)
            elif score >= 7.0:
                ranges["7.0-8.9 (High)"].append(vuln)
            elif score >= 4.0:
                ranges["4.0-6.9 (Medium)"].append(vuln)
            else:
                ranges["0.1-3.9 (Low)"].append(vuln)
        else:
            ranges["Без оценки"].append(vuln)
    
    for range_name, range_vulns in ranges.items():
        if range_vulns:
            log.write(f"  • {range_name}: {len(range_vulns)} шт.")


def print_target_breakdown(log, groups):
    """Выводит разбивку по целям"""
    print_separator(log, "РАЗБИВКА ПО ЦЕЛЯМ")
    
    for target, target_vulns in groups["by_target"].items():
        sev_count = defaultdict(int)
        for v in target_vulns:
            sev_count[v["severity"]] += 1
        
        log.write(f"\n  🎯 {target}")
        log.write(f"     Всего: {len(target_vulns)} уязвимостей")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev in sev_count:
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "")
                log.write(f"     {icon} {sev}: {sev_count[sev]}")


def print_recommendations(log, vulns, groups):
    """Выводит рекомендации"""
    print_separator(log, "РЕКОМЕНДАЦИИ")
    critical_count = len(groups["by_severity"].get("CRITICAL", []))
    high_count = len(groups["by_severity"].get("HIGH", []))
    
    if critical_count > 0:
        log.write(f"🔴 Обнаружено {critical_count} CRITICAL уязвимостей — требуется немедленное обновление!")
    if high_count > 0:
        log.write(f"🟠 Обнаружено {high_count} HIGH уязвимостей — запланируйте обновление в ближайшее время.")
    
    # Топ пакетов для обновления
    pkg_impact = defaultdict(lambda: {"count": 0, "max_sev": "LOW"})
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    
    for vuln in vulns:
        pkg = vuln["package"]
        pkg_impact[pkg]["count"] += 1
        if sev_rank.get(vuln["severity"], 0) > sev_rank.get(pkg_impact[pkg]["max_sev"], 0):
            pkg_impact[pkg]["max_sev"] = vuln["severity"]
    
    # Пакеты с критическими уязвимостями
    critical_pkgs = [(pkg, info) for pkg, info in pkg_impact.items() if info["max_sev"] == "CRITICAL"]
    if critical_pkgs:
        log.write("\n📦 Пакеты с CRITICAL уязвимостями (обновить в первую очередь):")
        for pkg, info in sorted(critical_pkgs, key=lambda x: x[1]["count"], reverse=True):
            log.write(f"   • {pkg} ({info['count']} уязвимостей)")


def main():
    if len(sys.argv) < 2:
        print("Использование: python3 parse_trivy.py <путь-к-json-отчету> [--save-log]")
        sys.exit(1)

    filepath = sys.argv[1]
    save_log = "--save-log" in sys.argv
    
    log = LogWriter("trivy", save_log)

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

    results = report.get("Results", [])
    if not results:
        log.write("✅ Уязвимостей не найдено. Образ чист!")
        log.save()
        return

    vulns = parse_vulnerabilities(results)
    
    if not vulns:
        log.write("✅ Уязвимостей не найдено. Образ чист!")
        log.save()
        return

    groups = group_findings(vulns)
    
    # Вывод
    print_summary(log, report, vulns)
    print_top_findings(log, vulns, n=10)
    print_package_summary(log, vulns)
    print_cvss_distribution(log, vulns)
    print_target_breakdown(log, groups)
    print_recommendations(log, vulns, groups)
    
    log.write(f"\n{'=' * 80}")
    log.write("✅ Анализ завершен")
    
    log.save()


if __name__ == "__main__":
    main()
