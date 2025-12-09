#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Opsz v3.3 — Финальная версия с экспортом JSON + HTML
Пауза / Стоп / История / Экспорт / Связь с автором
21 ноября 2025
"""
import requests
import os
import sys
import ssl
import certifi
import asyncio
import aiohttp
import socket
import ipaddress
import json
from urllib.parse import urlparse, urljoin
from pathlib import Path
from datetime import datetime
from bs4 import BeautifulSoup

from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

class DeepSeekWorker(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, findings):
        super().__init__()
        self.findings = findings

    def run(self):
        try:
            api_key = os.environ.get(
                "DEEPSEEK_API_KEY",
                "sk-6092c31ec43f424592ff33ba171e92f6"
            )

            prompt = (
                "Ниже результаты веб-сканирования.\n\n"
                "Твоя задача:\n"
                "— объяснить всё ПРОСТЫМИ словами (для чайников)\n"
                "— разобрать КАЖДУЮ проблему\n"
                "— сказать, можно ли ЭТО эксплуатировать В ТЕОРИИ (БЕЗ кода)\n"
                "— дать рекомендации\n"
                "— дать общий вердикт\n"
                "— НИКАКОГО exploit-кода\n\n"
                "Результаты:\n"
                f"{json.dumps(self.findings, ensure_ascii=False, indent=2)}"
            )

            payload = {
                "model": "deepseek-chat",
                "messages": [
                    {"role": "system", "content": "Ты эксперт по веб-безопасности."},
                    {"role": "user", "content": prompt}
                ]
            }

            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }

            r = requests.post(
                "https://api.deepseek.com/v1/chat/completions",
                json=payload,
                headers=headers,
                timeout=90
            )
            r.raise_for_status()

            answer = r.json()["choices"][0]["message"]["content"]
            self.finished.emit(answer)

        except Exception as e:
            self.error.emit(str(e))


class ScanWorker(QThread):
    progress = pyqtSignal(str)
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, target):
        super().__init__()
        self.target = target.rstrip("/") + "/"
        self._stop = False
        self._pause = False
        self._pause_cond = QWaitCondition()
        self._mutex = QMutex()

    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self.scan())
            loop.close()
            if not self._stop:
                self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))

    def stop(self):
        self._stop = True

    def pause(self):
        with QMutexLocker(self._mutex):
            self._pause = True

    def resume(self):
        with QMutexLocker(self._mutex):
            self._pause = False
            self._pause_cond.wakeAll()

    async def scan(self):
        findings = []
        visited = set()
        queue = asyncio.Queue()
        await queue.put((self.target, 0))

        connector = aiohttp.TCPConnector(ssl=ssl.create_default_context(cafile=certifi.where()), limit=20)
        timeout = aiohttp.ClientTimeout(total=15)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async def worker():
                while not self._stop:
                    with QMutexLocker(self._mutex):
                        if self._pause:
                            self._pause_cond.wait(self._mutex)

                    try:
                        url, depth = await asyncio.wait_for(queue.get(), timeout=1)
                    except asyncio.TimeoutError:
                        continue

                    if url in visited or depth > 3:
                        queue.task_done()
                        continue
                    visited.add(url)

                    try:
                        async with session.get(url, timeout=10) as resp:
                            self.progress.emit(f"{resp.status} → {Path(urlparse(url).path).name or '/'}")
                            text = ""
                            if "text/html" in resp.headers.get("Content-Type", ""):
                                text = await resp.text()

                            findings.extend(self.analyze(url, dict(resp.headers), text))

                            if depth < 3 and text:
                                soup = BeautifulSoup(text, "lxml")
                                for a in soup.find_all("a", href=True):
                                    link = urljoin(url, a["href"])
                                    if urlparse(link).netloc == urlparse(self.target).netloc:
                                        await queue.put((link, depth + 1))
                    except:
                        pass
                    finally:
                        queue.task_done()

            tasks = [asyncio.create_task(worker()) for _ in range(20)]
            await queue.join()
            for t in tasks:
                t.cancel()

        return findings

    def analyze(self, url, headers, html):
        findings = []
        h = {k.lower(): v for k, v in headers.items()}
        html_l = html.lower()

        checks = [
            ("phpinfo", "PHPInfo обнаружен", "CRITICAL"),
            ("index of /", "Directory listing", "HIGH"),
            (".env", ".env файл доступен", "CRITICAL"),
            ("wp-config.php", "wp-config.php доступен", "CRITICAL"),
            ("adminer.php", "Adminer найден", "CRITICAL"),
        ]
        for pat, desc, sev in checks:
            if pat in html_l:
                findings.append({"severity": sev, "type": desc, "url": url})

        missing = {
            "content-security-policy": "Отсутствует CSP",
            "x-frame-options": "Отсутствует X-Frame-Options",
            "strict-transport-security": "Отсутствует HSTS",
        }
        for hdr, msg in missing.items():
            if hdr not in h:
                findings.append({"severity": "HIGH", "type": msg, "url": url})

        return findings


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Opsz v3.3")
        self.resize(1050, 680)
        self.setStyleSheet("""
            QMainWindow { background: #0d1117; color: #c9d1d9; }
            QLineEdit { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 8px; }
            QPushButton { background: #238636; color: white; border: none; padding: 10px 20px; border-radius: 6px; font-weight: bold; margin: 2px; }
            QPushButton:disabled { background: #3a4a3f; }
            QPushButton#pause { background: #daaa00; }
            QPushButton#stop { background: #da3633; }
            QPushButton#contact { background: #30363d; }
            QPushButton#export { background: #1f6feb; }
        """)

        self.current_findings = []
        self.history_file = Path("scan_history.json")
        self.history = self.load_history()

        central = QWidget()
        layout = QVBoxLayout(central)

        top = QHBoxLayout()
        top.addWidget(QLabel("Цель:"))
        self.url_input = QLineEdit("https://testphp.vulnweb.com")
        top.addWidget(self.url_input, 1)

        self.scan_btn = QPushButton("Запустить")
        self.scan_btn.clicked.connect(self.start_scan)
        top.addWidget(self.scan_btn)

        self.pause_btn = QPushButton("Пауза")
        self.pause_btn.setObjectName("pause")
        self.pause_btn.setEnabled(False)
        self.pause_btn.clicked.connect(self.toggle_pause)
        top.addWidget(self.pause_btn)

        self.stop_btn = QPushButton("Остановить")
        self.stop_btn.setObjectName("stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_scan)
        top.addWidget(self.stop_btn)

        layout.addLayout(top)

        self.status = QLabel("Готов")
        layout.addWidget(self.status)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Серьёзность", "Проблема", "URL"])
        self.tree.setColumnWidth(0, 110)
        layout.addWidget(self.tree, 1)

        bottom = QHBoxLayout()

        export_menu = QMenu()
        export_menu.addAction("JSON", lambda: self.export_results("json"))
        export_menu.addAction("HTML", lambda: self.export_results("html"))
        export_btn = QPushButton("Экспорт ▼")
        export_btn.setObjectName("export")
        export_btn.setMenu(export_menu)
        bottom.addWidget(export_btn)

        self.history_btn = QPushButton("История")
        self.history_btn.clicked.connect(self.show_history)
        bottom.addWidget(self.history_btn)

        contact = QPushButton("Связь с автором")
        contact.setObjectName("contact")
        contact.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("mailto:hixrussia@protonmail.com")))
        bottom.addWidget(contact)

        clear = QPushButton("Очистить")
        clear.clicked.connect(self.tree.clear)
        bottom.addWidget(clear)
        bottom.addStretch()
        layout.addLayout(bottom)

        self.setCentralWidget(central)
        self.worker = None

    def load_history(self):
        if self.history_file.exists():
            try:
                return json.loads(self.history_file.read_text(encoding="utf-8"))
            except:
                return []
        return []

    def save_history(self, target, count):
        entry = {"date": datetime.now().strftime("%Y-%m-%d %H:%M"), "target": target, "findings": count}
        self.history.insert(0, entry)
        self.history = self.history[:50]
        self.history_file.write_text(json.dumps(self.history, ensure_ascii=False, indent=2), encoding="utf-8")

    def start_scan(self):
        url = self.url_input.text().strip()
        if not url.startswith(("http://", "https://")):
            QMessageBox.critical(self, "Ошибка", "URL должен быть http/https")
            return

        self.tree.clear()
        self.current_findings = []
        self.status.setText("Запуск...")
        self.scan_btn.setEnabled(False)
        self.pause_btn.setEnabled(True)
        self.stop_btn.setEnabled(True)
        self.pause_btn.setText("Пауза")

        self.worker = ScanWorker(url)
        self.worker.progress.connect(self.status.setText)
        self.worker.finished.connect(self.scan_finished)
        self.worker.error.connect(lambda e: self.status.setText(f"Ошибка: {e}"))
        self.worker.start()

    def toggle_pause(self):
        if not self.worker: return
        if self.worker._pause:
            self.worker.resume()
            self.pause_btn.setText("Пауза")
            self.status.setText("Возобновлено")
        else:
            self.worker.pause()
            self.pause_btn.setText("Возобновить")
            self.status.setText("Пауза...")

    def stop_scan(self):
        if self.worker:
            self.worker.stop()
            self.worker.wait(5000)
            self.cleanup_after_stop()
            self.status.setText("Остановлено пользователем")

    def scan_finished(self, findings):
        self.current_findings = findings
        self.cleanup_after_stop()
        self.status.setText(f"Готово. Найдено: {len(findings)}")
        self.display_findings(findings)
        self.save_history(self.url_input.text().strip(), len(findings))
        
        if findings:
        	self.status.setText("ИИ анализ результатов...")
        	self.ai = DeepSeekWorker(findings)
        	self.ai.finished.connect(self.show_ai_result)
        	self.ai.error.connect(lambda e: QMessageBox.critical(self, "DeepSeek error", e))
        	self.ai.start()

    def display_findings(self, findings):
        colors = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffbb33", "INFO": "#58a6ff"}
        for f in findings:
            item = QTreeWidgetItem([f["severity"], f["type"], f["url"]])
            item.setForeground(0, QBrush(QColor(colors.get(f["severity"], "#ffffff"))))
            self.tree.addTopLevelItem(item)

        if not findings:
            item = QTreeWidgetItem(["INFO", "Уязвимостей не найдено", ""])
            item.setForeground(0, QBrush(QColor("#58a6ff")))
            self.tree.addTopLevelItem(item)

    def cleanup_after_stop(self):
        self.scan_btn.setEnabled(True)
        self.pause_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)
        self.pause_btn.setText("Пауза")

    def export_results(self, format_type):
        if not self.current_findings:
            QMessageBox.warning(self, "Экспорт", "Нет результатов для экспорта")
            return

        file_name = f"opsz_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        filters = "JSON files (*.json)" if format_type == "json" else "HTML files (*.html)"
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить отчёт", file_name, filters)
        if not path:
            return

        if format_type == "json":
            data = {
                "target": self.url_input.text().strip(),
                "date": datetime.now().isoformat(),
                "total_findings": len(self.current_findings),
                "findings": self.current_findings
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        else:
            self.export_html(path)

        QMessageBox.information(self, "Успех", f"Отчёт сохранён:\n{path}")

    def export_html(self, path):
        critical = sum(1 for f in self.current_findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.current_findings if f["severity"] == "HIGH")

        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Opsz Report — {self.url_input.text()}</title>
<style>
    body {{ font-family: Segoe UI, sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }}
    .header {{ background: #1f6feb; padding: 20px; border-radius: 10px; text-align: center; color: white; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
    th, td {{ padding: 12px; border-bottom: 1px solid #30363d; text-align: left; }}
    th {{ background: #161b22; }}
    .CRITICAL {{ color: #ff4444; font-weight: bold; }}
    .HIGH {{ color: #ff8800; }}
</style></head><body>
<div class="header"><h1>Opsz Scan Report</h1><p>{self.url_input.text()}</p><p>{datetime.now().strftime('%d.%m.%Y %H:%M')}</p></div>
<h2>Найдено уязвимостей: {len(self.current_findings)} (Critical: {critical} | High: {high})</h2>
<table><tr><th>Серьёзность</th><th>Проблема</th><th>URL</th></tr>"""
        for f in self.current_findings:
            html += f"<tr><td class='{f['severity']}'>{f['severity']}</td><td>{f['type']}</td><td>{f['url']}</td></tr>"
        html += "</table></body></html>"

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def show_history(self):
        if not self.history:
            QMessageBox.information(self, "История", "Пока пусто")
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("История сканирований")
        dialog.resize(700, 500)
        layout = QVBoxLayout(dialog)
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["Дата", "Цель", "Найдено"])
        table.setRowCount(len(self.history))
        for i, h in enumerate(self.history):
            table.setItem(i, 0, QTableWidgetItem(h["date"]))
            table.setItem(i, 1, QTableWidgetItem(h["target"]))
            table.setItem(i, 2, QTableWidgetItem(str(h["findings"])))
        layout.addWidget(table)
        close = QPushButton("Закрыть")
        close.clicked.connect(dialog.accept)
        layout.addWidget(close)
        dialog.exec()
        
    def show_ai_result(self, text):
    	dlg = QDialog(self)
    	dlg.setWindowTitle("ИИ-анализ результатов")
    	dlg.resize(900, 600)

    	layout = QVBoxLayout(dlg)
    	box = QTextEdit()
    	box.setReadOnly(True)
    	box.setText(text)

    	layout.addWidget(box)
    	dlg.exec()



if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = MainWindow()
    win.show()
    sys.exit(app.exec())