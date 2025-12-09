Opsz v3.3 — Web Security Scanner
📌 Description

Opsz is a web security scanner with a graphical interface (PyQt6) that allows you to scan websites for common vulnerabilities such as:

    PHPInfo exposure

    Directory listing

    Accessible .env files

    Exposed wp-config.php

    Adminer presence

    Missing security headers (CSP, HSTS, X-Frame-Options)

The tool also includes:

    Pause/Stop functionality during scanning

    History of past scans

    Export of results in JSON and HTML formats

    AI-powered analysis via DeepSeek API

🚀 Features

    Async scanning (up to 20 concurrent requests)

    Depth-limited crawling (up to 3 levels)

    Real-time progress display

    Interactive history panel

    AI-based vulnerability explanation

    Export in JSON/HTML

    Contact author via email

🛠 Installation
Prerequisites

    Python 3.8+

    Required libraries:

bash

pip install requests aiohttp beautifulsoup4 PyQt6 certifi lxml

Run
bash

python opsz.py

📖 Usage

    Enter the target URL (must start with http:// or https://)

    Click "Запустить" (Start)

    View results in the table

    Use Пауза (Pause) or Остановить (Stop) as needed

    Export results via Экспорт ▼

    View scan history via История

    Use Связь с автором to contact the developer

🔧 Configuration

Set your DeepSeek API key (optional) as an environment variable:
bash

export DEEPSEEK_API_KEY="your-api-key"

If not set, a default demo key is used.
📁 Project Structure
text

opsz.py               # Main application
scan_history.json     # Automatically saved scan history

📄 Export Formats

    JSON: Structured data with metadata

    HTML: Visual report with color-coded severity levels

📬 Contact

Author: hixrussia@protonmail.com
⚠️ Disclaimer

This tool is for educational and authorized testing purposes only.
Do not use it on websites without explicit permission.
