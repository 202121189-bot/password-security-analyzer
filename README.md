# 🛡️ Password Security Analyzer

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Domain](https://img.shields.io/badge/Domain-Cybersecurity-red.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

A tool that analyzes password strength and generates detailed security reports. Built for **Cybersecurity** fundamentals, password policy auditing, and awareness.

## ✨ Features

- 📏 **Length & Character Analysis** — detects lowercase, uppercase, digits, symbols
- 🔀 **Pattern Detection** — repetition (aaa, 111), sequences (abc, 123, qwerty)
- 📚 **Common Password Check** — compares against 350+ known weak passwords
- 🎲 **Entropy Calculation** — Shannon-style entropy in bits
- ⏱️ **Crack Time Estimation** — estimated time to brute-force (10B guesses/sec)
- 🎯 **Score (0-100)** — overall strength rating
- 💡 **Suggestions** — actionable tips to improve the password
- 📊 **HTML/JSON/CSV Reports** — clean reports for single or bulk analysis
- 📁 **Bulk Mode** — analyze entire files of passwords

## 🛠️ Requirements

- Python 3.8+
- `jinja2`

Install:

```bash
pip install -r requirements.txt