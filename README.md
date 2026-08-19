# 🕷️ J.A.R.V.I.S.

**Joint Automated Reconnaissance & Vulnerability Inspection System**

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://github.com/msdrakula/J.A.R.V.I.S/actions/workflows/test.yml/badge.svg)](https://github.com/msdrakula/J.A.R.V.I.S/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/msdrakula/J.A.R.V.I.S)](https://github.com/msdrakula/J.A.R.V.I.S/releases)

Модульный CLI-инструмент на Go для автоматизированного аудита конфигурации, доступности и устойчивости веб-приложений в закрытом контуре.

## 🌟 Возможности

- **Модульная архитектура** — запускай всё или только нужные модули
- **5 уровней детальности** — от stealth до thorough
- **YAML-шаблоны** — пиши проверки конфигурации без перекомпиляции
- **Пассивное обнаружение WAF/CDN** — Cloudflare, AWS WAF, Imperva, Akamai и др.
- **HTML-дашборды** — красивые отчёты с группировкой по severity
- **Сравнение сканов** — команда `diff` для отслеживания изменений
- **Graceful shutdown** — прерывание и возобновление сканов
- **Экспорт в Nmap XML** — интеграция с Metasploit и DefectDojo
- **SQLite-хранилище** — все результаты структурированы в БД
- **Визуализация** — дерево путей в терминале с цветовой кодировкой

## 📦 Установка

Нужен **Go 1.22+** (`go version`). На Kali rolling обычно уже стоит.

### Kali / Linux (клонирование репозитория)

```bash
git clone https://github.com/msdrakula/J.A.R.V.I.S.git
cd J.A.R.V.I.S
go build -o jarvis ./cmd/jarvis
./jarvis --help
```

Если репозиторий уже склонирован, обновите его и пересоберите:

```bash
cd ~/J.A.R.V.I.S
git pull
go build -o jarvis ./cmd/jarvis
./jarvis --help
```

### Из исходников (модуль)

```bash
go install github.com/msdrakula/J.A.R.V.I.S/cmd/jarvis@latest
```

### Бинарники

Скачай готовый бинарник для твоей ОС со страницы [Releases](https://github.com/msdrakula/J.A.R.V.I.S/releases).

### Debian/Kali Linux (deb-пакет)

```bash
wget https://github.com/msdrakula/J.A.R.V.I.S/releases/latest/download/jarvis_amd64.deb
sudo dpkg -i jarvis_amd64.deb
```

## 🚀 Быстрый старт

Как Nuclei/httpx: цель передаётся флагом `-u`. **config.yaml не нужен.**

```bash
# Домен или URL
./jarvis scan -u https://example.com -o ./results

# Короткий домен (будет https://)
./jarvis scan -u example.com -o ./results

# IP — проверка портов 22, 80, 443
./jarvis scan -u 192.168.1.10 -o ./results

# Результаты
./jarvis history -o ./results
./jarvis show <scan_id> -o ./results
./jarvis report <scan_id> --format html --output dashboard.html -o ./results
```

`-u` и `--target` — одно и то же. `--level` по умолчанию 3. `-c config.yaml` опционален.

Сканируйте только системы, на которые у вас есть разрешение.

## 📖 Документация

### Основные команды

```bash
# Сканирование (цель обязательна, YAML нет)
jarvis scan -u https://example.com -o ./results
jarvis scan -u 192.168.1.10 -p 22,80,443,8080 -o ./results
jarvis scan --target example.com --level 2 -o ./results

# Отдельные модули
jarvis recon -u example.com -o ./results
jarvis portscan -t 192.168.1.10 -p 22,80,443 -o ./results
jarvis dirbust -u https://example.com -w wordlists/common_paths.txt -o ./results

# Работа с результатами
jarvis history --limit 10 --status completed -o ./results
jarvis show <scan_id> -o ./results
jarvis diff <scan_id_1> <scan_id_2> -o ./results
jarvis resume <scan_id> -o ./results

# Генерация отчётов
jarvis report <scan_id> --format html --output report.html -o ./results
jarvis report <scan_id> --format csv --output report.csv -o ./results
jarvis report <scan_id> --format nmap --output nmap.xml -o ./results
```

### Уровни детальности

| Уровень | Название | Workers | Rate Limit | Timeout | Recursion |
|---------|----------|---------|------------|---------|-----------|
| 1 | stealth | 2 | 1 req/s | 30s | 1 |
| 2 | polite | 5 | 5 req/s | 20s | 2 |
| 3 | normal | 10 | 10 req/s | 15s | 3 |
| 4 | aggressive | 25 | 50 req/s | 10s | 4 |
| 5 | thorough | 50 | 100 req/s | 5s | 5 |

### Advanced Configuration

`config.yaml` не обязателен. Он нужен, чтобы переопределить таймауты, прокси, пути к `rules.yaml` и `waf_signatures.yaml`:

```bash
./jarvis scan -u https://example.com -c config.example.yaml --level 3 -o ./results
```

Пример `config.example.yaml`:

```yaml
output_dir: ./results
report_dir: ./reports
rules_path: ./rules.yaml
waf_signatures_path: ./waf_signatures.yaml

http:
  timeout_seconds: 15
  rate_limit_per_sec: 5
  proxy: ""
```

Секция `inventory` в YAML больше не нужна для обычного запуска: цель задаётся через `-u`.

### YAML-шаблоны (rules.yaml)

```yaml
- id: env-exposure-check
  description: "Проверка недоступности файла .env"
  path: "/.env"
  expected_status: 403
  severity: "high"

- id: sensitive-data-exposure
  description: "Проверка на раскрытие чувствительных данных"
  path: "/"
  matchers:
    - type: word
      part: body
      words: ["Index of /", "directory listing"]
      condition: or
    - type: regex
      part: body
      regex: ["(?i)aws_access_key_id\\s*[:=]\\s*[A-Za-z0-9]{20}"]
  severity: "high"
```

## 🏗️ Архитектура

```
jarvis/
├── cmd/jarvis/              # Точка входа CLI
├── internal/
│   ├── cli/                 # Команды Cobra
│   ├── config/              # Конфигурация и профили
│   ├── httpclient/          # HTTP-клиент с retry, rate-limit
│   ├── storage/             # SQLite-хранилище
│   ├── modules/
│   │   ├── recon/           # Сбор информации (DNS, TLS, robots.txt)
│   │   ├── availability/    # Проверка доступности портов
│   │   ├── urlaudit/        # Аудит путей и security headers
│   │   ├── compliance/      # Проверка по YAML-шаблонам
│   │   ├── waflib/          # Обнаружение WAF/CDN
│   │   └── resilience/      # Проверка устойчивости ввода
│   └── report/              # Генерация отчётов (HTML, CSV, Nmap XML)
├── wordlists/               # Словари для аудита
├── rules.yaml               # Шаблоны проверок
└── waf_signatures.yaml      # Сигнатуры WAF
```

## ⚠️ Отказ от ответственности

J.A.R.V.I.S. предназначен **только** для легального аудита: собственных систем, систем с явным разрешением владельца, авторизованных bug bounty-программ, исследований и обучения.

Использование инструмента против систем **без предварительного согласия** владельца **незаконно**. Авторы и контрибьюторы **не несут ответственности** за противоправное использование, включая действия хакеров и любой причинённый ущерб. Вся ответственность лежит на конечном пользователе.

Полный текст: [DISCLAIMER.md](DISCLAIMER.md).

## 📜 Лицензия

J.A.R.V.I.S. распространяется под лицензией **MIT**. См. [LICENSE](LICENSE).

## 🤝 Участие в разработке

Мы приветствуем вклад в проект! Пожалуйста, прочитай [CONTRIBUTING.md](CONTRIBUTING.md) перед созданием pull request.

## 🔒 Безопасность

Если вы обнаружили уязвимость в самом инструменте JARVIS, пожалуйста, ознакомьтесь с [SECURITY.md](SECURITY.md).

## 📝 Changelog

Смотри [CHANGELOG.md](CHANGELOG.md) для списка изменений по версиям.

## ⭐ Поддержка проекта

Если JARVIS оказался полезен, поставь звёздочку на GitHub! Это мотивирует развивать проект дальше.
