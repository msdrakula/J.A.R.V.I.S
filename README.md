# 🕷️ J.A.R.V.I.S.

**Joint Automated Reconnaissance & Vulnerability Inspection System**

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://github.com/msdrakula/J.A.R.V.I.S/actions/workflows/test.yml/badge.svg)](https://github.com/msdrakula/J.A.R.V.I.S/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/msdrakula/J.A.R.V.I.S)](https://github.com/msdrakula/J.A.R.V.I.S/releases)

Модульный CLI на Go для **легального** аудита собственной инфраструктуры. Запуск как у Nuclei: цель через `-u`, файл `config.yaml` **не нужен**.

Сканируйте только системы, на которые у вас есть разрешение. Полный отказ от ответственности: [DISCLAIMER.md](DISCLAIMER.md).

---

## A. Установка (Installation)

Нужен **Go 1.22+** (`go version`). На Kali rolling он обычно уже установлен.

### Рекомендуемый способ: `go install` (глобальный запуск)

Так команда `jarvis` работает из любой директории, без `./jarvis`:

```bash
go install github.com/msdrakula/J.A.R.V.I.S/cmd/jarvis@latest
```

Бинарник попадает в `$(go env GOPATH)/bin` (на Kali часто `~/go/bin`). Добавьте этот каталог в `PATH`, если `jarvis` ещё не находится:

```bash
echo 'export PATH="$(go env GOPATH)/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Проверка:

```bash
which jarvis
jarvis --help
```

Из клона репозитория то же самое без sudo:

```bash
git clone https://github.com/msdrakula/J.A.R.V.I.S.git
cd J.A.R.V.I.S
make go-install
```

### Вручную: скачать бинарник и положить в `/usr/local/bin`

1. Скачайте архив для Linux со страницы [Releases](https://github.com/msdrakula/J.A.R.V.I.S/releases).
2. Сделайте файл исполняемым и переместите его в каталог из `PATH`:

```bash
chmod +x jarvis
sudo mv jarvis /usr/local/bin/jarvis
jarvis --help
```

Либо соберите сами и установите через Makefile (копирует бинарник в `/usr/local/bin` и словари в `/usr/local/share/jarvis`):

```bash
git clone https://github.com/msdrakula/J.A.R.V.I.S.git
cd J.A.R.V.I.S
sudo make install
```

Обновление: `git fetch origin && git reset --hard origin/main`, затем снова `go install ...@latest` или `sudo make install`.

---

## B. Быстрый старт (Quick Start) — стиль Nuclei

`config.yaml` не обязателен. Достаточно цели и каталога результатов.

Тип цели определяется автоматически:

| `-u` | Что запускается |
|---|---|
| URL или домен (`http://host`, `https://site`, `example.com`) | `recon` и `urlaudit` (плюс compliance / WAF / resilience) |
| Голый IP (`192.168.1.10`) | `portscan` (порты 22, 80, 443) |
| `http://172.23.94.168` | как сайт (веб-модули) |

### Скан без конфига

```bash
jarvis scan -u http://172.23.94.168 -o ./results
jarvis scan -u https://example.com -o ./results --level 2
```

`--level` по умолчанию **3**. `-u` и `--target` — одно и то же.

### Отдельные модули

```bash
jarvis recon -u example.com -o ./results
jarvis portscan -t 192.168.1.10 -p 22,80,443 -o ./results
```

Дополнительно: `jarvis dirbust -u https://example.com -w wordlists/common_paths.txt -o ./results`

После скана в терминале печатаются пути, дерево и findings. Файл `.jarvis.db` в каталоге `-o` — это SQLite, не текстовый отчёт. Не делайте `cat .jarvis.db`.

---

## C. Работа с результатами

Один и тот же `-o` указывайте для `scan`, `history`, `show` и `report` — иначе инструмент не найдёт базу.

```bash
# История сканов
jarvis history -o ./results

# Детали, таблица путей и дерево
jarvis show <scan_id> -o ./results

# HTML-отчёт
jarvis report <scan_id> --format html --output report.html -o ./results
```

Другие форматы: `--format csv`, `--format nmap`. Сравнение двух сканов: `jarvis diff <id1> <id2> -o ./results`. Прерванный скан: `jarvis resume <scan_id> -o ./results`.

---

## D. Продвинутая настройка (Optional)

Для обычного запуска YAML не нужен. Файл `-c config.yaml` нужен только если вы хотите задать прокси, таймауты, свои пути к правилам или сигнатурам WAF.

```bash
jarvis scan -u https://example.com -c config.yaml --level 3 -o ./results
```

Минимальный пример `config.yaml`:

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

Готовый шаблон лежит в репозитории: [config.example.yaml](config.example.yaml). Секция `inventory` для запуска через `-u` не нужна.

Уровни `--level`: 1 stealth, 2 polite, 3 normal, 4 aggressive, 5 thorough.

---

## E. Устранение неполадок (Troubleshooting)

**`jarvis: command not found`**

1. Проверьте, есть ли бинарник в `PATH`:

```bash
which jarvis
echo "$PATH"
go env GOPATH
```

2. Переустановите рекомендованным способом и добавьте `GOPATH/bin` в `PATH`:

```bash
go install github.com/msdrakula/J.A.R.V.I.S/cmd/jarvis@latest
export PATH="$(go env GOPATH)/bin:$PATH"
```

3. Либо положите бинарник в `/usr/local/bin`:

```bash
sudo mv jarvis /usr/local/bin/jarvis
```

На zsh (Kali по умолчанию) сохраните PATH в `~/.zshrc`, на bash — в `~/.bashrc`, затем `source` этого файла.

**`unknown shorthand flag: 'u'`**

Собран старый бинарник. Обновите код и переустановите:

```bash
cd ~/J.A.R.V.I.S
git fetch origin && git reset --hard origin/main
go install github.com/msdrakula/J.A.R.V.I.S/cmd/jarvis@latest
# или: sudo make install
jarvis scan --help
```

В help должна быть строка `-u, --url`.

**Нет `config.yaml` — программа падает**

Так быть не должно. Запускайте только с `-u`. Если указали `-c` на несуществующий файл, JARVIS всё равно берёт безопасные дефолты (level 3, стандартные wordlists).

**`cat .jarvis.db` выдаёт кракозябры**

Это база SQLite. Смотрите результаты через `jarvis show` / `jarvis report`.

---

## Возможности

- Модули: recon, availability (portscan), urlaudit, compliance, WAF fingerprint, resilience
- 5 уровней детальности, YAML-правила, HTML/CSV/Nmap XML
- Сравнение сканов (`diff`), пауза по Ctrl+C и `resume`
- Один бинарник, встроенная SQLite, без CGO

Это **не** эксплойт-сканер. Модули только наблюдают: DNS/TLS, TCP connect, GET, разбор заголовков и HTML.

## Лицензия и участие

MIT — [LICENSE](LICENSE). Вклад: [CONTRIBUTING.md](CONTRIBUTING.md). Уязвимости в самом инструменте: [SECURITY.md](SECURITY.md). История версий: [CHANGELOG.md](CHANGELOG.md).
