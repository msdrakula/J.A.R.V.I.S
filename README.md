# J.A.R.V.I.S.

Инструмент для **легального** аудита своих систем. Цель задаётся флагом `-u`. Файл `config.yaml` **не нужен**.

Сканируйте только то, на что есть разрешение. [DISCLAIMER.md](DISCLAIMER.md)

---

## Как запустить на Kali

Не клонируй репозиторий заново, если папка `J.A.R.V.I.S` уже есть. Не пиши `./jarvis` из домашней директории (`~`) — там этого файла нет.

Скопируй команды **по порядку**, каждую целиком:

```bash
cd ~/J.A.R.V.I.S
git fetch origin
git reset --hard origin/main
go build -o jarvis ./cmd/jarvis
sudo install -m 755 jarvis /usr/local/bin/jarvis
```

Проверка (уже из любой папки, в том числе из `~`):

```bash
cd ~
which jarvis
jarvis --help
jarvis scan -u http://172.23.94.168 -o ~/Documents/jarvis-results
```

После `sudo install` команда называется **`jarvis`**, не `./jarvis`.

Если папки `~/J.A.R.V.I.S` ещё нет:

```bash
cd ~
git clone https://github.com/msdrakula/J.A.R.V.I.S.git
cd J.A.R.V.I.S
go build -o jarvis ./cmd/jarvis
sudo install -m 755 jarvis /usr/local/bin/jarvis
```

---

## Что запускать дальше

Без конфига, как Nuclei:

```bash
jarvis scan -u http://172.23.94.168 -o ~/Documents/jarvis-results
jarvis scan -u https://example.com -o ~/Documents/jarvis-results --level 2
```

- URL или домен → recon + urlaudit
- Голый IP (`192.168.1.10`) → проверка портов 22, 80, 443
- `http://172.23.94.168` → как сайт

Отдельные модули:

```bash
jarvis recon -u example.com -o ~/Documents/jarvis-results
jarvis portscan -t 192.168.1.10 -p 22,80,443 -o ~/Documents/jarvis-results
```

Результаты (тот же `-o`, что у скана):

```bash
jarvis history -o ~/Documents/jarvis-results
jarvis show <scan_id> -o ~/Documents/jarvis-results
jarvis report <scan_id> --format html --output report.html -o ~/Documents/jarvis-results
```

`.jarvis.db` — это база SQLite, не текстовый отчёт. Не делай `cat` по этому файлу.

---

## Если нужен config.yaml (не обязательно)

```bash
jarvis scan -u https://example.com -c config.yaml -o ~/Documents/jarvis-results
```

Минимальный файл:

```yaml
output_dir: ./results
http:
  timeout_seconds: 15
  rate_limit_per_sec: 5
  proxy: ""
```

---

## Если что-то сломалось

| Что видишь | Почему | Что делать |
|---|---|---|
| `zsh: no such file or directory: ./jarvis` | Ты в `~`, а файл `jarvis` лежит в `~/J.A.R.V.I.S` или ещё не собран | Команды из блока «Как запустить», потом `jarvis` без точки и слэша |
| `destination path already exists` | Репозиторий уже скачан | `cd ~/J.A.R.V.I.S` и дальше по инструкции. `git clone` не повторять |
| `module ... v1.0.0, but does not contain package .../cmd/jarvis` | `go install ...@latest` берёт старый тег `v1.0.0`, там не было `cmd/jarvis` | Не используй этот способ. Собери из папки, как выше |
| `jarvis: command not found` | Бинарник не скопирован в `/usr/local/bin` | `cd ~/J.A.R.V.I.S && sudo install -m 755 jarvis /usr/local/bin/jarvis` |
| `unknown shorthand flag: 'u'` | Стоит старый бинарник | Снова `git reset --hard origin/main`, `go build`, `sudo install` |
| `zsh: corrupt history file` | Сломан файл истории zsh, к JARVIS не относится | `mv ~/.zsh_history ~/.zsh_history.bak` и открой новый терминал |

Проверка, что стоит свежая версия:

```bash
jarvis scan --help
```

В списке флагов должно быть `-u, --url`.

---

Лицензия MIT. Подробности: [LICENSE](LICENSE), [CHANGELOG.md](CHANGELOG.md).
