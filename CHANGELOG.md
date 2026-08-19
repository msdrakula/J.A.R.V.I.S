# Changelog

Все значимые изменения в проекте будут документироваться в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
и этот проект придерживается [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Лицензия изменена с GNU AGPL v3 на MIT
- `jarvis scan -u` / `--target`: запуск без обязательного config.yaml (URL/домен → recon+urlaudit+compliance, IP → portscan)
- Добавлен [DISCLAIMER.md](DISCLAIMER.md): отказ от ответственности за незаконное использование
- В репозиторий включены исходники `cmd/jarvis` (раньше игнорировались `.gitignore`)
- `go.mod` дополнен indirect-зависимостями — `go build` работает без `go mod tidy`
- Минимальная версия Go: 1.22

## [1.0.0] - 2026-08-19

### Added
- Модульная архитектура с разделением на cli, config, httpclient, storage, modules, report
- CLI на Cobra с командами: scan, recon, portscan, dirbust, history, show, report, query, diff, resume
- Конфигурация через Viper (YAML-файлы + флаги CLI)
- Логирование через Zap с уровнями debug, info, warn, error
- SQLite-хранилище через modernc.org/sqlite (чистый Go, без CGO)
- HTTP-клиент с retry, rate-limit, прокси, gzip, ротацией User-Agent
- Модуль `recon`: DNS-резолвинг, TLS-сертификаты, robots.txt, sitemap.xml, извлечение параметров из HTML
- Модуль `availability`: проверка доступности TCP-портов, определение сервисов по баннерам
- Модуль `urlaudit`: проверка путей по словарю, фильтрация soft 404, анализ security headers
- Модуль `compliance`: YAML-шаблоны с матчерами (status, header, word, regex)
- Модуль `waflib`: пассивное обнаружение WAF/CDN по сигнатурам (Cloudflare, AWS WAF, Imperva, Akamai)
- Модуль `resilience`: проверка устойчивости ввода с безопасными маркерными строками
- 5 уровней детальности (stealth, polite, normal, aggressive, thorough)
- Graceful shutdown с сохранением прогресса (статус `paused`)
- HTML-дашборд с группировкой по severity и цветовой кодировкой
- Экспорт в форматы: JSON, Markdown, HTML, CSV, Nmap XML
- Команда `diff` для сравнения двух сканов (терминал и HTML)
- Визуализация дерева путей в терминале с ANSI-цветами
- Команда `resume` для возобновления прерванных сканов
- Юнит-тесты для ключевых функций
- GitHub Actions для автоматической сборки и тестирования
- Deb-пакет для Debian/Kali Linux
